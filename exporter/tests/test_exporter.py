from __future__ import annotations

import time

import pytest

from voltage_exporter import config, metrics
from voltage_exporter.client import VoltageClient, _first_string_list, host_port
from voltage_exporter.policy import parse_policy
from voltage_exporter.probes import _same_shape, run_target

from .conftest import target_for

# --------------------------------------------------------------------- policy parser
SAMPLE_POLICY = """<?xml version="1.0"?>
<clientPolicy version="7.0.2" district="prod" policyId="p1">
  <KeyServers><KeyServer url="https://ks.example.com/vibekeys/"/></KeyServers>
  <AuthMethods><AuthMethod name="SharedSecret"/><AuthMethod>LDAP</AuthMethod></AuthMethods>
  <FormatMappings><Format name="CC" type="FPE"/><Format name="SSN" type="FPE"/></FormatMappings>
  <TokenizationFormats><Format name="CC-ST-64O"/></TokenizationFormats>
</clientPolicy>"""


def test_parse_policy_extracts_everything():
    p = parse_policy(SAMPLE_POLICY)
    assert p.version == "7.0.2" and p.district == "prod" and p.policy_id == "p1"
    assert p.format_names == ["CC", "SSN", "CC-ST-64O"]
    assert {f["name"]: f["kind"] for f in p.formats}["CC-ST-64O"] == "tokenization"
    assert p.auth_methods == ["SharedSecret", "LDAP"]
    assert p.key_servers == ["https://ks.example.com/vibekeys/"]
    assert len(p.sha256) == 64


def test_parse_policy_tolerates_namespaces_and_unknown_shape():
    xml = (
        '<ns:policy xmlns:ns="urn:x" version="1"><ns:fpeFormats><ns:f name="A"/></ns:fpeFormats>'
        "<ns:district>dr</ns:district></ns:policy>"
    )
    p = parse_policy(xml)
    assert p.format_names == ["A"] and p.district == "dr" and p.version == "1"


# --------------------------------------------------------------------- helpers
def test_same_shape():
    assert _same_shape("4111-1111", "4923-7710")
    assert not _same_shape("4111", "49a3")
    assert not _same_shape("4111", "491")


def test_first_string_list():
    assert _first_string_list({"data": ["x"]}) == ["x"]
    assert _first_string_list({"result": {"protectedData": ["y", "z"]}}) == ["y", "z"]
    assert _first_string_list(["a"]) == ["a"]
    assert _first_string_list({"data": []}) == []


def test_host_port():
    assert host_port("https://h.example.com/policy/x") == ("h.example.com", 443)
    assert host_port("https://h:8443/x") == ("h", 8443)
    assert host_port("h:9443") == ("h", 9443)
    assert host_port("h") == ("h", 443)


# --------------------------------------------------------------------- config
def test_config_load(tmp_path, monkeypatch):
    monkeypatch.setenv("SEC", "s3")
    (tmp_path / "c.yml").write_text(
        "exporter: {port: 1234, interval_seconds: 7}\n"
        "targets:\n  - name: a\n    policy_url: https://pp.example.com/policy/clientPolicy.xml\n"
        "    identity: i@x\n    auth: {method: shared_secret, secret_env: SEC}\n    ca_cert: /ca.pem\n"
        "    probes: [{format: CC, sample: '4111'}]\n    extra_tls_hosts: ['ks:443']\n"
    )
    c = config.load(tmp_path / "c.yml")
    assert c.port == 1234 and c.interval == 7
    t = c.targets[0]
    assert t.ws_url == "https://pp.example.com" and t.secret == "s3" and t.verify_tls == "/ca.pem"
    assert t.probes[0].format == "CC" and t.extra_tls_hosts == ["ks:443"]


def test_config_missing_secret(tmp_path, monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    (tmp_path / "c.yml").write_text(
        "targets:\n  - {name: a, policy_url: https://x/policy/clientPolicy.xml, identity: i,"
        " auth: {secret_env: NOPE}}\n"
    )
    with pytest.raises(config.ConfigError, match="NOPE"):
        config.load(tmp_path / "c.yml")


# --------------------------------------------------------------------- live against the mock
def test_rest_roundtrip(mock_server, healthy):
    r = run_target(target_for(mock_server))
    assert r.policy_ok and r.policy.district == "prod" and len(r.policy.formats) == 8
    assert all(t.ok for t in r.tokenize), [t.error for t in r.tokenize]
    cc = r.tokenize[0]
    assert cc.roundtrip_ok and cc.format_preserved and cc.protect_seconds < 2
    assert r.tls and all(c.ok for c in r.tls)
    assert 19 * 86400 < r.tls[0].not_after - time.time() < 21 * 86400
    assert r.keyservers and all(r.keyservers.values())


def test_soap_roundtrip(mock_server, healthy):
    t = target_for(mock_server, api="soap", identity="monitor", auth_method="password", username="monitor",
                   secret="changeme")  # fmt: skip
    r = run_target(t)
    assert r.tokenize[0].ok, r.tokenize[0].error


def test_auth_in_body(mock_server, healthy):
    r = run_target(target_for(mock_server, auth_in_body=True))
    assert r.tokenize[0].ok, r.tokenize[0].error


def test_bad_secret_is_auth_error(mock_server, healthy):
    r = run_target(target_for(mock_server, secret="wrong"))
    assert not r.tokenize[0].ok and r.tokenize[0].error_kind == "auth"


def test_scenarios(mock_server):
    _, _, mod = mock_server
    t = target_for(mock_server)
    mod._state["scenario"] = "policy-down"
    r = run_target(t)
    assert not r.policy_ok and "503" in r.policy_error
    mod._state["scenario"] = "auth-fail"
    r = run_target(t)
    assert all(x.error_kind == "auth" for x in r.tokenize)
    mod._state["scenario"] = "keyserver-down"
    r = run_target(t)
    assert r.keyservers and not any(r.keyservers.values())
    mod._state["scenario"] = "policy-changed"
    r = run_target(t)
    assert "PHONE" in r.policy.format_names
    mod._state["scenario"] = "healthy"


def test_unknown_format_reports_http_error(mock_server, healthy):
    from voltage_exporter.config import ProbeSpec

    r = run_target(target_for(mock_server, probes=[ProbeSpec("NOPE", "123")]))
    assert not r.tokenize[0].ok and r.tokenize[0].error_kind == "http"


def test_metrics_apply_and_policy_change_counter(mock_server):
    _, _, mod = mock_server
    t = target_for(mock_server, name="m")
    mod._state["scenario"] = "healthy"
    metrics.apply(run_target(t))
    mod._state["scenario"] = "policy-changed"
    metrics.apply(run_target(t))
    mod._state["scenario"] = "healthy"
    from prometheus_client import generate_latest

    text = generate_latest().decode()
    assert 'voltage_policy_changes_total{target="m"} 1.0' in text
    assert 'voltage_tokenize_success{format="CC",identity="probe@demo.bank",target="m"} 1.0' in text
    assert "voltage_protect_seconds_bucket" in text
    assert 'voltage_certificate_expiry_timestamp_seconds{host="127.0.0.1' in text


def test_client_certificate_helper(mock_server):
    _, https, _ = mock_server
    host, port = host_port(https)
    info = VoltageClient.certificate(host, port)
    assert "Mock Voltage" in info["subject"] and info["tls_version"].startswith("TLS")


# --------------------------------------------------------------------- policy: crypto facts (R1, R2, R5, R12)
RICH_POLICY = """<?xml version="1.0"?>
<clientPolicy version="7.0.3" district="prod" policyId="p1">
  <server name="SecureDataAppliance" version="7.0.3.100100"/>
  <keyNumberConfig>
    <keyNumberTable name="PCI" currentNumber="4">
      <keyNumber number="1" algorithm="FPE" keySize="128"/>
      <keyNumber number="4" algorithm="FPE" keySize="256"/>
    </keyNumberTable>
    <keyNumberTable name="NOCURRENT">
      <keyNumber number="7" algorithm="AES"/>
    </keyNumberTable>
  </keyNumberConfig>
  <FormatMappings>
    <Format name="CC" alphabet="digits" length="16" preserveLeading="6" preserveTrailing="4"/>
    <Format name="SSN" alphabet="0-9" length="9" preserveTrailing="4"/>
    <Format name="CVV" alphabet="0123456789" length="3"/>
    <Format name="STATE" alphabet="A-Z" length="2"/>
    <Format name="CC-EFPE" alphabet="digits" length="16" preserveLeading="6" preserveTrailing="4" encryption="eFPE"/>
    <Format name="ALNUM" alphabet="alphanumeric" minLength="6" maxLength="64"/>
    <Format name="NESTED"><alphabet>hex</alphabet><length>8</length></Format>
    <Format name="MYSTERY"/>
  </FormatMappings>
  <TokenizationFormats><Format name="CC-ST-64O" engine="SST" alphabet="digits" length="16"/></TokenizationFormats>
</clientPolicy>"""


def test_parse_key_tables_and_server_version():
    from voltage_exporter.policy import parse_policy

    p = parse_policy(RICH_POLICY)
    assert p.server_version == "7.0.3.100100"
    assert [t.name for t in p.key_tables] == ["PCI", "NOCURRENT"]
    pci = p.key_tables[0]
    assert pci.current_number == 4 and len(pci.keys) == 2
    assert pci.current == {"number": 4, "algorithm": "FPE", "key_size": 256}
    # no currentNumber attribute -> assume the highest listed key number
    assert p.key_tables[1].current_number == 7 and p.key_tables[1].current["key_size"] is None
    d = p.to_dict()
    assert d["server_version"] == "7.0.3.100100" and d["key_tables"][0]["current_number"] == 4
    assert d["efpe_formats"] == ["CC-EFPE"]
    assert d["format_domain_sizes"]["SSN"] == 100_000


@pytest.mark.parametrize(
    "name,expected",
    [
        ("CC", 10**6),  # 16 digits, 6 + 4 preserved -> exactly at the NIST floor
        ("SSN", 10**5),  # last-4 preserving SSN is *under* the floor -- true in real deployments too
        ("CVV", 10**3),
        ("STATE", 26**2),
        ("CC-EFPE", 10**6),
        ("ALNUM", 62**6),  # minimum length is the weakest case
        ("NESTED", 16**8),  # attributes given as child elements
        ("MYSTERY", None),  # policy says nothing -> no guess
        ("CC-ST-64O", None),  # tokenization is not a permutation on a domain
    ],
)
def test_format_domain_size(name, expected):
    from voltage_exporter.policy import format_domain_size, parse_policy

    fmt = {f["name"]: f for f in parse_policy(RICH_POLICY).formats}[name]
    assert format_domain_size(fmt) == expected


def test_is_efpe():
    from voltage_exporter.policy import is_efpe

    assert is_efpe({"name": "x", "encryption": "eFPE"})
    assert is_efpe({"name": "x", "type": "EmbeddedFPE"})
    assert is_efpe({"name": "x", "embeddedKey": "true"})
    assert not is_efpe({"name": "eFPE-looking-name", "type": "FPE"})  # the name alone proves nothing
    assert not is_efpe({"name": "x", "kind": "fpe"})


def test_support_end_lookup():
    import datetime as dt

    from voltage_exporter.lifecycle import split_version, support_end

    rel, ts = support_end("7.0.3.100100")
    assert rel == "DPP Foundation CE 24.4"
    assert dt.datetime.fromtimestamp(ts, dt.UTC).date() == dt.date(2027, 11, 30)
    assert support_end("7.1.1.100286") is None  # not public -> no guess
    assert support_end("") is None
    # operator overrides: plain date, or {release, end}; longest prefix wins
    ov = {"7.1": "2028-06-30", "7.1.1": {"release": "CE 25.2", "end": "2028-09-30"}}
    assert support_end("7.1.0.5", ov)[0] == "7.1"
    assert support_end("7.1.1.100286", ov)[0] == "CE 25.2"
    assert support_end("7.1.1.100286", {"7.1.1": "not-a-date"}) is None
    assert split_version("7.0.3.100100") == ("7", "7.0") and split_version("8") == ("8", "8")


def test_metrics_expose_crypto_policy_facts(mock_server, healthy):
    from prometheus_client import REGISTRY

    from voltage_exporter.config import Config

    _, _, mod = mock_server
    tgt = target_for(mock_server, name="crypto")
    metrics.configure(Config(targets=[tgt], support_end={"7.0.3": "2027-11-30"}))
    metrics.apply(run_target(tgt))

    def g(name, **labels):
        return REGISTRY.get_sample_value(name, {"target": "crypto", **labels})

    assert g("voltage_key_table_current_number", table="PCI") == 4.0
    assert g("voltage_key_table_versions", table="PCI") == 4.0
    assert g("voltage_key_current_size_bits", table="PCI") == 256.0
    assert g("voltage_key_info", table="PCI", number="1", algorithm="FPE", key_size="128") == 1.0
    assert g("voltage_key_rotations_total", table="PCI") == 0.0
    assert g("voltage_format_domain_size", format="CC") == 1e6
    assert g("voltage_format_below_minimum_domain", format="CC") == 0.0
    assert g("voltage_format_below_minimum_domain", format="SSN") == 1.0
    assert g("voltage_format_domain_size", format="ORA-DATE") is None  # unknown -> no series
    assert g("voltage_policy_format_efpe", format="CC-EFPE") == 1.0
    assert g("voltage_policy_format_efpe", format="CC") is None
    assert g("voltage_appliance_version_info", version="7.0.3.100100", major="7", minor="7.0") == 1.0
    assert g("voltage_support_end_timestamp_seconds", version="7.0.3.100100", release="DPP Foundation CE 24.4") > 0

    # a rotation is a currentNumber change between two cycles
    mod._state["scenario"] = "key-rotated"
    metrics.apply(run_target(tgt))
    assert g("voltage_key_table_current_number", table="PCI") == 5.0
    assert g("voltage_key_table_versions", table="PCI") == 5.0
    assert g("voltage_key_rotations_total", table="PCI") == 1.0
    mod._state["scenario"] = "weak-key"
    metrics.apply(run_target(tgt))
    assert g("voltage_key_current_size_bits", table="PII") == 128.0


def test_efpe_format_round_trips_like_fpe(mock_server, healthy):
    """eFPE is still reversible; only *determinism across epochs* differs (that is R3's job)."""
    from voltage_exporter.config import ProbeSpec

    tgt = target_for(mock_server, probes=[ProbeSpec("CC-EFPE", "4111111111111111")])
    r = run_target(tgt)
    assert r.tokenize[0].ok and r.tokenize[0].roundtrip_ok and r.tokenize[0].format_preserved


# --------------------------------------------------------------------- integrity probes (R3)
def _integrity(r, check, fmt=None):
    return [x for x in r.integrity if x.check == check and (fmt is None or x.format == fmt)]


def test_integrity_probes_pass_on_healthy_mock(mock_server, healthy):
    from voltage_exporter.config import ProbeSpec

    tgt = target_for(
        mock_server,
        probes=[
            ProbeSpec("CC", "4111111111111111"),
            ProbeSpec("SSN", "123456789"),
            ProbeSpec("CC-EFPE", "4111111111111111"),
            ProbeSpec("CC-ST-64O", "5500000000000004", tokenization=True),
        ],
    )
    r = run_target(tgt)
    det = _integrity(r, "determinism")
    assert {x.format for x in det} == {"CC", "SSN"}  # eFPE excluded, tokenization excluded
    assert all(x.ok for x in det)
    dbl = _integrity(r, "double_protect")
    assert {x.format for x in dbl} == {"CC", "SSN", "CC-EFPE"} and all(x.ok for x in dbl)
    iso = _integrity(r, "format_isolation")
    # default pairing: each FPE probe against the next one, round-robin
    assert [(x.format, x.against) for x in iso] == [("CC", "SSN"), ("SSN", "CC-EFPE"), ("CC-EFPE", "CC")]
    assert all(x.ok for x in iso)


def test_integrity_detects_format_leak(mock_server, healthy):
    from voltage_exporter.config import ProbeSpec

    _, _, mod = mock_server
    tgt = target_for(mock_server, probes=[ProbeSpec("CC", "4111111111111111"), ProbeSpec("SSN", "123456789")])
    mod._state["scenario"] = "format-leak"
    r = run_target(tgt)
    iso = _integrity(r, "format_isolation")
    assert iso and all(x.ok is False for x in iso)
    assert "returned the plaintext" in iso[0].detail
    # the ordinary round-trip probe is *green* in this scenario -- that's the whole point
    assert all(t.ok for t in r.tokenize)


def test_integrity_detects_nondeterminism(mock_server, healthy):
    from voltage_exporter.config import ProbeSpec

    _, _, mod = mock_server
    probes = [ProbeSpec("CC", "4111111111111111"), ProbeSpec("CC-EFPE", "4111111111111111")]
    tgt = target_for(mock_server, probes=probes)
    mod._state["scenario"] = "nondeterministic"
    r = run_target(tgt)
    det = _integrity(r, "determinism")
    assert [x.format for x in det] == ["CC"] and det[0].ok is False
    assert all(t.ok for t in r.tokenize)  # round-trip still passes: silent


def test_efpe_changes_ciphertext_on_rotation_but_is_excluded_from_determinism(mock_server, healthy):
    from voltage_exporter.client import VoltageClient
    from voltage_exporter.config import ProbeSpec

    _, _, mod = mock_server
    tgt = target_for(mock_server, probes=[ProbeSpec("CC-EFPE", "4111111111111111")])
    c = VoltageClient(tgt)
    before = str(c.protect("CC-EFPE", "4111111111111111").value)
    mod._state["scenario"] = "key-rotated"
    after = str(c.protect("CC-EFPE", "4111111111111111").value)
    assert before != after  # same plaintext, new key epoch -> different ciphertext
    assert str(c.access("CC-EFPE", before).value) == "4111111111111111"  # old ciphertext still decrypts
    r = run_target(tgt)
    assert _integrity(r, "determinism") == []  # excluded because the policy marks it eFPE
    assert _integrity(r, "double_protect", "CC-EFPE")[0].ok


def test_integrity_config_flags_and_pairs(mock_server, healthy, tmp_path):
    from voltage_exporter.config import ProbeSpec

    tgt = target_for(
        mock_server,
        probes=[ProbeSpec("CC", "4111111111111111"), ProbeSpec("SSN", "123456789")],
        integrity_determinism=False,
        integrity_double_protect=False,
        isolation_pairs=[("SSN", "CC"), ("CC", "NOPE")],
    )
    r = run_target(tgt)
    assert _integrity(r, "determinism") == [] and _integrity(r, "double_protect") == []
    iso = _integrity(r, "format_isolation")
    assert [(x.format, x.against, x.ok) for x in iso] == [("SSN", "CC", True), ("CC", "NOPE", True)]
    # config loader
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        "targets:\n  - name: t\n    policy_url: https://x/policy/clientPolicy.xml\n    identity: i\n"
        "    auth: {secret: s}\n    integrity: {determinism: false, isolation_pairs: [[CC, SSN]]}\n"
    )
    t = config.load(cfg).targets[0]
    assert t.integrity_determinism is False and t.integrity_double_protect is True
    assert t.isolation_pairs == [("CC", "SSN")]
    cfg.write_text(
        "targets:\n  - name: t\n    policy_url: https://x/policy/clientPolicy.xml\n    identity: i\n"
        "    auth: {secret: s}\n    integrity: {isolation_pairs: [CC]}\n"
    )
    with pytest.raises(config.ConfigError):
        config.load(cfg)


def test_integrity_metrics(mock_server, healthy):
    from prometheus_client import REGISTRY

    from voltage_exporter.config import ProbeSpec

    _, _, mod = mock_server
    probes = [ProbeSpec("CC", "4111111111111111"), ProbeSpec("SSN", "123456789")]
    tgt = target_for(mock_server, name="integ", probes=probes)
    metrics.apply(run_target(tgt))

    def g(**lb):
        return REGISTRY.get_sample_value("voltage_integrity_ok", {"target": "integ", **lb})

    assert g(check="determinism", format="CC", against="") == 1.0
    assert g(check="format_isolation", format="CC", against="SSN") == 1.0
    mod._state["scenario"] = "format-leak"
    metrics.apply(run_target(tgt))
    assert g(check="format_isolation", format="CC", against="SSN") == 0.0
    fails = {"target": "integ", "check": "format_isolation", "result": "fail"}
    assert REGISTRY.get_sample_value("voltage_integrity_checks_total", fails) >= 1


# --------------------------------------------------------------------- fleet agreement (R4, R15)
def _fleet_targets(mock_server, mock_dr):
    from voltage_exporter.config import ProbeSpec

    probes = [ProbeSpec("CC", "4111111111111111"), ProbeSpec("CC-ST-64O", "5500000000000004", tokenization=True)]
    prod = target_for(mock_server, name="prod", fleet="pci", probes=probes)
    dr_https, _ = mock_dr
    dr = target_for(
        mock_server, name="dr", fleet="pci", probes=probes,
        policy_url=f"{dr_https}/policy/clientPolicy.xml", ws_url=dr_https,
    )  # fmt: skip
    lone = target_for(mock_server, name="lone", probes=probes)  # no fleet -> never compared
    return prod, dr, lone


def test_fleet_agrees_when_regions_match(mock_server, mock_dr, healthy):
    from voltage_exporter.fleet import evaluate

    prod, dr, lone = _fleet_targets(mock_server, mock_dr)
    checks = evaluate([run_target(prod), run_target(dr), run_target(lone)])
    by = {(c.check, c.key): c for c in checks}
    assert all(c.fleet == "pci" for c in checks)
    assert by[("policy", "")].ok is True and by[("policy", "")].members == 2
    assert by[("version", "")].ok is True
    assert by[("key_table", "PCI")].ok is True and by[("key_table", "PII")].ok is True
    assert by[("token", "CC")].ok is True and by[("token", "CC-ST-64O")].ok is True


def test_fleet_detects_policy_and_key_table_divergence(mock_server, mock_dr, healthy):
    from voltage_exporter.fleet import evaluate

    prod, dr, _ = _fleet_targets(mock_server, mock_dr)
    _, dr_mod = mock_dr
    dr_mod._state["scenario"] = "key-rotated"  # DR rotated, prod did not: policy hash and PCI table differ
    try:
        checks = {(c.check, c.key): c for c in evaluate([run_target(prod), run_target(dr)])}
    finally:
        dr_mod._state["scenario"] = "healthy"
    assert checks[("policy", "")].ok is False and checks[("policy", "")].odd_ones == ["dr"]
    assert checks[("key_table", "PCI")].ok is False and checks[("key_table", "PII")].ok is True
    assert checks[("token", "CC")].ok is True  # CC is plain FPE, not on the rotated table -> still equal


def test_fleet_detects_diverged_master_secret(mock_server, mock_dr, healthy):
    """Same policy, same formats, different tokens: the DR region that was never restored."""
    from voltage_exporter.fleet import evaluate

    prod, dr, _ = _fleet_targets(mock_server, mock_dr)
    _, dr_mod = mock_dr
    dr_mod._state["scenario"] = "diverged-keys"
    try:
        rp, rd = run_target(prod), run_target(dr)
        checks = {(c.check, c.key): c for c in evaluate([rp, rd])}
    finally:
        dr_mod._state["scenario"] = "healthy"
    assert checks[("policy", "")].ok is True  # nothing in the policy file gives it away
    assert all(t.ok for t in rp.tokenize + rd.tokenize)  # each region round-trips fine on its own
    assert checks[("token", "CC")].ok is False and checks[("token", "CC")].odd_ones == ["dr"]
    assert checks[("token", "CC-ST-64O")].ok is False  # SST tables too


def test_fleet_needs_two_members_and_ignores_unfleeted(mock_server, mock_dr, healthy):
    from voltage_exporter.fleet import evaluate

    prod, _, lone = _fleet_targets(mock_server, mock_dr)
    checks = evaluate([run_target(prod), run_target(lone)])
    assert checks and all(c.ok is None and c.members == 1 for c in checks)
    assert evaluate([run_target(lone)]) == []


def test_fleet_metrics(mock_server, mock_dr, healthy):
    from prometheus_client import REGISTRY

    from voltage_exporter.fleet import evaluate

    prod, dr, _ = _fleet_targets(mock_server, mock_dr)
    _, dr_mod = mock_dr
    dr_mod._state["scenario"] = "diverged-keys"
    try:
        metrics.apply_fleet(evaluate([run_target(prod), run_target(dr)]), ["prod", "dr"])
    finally:
        dr_mod._state["scenario"] = "healthy"
    g = REGISTRY.get_sample_value
    assert g("voltage_fleet_agreement", {"fleet": "pci", "check": "token", "key": "CC"}) == 0.0
    assert g("voltage_fleet_agreement", {"fleet": "pci", "check": "policy", "key": ""}) == 1.0
    assert g("voltage_fleet_members", {"fleet": "pci", "check": "token", "key": "CC"}) == 2.0
    assert g("voltage_fleet_member_diverged", {"fleet": "pci", "check": "token", "key": "CC", "target": "dr"}) == 1.0
    assert g("voltage_fleet_member_diverged", {"fleet": "pci", "check": "token", "key": "CC", "target": "prod"}) == 0.0
    metrics.apply_fleet(evaluate([run_target(prod), run_target(dr)]), ["prod", "dr"])
    assert g("voltage_fleet_agreement", {"fleet": "pci", "check": "token", "key": "CC"}) == 1.0
    assert g("voltage_fleet_member_diverged", {"fleet": "pci", "check": "token", "key": "CC", "target": "dr"}) == 0.0


def test_fleet_config_loads(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        "targets:\n"
        "  - {name: a, policy_url: https://x/policy/clientPolicy.xml, identity: i, auth: {secret: s}, fleet: pci}\n"
        "  - {name: b, policy_url: https://y/policy/clientPolicy.xml, identity: i, auth: {secret: s}}\n"
    )
    ts = config.load(cfg).targets
    assert ts[0].fleet == "pci" and ts[1].fleet == ""


# --------------------------------------------------------------------- coverage (R6, R7)
FEED = """system,schema,table,column,classification,confidence
cards-db,public,customers,pan,PAN,0.99
cards-db,public,customers,cvv,CVV,0.97
crm,,contacts,ssn,SSN,0.95
crm,,contacts,email,EMAIL,0.40
warehouse,dw,fact_orders,card_no,PAN,
legacy,,ledger,acct,PAN,0.9
"""
DATA_MAP = {
    "version": 1,
    "columns": [
        {"system": "cards-db", "schema": "public", "table": "customers", "column": "pan",
         "district": "prod", "format": "CC", "identities": ["payments@demo.bank"], "classification": "PAN"},
        {"system": "crm", "table": "contacts", "column": "ssn",
         "district": "prod", "format": "SSN", "identities": ["crm@demo.bank"]},
        {"system": "warehouse", "schema": "dw", "table": "fact_orders", "column": "card_no",
         "district": "prod", "format": "CC-OLD", "identities": ["etl@demo.bank"]},
        {"system": "legacy", "table": "ledger", "column": "acct",
         "district": "mainframe", "format": "CC"},
        {"system": "hr", "table": "people", "column": "tax_id", "district": "prod", "format": "SSN"},
    ],
}  # fmt: skip
DESIRED = {
    "identities": {
        "payments@demo.bank": {"district": "prod", "formats": ["CC", "CC-ST-64O"]},
        "crm@demo.bank": {"district": "prod", "formats": ["AlphaNumeric"]},  # not allowed SSN
    }
}


def test_coverage_join():
    from voltage_exporter import coverage as cov

    feed, ferr = cov.parse_feed(FEED)
    dmap, merr = cov.parse_data_map(DATA_MAP)
    assert not ferr and not merr and len(feed) == 6 and len(dmap) == 5
    rep = cov.evaluate(
        feed, dmap, {"prod": ["CC", "SSN", "AlphaNumeric", "CC-ST-64O", "ORA-DATE"]},
        cov.identities_from_desired_state(DESIRED), min_confidence=0.8,
    )  # fmt: skip
    verdict = {c.row.qualified: (c.state, c.reason) for c in rep.columns}
    assert verdict["cards-db.public.customers.pan"] == ("protected", "")
    assert verdict["cards-db.public.customers.cvv"][0] == "unmapped"
    assert verdict["crm.contacts.ssn"] == ("broken", "crm@demo.bank not allowed format SSN")
    assert verdict["crm.contacts.email"][0] == "unknown"  # below confidence
    assert verdict["warehouse.dw.fact_orders.card_no"] == ("broken", "format CC-OLD not offered by district prod")
    assert verdict["legacy.ledger.acct"][0] == "unknown"  # district policy unavailable -> not blamed
    assert rep.to_dict()["totals"] == {"protected": 1, "unmapped": 1, "broken": 2, "unknown": 2}
    assert [m.qualified for m in rep.unclassified_mappings] == ["hr.people.tax_id"]
    # dead: offered, but no column and no identity uses it
    assert rep.dead_formats == {"prod": ["ORA-DATE"]}
    # class filter and identity-less evaluation
    rep2 = cov.evaluate(feed, dmap, {"prod": ["CC", "SSN"]}, None, sensitive_classes=["PAN"])
    assert {c.row.classification for c in rep2.columns} == {"PAN"}
    assert rep2.counts()[("protected", "PAN")] == 1


def test_coverage_parsers_report_errors():
    from voltage_exporter import coverage as cov

    rows, errs = cov.parse_feed("system,column\nx,y\n")
    assert rows == [] and "no 'table' column" in errs[0]
    rows, errs = cov.parse_feed("system,table,column,confidence\na,b,c,high\n,b,c,\n")
    assert len(rows) == 1 and rows[0].confidence is None and len(errs) == 2
    assert cov.parse_data_map({}) == ([], ["data map is empty"])
    entries, errs = cov.parse_data_map({"columns": [{"system": "a", "table": "b"}, "junk"]})
    assert entries == [] and len(errs) == 2
    dup, _ = cov.parse_data_map({"columns": [DATA_MAP["columns"][0], DATA_MAP["columns"][0]]})
    rep = cov.evaluate([], dup, {"prod": ["CC"]})
    assert rep.errors and "duplicate" in rep.errors[0]


def test_coverage_end_to_end_with_files_and_metrics(mock_server, healthy, tmp_path):
    import yaml
    from prometheus_client import REGISTRY

    from voltage_exporter.config import CoverageConfig
    from voltage_exporter.coverage_runner import run_coverage

    feed = tmp_path / "classification.csv"
    feed.write_text(FEED)
    dmap = tmp_path / "map.yml"
    dmap.write_text(yaml.safe_dump(DATA_MAP))
    desired = tmp_path / "voltage-config.yml"
    desired.write_text(yaml.safe_dump(DESIRED))
    cfg = CoverageConfig(str(feed), str(dmap), str(desired), min_confidence=0.8, max_named_columns=2)

    results = [run_target(target_for(mock_server))]  # mock district is 'prod'
    rep, mtime = run_coverage(cfg, results)
    assert rep is not None and mtime is not None
    totals = rep.to_dict()["totals"]
    assert totals["protected"] == 1 and totals["unmapped"] == 1 and totals["broken"] == 2 and totals["unknown"] == 2
    assert rep.dead_formats["prod"]  # the mock offers formats the map never uses

    metrics.apply_coverage(rep, mtime, cfg.max_named_columns)
    g = REGISTRY.get_sample_value
    assert g("voltage_coverage_up", {}) == 1.0
    assert g("voltage_coverage_columns", {"state": "unmapped", "classification": "CVV"}) == 1.0
    assert g("voltage_coverage_columns", {"state": "protected", "classification": "CVV"}) == 0.0  # exists at 0
    assert g("voltage_coverage_feed_rows", {}) == 6.0
    named = [s for m in REGISTRY.collect() if m.name == "voltage_coverage_column_info" for s in m.samples]
    assert len(named) == 2  # capped
    assert g("voltage_coverage_dead_format", {"district": "prod", "format": "ORA-DATE"}) == 1.0

    # inputs missing -> coverage_up 0, nothing else touched
    rep2, _ = run_coverage(CoverageConfig(str(tmp_path / "nope.csv"), str(dmap)), results)
    assert rep2 is None
    metrics.apply_coverage(rep2, None)
    assert g("voltage_coverage_up", {}) == 0.0


def test_coverage_config_loads(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        "coverage: {classification_csv: /x.csv, data_map: /m.yml, sensitive_classes: [PAN], min_confidence: 0.9}\n"
        "targets:\n  - {name: a, policy_url: https://x/policy/clientPolicy.xml, identity: i, auth: {secret: s}}\n"
    )
    c = config.load(cfg).coverage
    assert c and c.sensitive_classes == ["PAN"] and c.min_confidence == 0.9 and c.desired_state == ""
    cfg.write_text(
        "coverage: {classification_csv: /x.csv}\n"
        "targets:\n  - {name: a, policy_url: https://x/policy/clientPolicy.xml, identity: i, auth: {secret: s}}\n"
    )
    with pytest.raises(config.ConfigError):
        config.load(cfg)


# --------------------------------------------------------------------- SDM: masking quality + jobs (R8, R9)
@pytest.fixture(scope="module")
def nonprod_db(tmp_path_factory):
    """The demo seeder, exactly as compose runs it."""
    import importlib.util as ilu
    from pathlib import Path

    seed = Path(__file__).resolve().parents[2] / "demo" / "seed_nonprod.py"
    spec = ilu.spec_from_file_location("seed_nonprod", seed)
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    path = tmp_path_factory.mktemp("sdm") / "nonprod.db"
    mod.main(str(path))
    return str(path), mod.CANARIES


def _sdm_cfg(db, canaries):
    return {
        "masking": [
            {"name": "pan-leak", "kind": "leak", "source": {"type": "sql", "dsn": f"sqlite:///{db}"},
             "query": "SELECT pan FROM customers", "canaries": canaries},
            {"name": "pan-ri", "kind": "consistency", "source": {"type": "sql", "dsn": f"sqlite:///{db}"},
             "query": "SELECT c.customer_id, c.pan, o.pan FROM customers c JOIN orders o USING (customer_id)"},
            {"name": "ssn-constant", "kind": "constant", "source": {"type": "sql", "dsn": f"sqlite:///{db}"},
             "query": "SELECT ssn FROM customers"},
            {"name": "pan-heuristic", "kind": "leak", "source": {"type": "sql", "dsn": f"sqlite:///{db}"},
             "query": "SELECT pan FROM customers", "classification": "PAN", "heuristic": True},
        ],
        "jobs": [
            {"name": "sdm", "source": {"type": "sql", "dsn": f"sqlite:///{db}"},
             "query": "SELECT job_name, status, finished_at, rows_processed FROM sdm_job_history",
             "expect_every": "24h"},
        ],
    }  # fmt: skip


def test_sdm_masking_checks_on_demo_db(nonprod_db):
    from voltage_exporter import sdm

    db, canaries = nonprod_db
    cfg = sdm.parse_config(_sdm_cfg(db, canaries))
    res = {m.name: sdm.run_mask_check(m) for m in cfg.masking}
    leak = res["pan-leak"]
    assert leak.ok is False and leak.hits == 1 and leak.rows == 40  # the planted canary row
    assert canaries[0] not in leak.detail  # never printed
    assert res["pan-ri"].ok is True and res["pan-ri"].hits == 0
    const = res["ssn-constant"]
    assert const.ok is False and "identical" in const.detail
    # the heuristic is *narrow*: masked PANs are not Luhn-valid here, the canary is -> exactly 1 hit
    assert res["pan-heuristic"].ok is False and res["pan-heuristic"].hits == 1


def test_sdm_leak_needs_a_method_and_reads_canary_files(nonprod_db, tmp_path):
    from voltage_exporter import sdm

    db, canaries = nonprod_db
    src = {"type": "sql", "dsn": f"sqlite:///{db}"}
    none = sdm.parse_config(
        {"masking": [{"name": "x", "kind": "leak", "source": src, "query": "SELECT pan FROM customers"}]}
    )
    r = sdm.run_mask_check(none.masking[0])
    assert r.ok is None and "needs canaries" in r.detail
    # canary file, hashed
    import hashlib

    f = tmp_path / "canaries.sha256"
    f.write_text("\n".join(hashlib.sha256(c.encode()).hexdigest() for c in canaries) + "\n")
    hashed = sdm.parse_config(
        {"masking": [{"name": "x", "kind": "leak", "source": src, "query": "SELECT pan FROM customers",
                      "canary_file": str(f), "canaries_hashed": True}]}
    )  # fmt: skip
    r = sdm.run_mask_check(hashed.masking[0])
    assert r.ok is False and r.hits == 1


def test_sdm_consistency_detects_inconsistent_keys(tmp_path):
    import sqlite3

    from voltage_exporter import sdm

    db = tmp_path / "t.db"
    c = sqlite3.connect(db)
    c.executescript("CREATE TABLE a(k, v); CREATE TABLE b(k, v);")
    c.executemany("INSERT INTO a VALUES (?,?)", [(1, "m1"), (2, "m2"), (3, "m3")])
    c.executemany("INSERT INTO b VALUES (?,?)", [(1, "m1"), (2, "DIFFERENT"), (3, "m3")])
    c.commit()
    c.close()
    cfg = sdm.parse_config(
        {"masking": [{"name": "ri", "kind": "consistency", "source": {"type": "sql", "dsn": f"sqlite:///{db}"},
                      "query": "SELECT a.k, a.v, b.v FROM a JOIN b ON a.k = b.k"}]}
    )  # fmt: skip
    r = sdm.run_mask_check(cfg.masking[0])
    assert r.ok is False and r.hits == 1


def test_sdm_file_source_and_bad_inputs(tmp_path):
    from voltage_exporter import sdm

    f = tmp_path / "masked.csv"
    f.write_text("id,pan\n1,4539000000000001\n2,4539000000000002\n")
    cfg = sdm.parse_config(
        {"masking": [{"name": "f", "kind": "leak", "source": {"type": "file", "path": str(f)}, "columns": ["pan"],
                      "canaries": ["4539000000000002"]}]}
    )  # fmt: skip
    r = sdm.run_mask_check(cfg.masking[0])
    assert r.ok is False and r.hits == 1 and r.rows == 2
    missing = sdm.parse_config(
        {"masking": [{"name": "f", "kind": "leak", "source": {"type": "file", "path": str(tmp_path / "nope.csv")},
                      "columns": ["pan"], "canaries": ["x"]}]}
    )  # fmt: skip
    assert sdm.run_mask_check(missing.masking[0]).ok is None
    with pytest.raises(Exception, match="unknown kind"):
        sdm.parse_config({"masking": [{"name": "x", "kind": "magic", "source": {"type": "file", "path": "p"}}]})
    with pytest.raises(Exception, match="SELECT"):
        from voltage_exporter.sources import Source, query_rows

        query_rows(Source.from_config({"type": "sql", "dsn": "sqlite://:memory:"}), "DROP TABLE x")


def test_sdm_jobs_stale_and_failing(nonprod_db):
    from voltage_exporter import sdm

    db, canaries = nonprod_db
    cfg = sdm.parse_config(_sdm_cfg(db, canaries))
    r = sdm.run_job_check(cfg.jobs[0])
    assert r.ok is False
    assert [j.job for j in r.jobs] == ["archive-orders-2019", "mask-nonprod-refresh"]
    assert r.stale == ["mask-nonprod-refresh"] and r.failing == ["mask-nonprod-refresh"]
    assert (
        "archive-orders-2019" in r.last_success and "mask-nonprod-refresh" in r.last_success
    )  # 3 days ago, still known
    latest = {j.job: j for j in r.jobs}
    assert latest["archive-orders-2019"].status == "success" and latest["archive-orders-2019"].rows == 1_198_002
    assert latest["mask-nonprod-refresh"].status == "failed"
    # a generous window makes the stale one fine (the failure remains)
    cfg.jobs[0].expect_every_seconds = 10 * 86400
    r2 = sdm.run_job_check(cfg.jobs[0])
    assert r2.stale == [] and r2.failing == ["mask-nonprod-refresh"]
    assert sdm._duration("90m", 0) == 5400 and sdm._duration("7d", 0) == 7 * 86400 and sdm._duration(30, 0) == 30


def test_sdm_metrics(nonprod_db):
    from prometheus_client import REGISTRY

    from voltage_exporter import sdm

    db, canaries = nonprod_db
    cfg = sdm.parse_config(_sdm_cfg(db, canaries))
    metrics.apply_sdm([sdm.run_mask_check(m) for m in cfg.masking], [sdm.run_job_check(j) for j in cfg.jobs])
    g = REGISTRY.get_sample_value
    assert g("voltage_sdm_mask_ok", {"check": "pan-leak", "kind": "leak"}) == 0.0
    assert g("voltage_sdm_mask_hits", {"check": "pan-leak", "kind": "leak"}) == 1.0
    assert g("voltage_sdm_mask_ok", {"check": "pan-ri", "kind": "consistency"}) == 1.0
    assert g("voltage_sdm_check_up", {"check": "pan-leak", "kind": "leak"}) == 1.0
    assert g("voltage_sdm_job_stale", {"check": "sdm", "job": "mask-nonprod-refresh"}) == 1.0
    assert g("voltage_sdm_job_failing", {"check": "sdm", "job": "mask-nonprod-refresh"}) == 1.0
    assert g("voltage_sdm_job_stale", {"check": "sdm", "job": "archive-orders-2019"}) == 0.0
    assert g("voltage_sdm_job_last_rows", {"check": "sdm", "job": "archive-orders-2019"}) == 1_198_002.0
    assert g("voltage_sdm_job_last_status", {"check": "sdm", "job": "mask-nonprod-refresh", "status": "failed"}) == 1.0
    assert g("voltage_sdm_job_last_success_timestamp_seconds", {"check": "sdm", "job": "archive-orders-2019"}) > 0


def test_sdm_config_loads(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        "sdm:\n  masking:\n"
        "    - {name: x, kind: leak, source: {type: file, path: /m.csv}, columns: [pan], canaries: [a]}\n"
        "targets:\n  - {name: a, policy_url: https://x/policy/clientPolicy.xml, identity: i, auth: {secret: s}}\n"
    )
    assert config.load(cfg).sdm["masking"][0]["name"] == "x"
