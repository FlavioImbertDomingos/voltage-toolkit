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
    assert r.policy_ok and r.policy.district == "prod" and len(r.policy.formats) == 7
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
