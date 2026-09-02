"""A pretend Voltage SecureData appliance.

Serves the three things a SecureData client touches:

  GET  /policy/clientPolicy.xml                       the client policy (formats, auth methods, key servers)
  POST /vibesimple/rest/v1/protect  and  /access       REST Web Services API (JSON)
  POST /vibesimple/services/VibeSimpleSOAP             SOAP Web Services API (ProtectFormattedData / AccessFormattedData)
  GET  /vibekeys/                                     a stand-in key server endpoint

"FPE" here is a toy, reversible, format-preserving substitution keyed by a secret.
It preserves length and character classes like FF1 does, and it is NOT
cryptography. It exists so the exporter and the Ansible collection can be built,
demoed and tested without a Voltage licence.

Scenarios (switch at runtime: `curl -X POST localhost:8800/mock/scenario/slow`):

  healthy         everything fine
  slow            protect/access take 800-1500 ms
  errors          ~50% of protect/access calls return HTTP 500
  auth-fail       every Web Services call answers 401
  policy-down     clientPolicy.xml returns 503 (nothing can start)
  keyserver-down  /vibekeys/ returns 503
  policy-changed  a new format appears in the policy (drift)
  cert-expiring   (startup only) HTTPS cert valid for 7 days -- MOCK_TLS_CERT_DAYS=7
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import logging
import os
import random
import re
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, Response, jsonify, request

log = logging.getLogger("mock-voltage")
app = Flask(__name__)

DISTRICT = os.environ.get("MOCK_DISTRICT", "prod")
KEY_HOST = os.environ.get("MOCK_KEY_HOST", "voltage-pp-0000.demo.bank")
IDENTITIES = {  # identity -> shared secret
    "probe@demo.bank": os.environ.get("MOCK_SHARED_SECRET", "probe-secret"),
    "payments@demo.bank": "payments-secret",
}
USERS = {
    "monitor": os.environ.get("MOCK_PASSWORD", "changeme")
}  # username -> password (LDAP-style)

FPE_FORMATS = {
    "CC": {"description": "Credit card, preserves BIN(6) and last 4"},
    "SSN": {"description": "US Social Security Number"},
    "AlphaNumeric": {},
    "UpperCaseAlphaNumeric": {},
    "US7ASCII-PRINTABLE": {},
    "ORA-DATE": {},
}
TOKEN_FORMATS = {"CC-ST-64O": {"description": "Secure Stateless Tokenization, keeps last 4"}}

SCENARIOS = {
    "healthy": "Everything is fine.",
    "slow": "protect/access take 800-1500 ms.",
    "errors": "About half of protect/access calls fail with HTTP 500.",
    "auth-fail": "Every Web Services call answers 401.",
    "policy-down": "clientPolicy.xml returns 503.",
    "keyserver-down": "The key server endpoint returns 503.",
    "policy-changed": "A new format (PHONE) appears in the policy.",
}
_state = {
    "scenario": os.environ.get("MOCK_SCENARIO", "healthy"),
    "started": time.time(),
    "lock": threading.Lock(),
}
if _state["scenario"] not in SCENARIOS:
    raise SystemExit(f"unknown MOCK_SCENARIO {_state['scenario']!r}")


def scenario() -> str:
    return _state["scenario"]


# ------------------------------------------------------------------ toy FPE
_SECRET = os.environ.get("MOCK_FPE_KEY", "not-a-real-key").encode()


def _perm(alphabet: str, salt: str) -> dict[str, str]:
    seed = int.from_bytes(hashlib.sha256(_SECRET + salt.encode()).digest()[:8], "big")
    chars = list(alphabet)
    random.Random(seed).shuffle(chars)
    return dict(zip(alphabet, chars, strict=True))


_DIG = "0123456789"
_UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOW = _UP.lower()


def fpe(value: str, fmt: str, reverse: bool = False) -> str:
    """Length- and class-preserving substitution. Position-dependent so it's not a trivial table."""
    out = []
    keep = set()
    if fmt == "CC":
        digits_idx = [i for i, c in enumerate(value) if c.isdigit()]
        keep = set(digits_idx[:6] + digits_idx[-4:])  # keep BIN + last 4 like a real CC format
    for i, ch in enumerate(value):
        if i in keep:
            out.append(ch)
            continue
        for alphabet in (_DIG, _UP, _LOW):
            if ch in alphabet:
                p = _perm(alphabet, f"{fmt}:{i}")
                if reverse:
                    p = {v: k for k, v in p.items()}
                out.append(p[ch])
                break
        else:
            out.append(ch)
    return "".join(out)


def tokenize(value: str, fmt: str, reverse: bool = False) -> str:
    """SST look-alike: opaque token that keeps the last 4 digits."""
    if reverse:
        # tokens are stored in memory; a real SST is stateless via a token table
        return _TOKENS.get(value, value)
    digits = re.sub(r"\D", "", value)
    tok = hashlib.sha256(_SECRET + fmt.encode() + value.encode()).hexdigest()[
        : max(4, len(digits) - 4)
    ]
    token = "".join(str(int(c, 16) % 10) for c in tok) + digits[-4:]
    _TOKENS[token] = value
    return token


_TOKENS: dict[str, str] = {}


# ------------------------------------------------------------------ auth
def _check_auth(identity: str | None, body: dict | None) -> str | None:
    """Returns an error string or None. Accepts Basic (identity:secret | user:pass) or body fields."""
    if scenario() == "auth-fail":
        return "authentication failed (scenario)"
    body = body or {}
    if body.get("sharedSecret") is not None:
        return (
            None if IDENTITIES.get(identity or "") == body["sharedSecret"] else "bad shared secret"
        )
    if body.get("username") is not None:
        return (
            None if USERS.get(body["username"]) == body.get("password") else "bad username/password"
        )
    header = request.headers.get("Authorization", "")
    if header.startswith("Basic "):
        try:
            user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
        except Exception:  # noqa: BLE001
            return "bad Authorization header"
        if IDENTITIES.get(user) == pw or USERS.get(user) == pw:
            return None
        return "bad credentials"
    return "no credentials"


def _maybe_delay_or_fail():
    if scenario() == "slow":
        time.sleep(random.uniform(0.8, 1.5))
    if scenario() == "errors" and random.random() < 0.5:
        return jsonify({"error": "internal error (scenario)"}), 500
    return None


def _do(op: str, fmt: str, values: list[str]) -> list[str] | str:
    if fmt in TOKEN_FORMATS:
        return [tokenize(v, fmt, reverse=(op == "access")) for v in values]
    if fmt in FPE_FORMATS or (fmt == "PHONE" and scenario() == "policy-changed"):
        return [fpe(v, fmt, reverse=(op == "access")) for v in values]
    return f"unknown format {fmt!r}"


# ------------------------------------------------------------------ policy
@app.get("/policy/clientPolicy.xml")
def client_policy():
    if scenario() == "policy-down":
        return Response("policy server unavailable\n", 503)
    fpe_formats = dict(FPE_FORMATS)
    if scenario() == "policy-changed":
        fpe_formats["PHONE"] = {"description": "added by scenario"}
    fmts = "".join(
        f'    <Format name="{n}" type="FPE"{" description=" + chr(34) + a["description"] + chr(34) if a.get("description") else ""}/>\n'
        for n, a in fpe_formats.items()
    )  # noqa: E501
    toks = "".join(
        f'    <Format name="{n}" type="SST" description="{a["description"]}"/>\n'
        for n, a in TOKEN_FORMATS.items()
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<clientPolicy version="7.0.2" district="{DISTRICT}" policyId="{DISTRICT}-2026-09">
  <KeyServers>
    <KeyServer url="https://{KEY_HOST}/vibekeys/"/>
  </KeyServers>
  <AuthMethods>
    <AuthMethod name="SharedSecret"/>
    <AuthMethod name="UsernamePassword"/>
    <AuthMethod name="LDAP"/>
  </AuthMethods>
  <FormatMappings>
{fmts}  </FormatMappings>
  <TokenizationFormats>
{toks}  </TokenizationFormats>
</clientPolicy>
"""
    return Response(xml, mimetype="application/xml")


@app.get("/vibekeys/")
def keyserver():
    if scenario() == "keyserver-down":
        return Response("key server unavailable\n", 503)
    return jsonify({"service": "vibekeys", "district": DISTRICT, "status": "ok"})


# ------------------------------------------------------------------ REST
@app.post("/vibesimple/rest/v1/<op>")
def rest_op(op: str):
    if op not in ("protect", "access"):
        return jsonify({"error": "unknown operation"}), 404
    body = request.get_json(silent=True) or {}
    err = _check_auth(body.get("identity"), body)
    if err:
        return jsonify({"error": err}), 401
    delayed = _maybe_delay_or_fail()
    if delayed:
        return delayed
    fmt, data = body.get("format"), body.get("data")
    if not fmt or not isinstance(data, list):
        return jsonify({"error": "format and data[] required"}), 400
    result = _do(op, fmt, [str(v) for v in data])
    if isinstance(result, str):
        return jsonify({"error": result}), 400
    return jsonify({"data": result, "format": fmt, "identity": body.get("identity")})


# ------------------------------------------------------------------ SOAP
_TAG = re.compile(r"<(?:\w+:)?(\w+)>([^<]*)</(?:\w+:)?\1>")  # leaf elements only


def _soap_fault(msg: str, code: int = 500):
    body = (
        '<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        f"<soapenv:Body><soapenv:Fault><faultcode>soapenv:Client</faultcode><faultstring>{msg}</faultstring>"
        "</soapenv:Fault></soapenv:Body></soapenv:Envelope>"
    )
    return Response(body, code, mimetype="text/xml")


@app.post("/vibesimple/services/VibeSimpleSOAP")
def soap():
    text = request.get_data(as_text=True)
    m = re.search(r"<(?:\w+:)?(ProtectFormattedData|AccessFormattedData)\b", text)
    if not m:
        return _soap_fault("unknown operation", 400)
    op = "protect" if m.group(1).startswith("Protect") else "access"
    fields = {k: v for k, v in _TAG.findall(text)}
    body = {k: fields[k] for k in ("sharedSecret", "username", "password") if k in fields}
    err = _check_auth(fields.get("identity"), body if body else None)
    if err:
        return _soap_fault(err, 401)
    delayed = _maybe_delay_or_fail()
    if delayed:
        return _soap_fault("internal error (scenario)", 500)
    result = _do(op, fields.get("format", ""), [fields.get("data", "")])
    if isinstance(result, str):
        return _soap_fault(result, 400)
    resp = (
        '<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        f'xmlns:vs="http://voltage.com/vibesimple"><soapenv:Body><vs:{m.group(1)}Response>'
        f"<data>{result[0]}</data></vs:{m.group(1)}Response></soapenv:Body></soapenv:Envelope>"
    )
    return Response(resp, mimetype="text/xml")


# ------------------------------------------------------------------ mock controls
@app.get("/mock/health")
def health():
    return "ok\n"


@app.get("/mock/scenario")
def get_scenario():
    return jsonify({"scenario": scenario(), "available": SCENARIOS})


@app.post("/mock/scenario/<name>")
def set_scenario(name: str):
    if name not in SCENARIOS:
        return jsonify({"error": f"unknown scenario {name!r}", "available": list(SCENARIOS)}), 400
    with _state["lock"]:
        _state["scenario"] = name
    log.info("scenario -> %s", name)
    return jsonify({"scenario": name, "description": SCENARIOS[name]})


# ------------------------------------------------------------------ TLS
def _self_signed(days: int, cn: str) -> tuple[str, str]:
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mock Voltage"),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("localhost"), x509.DNSName("voltage")]), critical=False)
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cp, kp


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    http_port = int(os.environ.get("MOCK_PORT", "8800"))
    https_port = int(os.environ.get("MOCK_TLS_PORT", "8443"))
    days = int(os.environ.get("MOCK_TLS_CERT_DAYS", "400"))
    cert, key = _self_signed(days, KEY_HOST)
    threading.Thread(
        target=lambda: app.run(
            host="0.0.0.0", port=https_port, ssl_context=(cert, key), threaded=True
        ),  # noqa: S104
        daemon=True,
    ).start()
    log.info(
        "mock Voltage: http :%d, https :%d (cert %d days), scenario=%s",
        http_port,
        https_port,
        days,
        scenario(),
    )
    app.run(host="0.0.0.0", port=http_port, threaded=True)  # noqa: S104


if __name__ == "__main__":
    main()
