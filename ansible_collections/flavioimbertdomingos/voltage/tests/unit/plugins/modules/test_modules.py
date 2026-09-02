from __future__ import annotations

import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import yaml

from ...conftest import run_module

# --------------------------------------------------------------------- file backend
def test_identity_file_backend_is_idempotent(state_file):
    args = dict(name="payments@x", district="prod", formats=["CC"], owner="pay",
                backend={"type": "file", "path": state_file})  # fmt: skip
    r1 = run_module("voltage_identity", args)
    assert r1["changed"] and r1["before"] is None and r1["after"]["formats"] == ["CC"]
    r2 = run_module("voltage_identity", args)
    assert not r2["changed"]
    doc = yaml.safe_load(open(state_file))
    assert doc["identities"]["payments@x"]["owner"] == "pay"
    # partial update keeps unspecified fields
    r3 = run_module("voltage_identity", dict(name="payments@x", formats=["CC", "SSN"], backend=args["backend"]))
    assert r3["changed"] and r3["after"]["owner"] == "pay" and r3["after"]["formats"] == ["CC", "SSN"]
    # absent
    r4 = run_module("voltage_identity", dict(name="payments@x", state="absent", backend=args["backend"]))
    assert r4["changed"] and r4["after"] is None
    assert "payments@x" not in yaml.safe_load(open(state_file))["identities"]


def test_check_mode_and_diff_do_not_write(state_file):
    args = dict(name="prod", formats=["CC", {"name": "T", "kind": "tokenization"}], auth_methods=["LDAP"],
                backend={"type": "file", "path": state_file})  # fmt: skip
    r = run_module("voltage_district", args, check_mode=True, diff=True)
    assert r["changed"] and "diff" in r and r["diff"]["after"]["prod"]["formats"][1]["kind"] == "tokenization"
    assert not os.path.exists(state_file)
    r = run_module("voltage_district", args)
    assert r["changed"]
    assert yaml.safe_load(open(state_file))["districts"]["prod"]["formats"][0] == {"name": "CC", "kind": "fpe"}


def test_auth_method_json_document(tmp_path):
    path = str(tmp_path / "cfg.json")
    r = run_module("voltage_auth_method", dict(name="LDAP", district="prod", type="ldap",
                                               settings={"ldap_url": "ldaps://x"}, secret_ref="vault:x",
                                               backend={"type": "file", "path": path}))  # fmt: skip
    assert r["changed"]
    assert json.load(open(path))["auth_methods"]["LDAP"]["settings"]["ldap_url"] == "ldaps://x"


def test_secret_is_not_logged(state_file):
    r = run_module("voltage_probe", dict(policy_url="https://127.0.0.1:1/policy/clientPolicy.xml", identity="i",
                                         secret="SUPERSECRET", format="CC", sample="1", fail_on_error=False,
                                         validate_certs=False, timeout=1))  # fmt: skip
    assert "SUPERSECRET" not in json.dumps(r)
    assert r["ok"] is False and r["error"]


# --------------------------------------------------------------------- command backend
def test_command_backend(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text(
        "#!/usr/bin/env python3\nimport json,sys\nreq=json.load(sys.stdin)\n"
        "print(json.dumps({'changed': req['state']=='present', 'before': None, 'after': req['spec'], 'message': 'ok '+req['kind']}))\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    r = run_module("voltage_identity", dict(name="a@x", district="d", backend={"type": "command", "command": f"python3 {script}"}))
    assert r["changed"] and r["after"] == {"district": "d"} and r["adapter_message"] == "ok identities"
    r = run_module("voltage_identity", dict(name="a@x", state="absent", backend={"type": "command", "command": f"python3 {script}"}))
    assert not r["changed"]


def test_command_backend_failure_is_reported(tmp_path):
    r = run_module("voltage_identity", dict(name="a@x", backend={"type": "command", "command": "false"}))
    assert r.get("failed") and "adapter command failed" in r["msg"]


# --------------------------------------------------------------------- http backend
class _Store(BaseHTTPRequestHandler):
    data: dict = {}
    calls: list = []

    def _send(self, code, body=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())

    def do_GET(self):  # noqa: N802
        _Store.calls.append(("GET", self.path, self.headers.get("Authorization")))
        if self.path in _Store.data:
            self._send(200, _Store.data[self.path])
        else:
            self._send(404, {"error": "not found"})

    def do_PUT(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Store.calls.append(("PUT", self.path, body))
        _Store.data[self.path] = body
        self._send(200, body)

    def do_DELETE(self):  # noqa: N802
        _Store.calls.append(("DELETE", self.path, None))
        _Store.data.pop(self.path, None)
        self._send(204)

    def log_message(self, *a):
        pass


def test_http_backend():
    srv = HTTPServer(("127.0.0.1", 0), _Store)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/api"
    backend = {"type": "http", "url": url, "token": "T0K"}
    r = run_module("voltage_district", dict(name="prod", auth_methods=["LDAP"], backend=backend))
    assert r["changed"] and r["endpoint"].endswith("/api/districts/prod")
    assert _Store.data["/api/districts/prod"] == {"auth_methods": ["LDAP"]}
    assert any(c[0] == "GET" and c[2] == "Bearer T0K" for c in _Store.calls)
    r = run_module("voltage_district", dict(name="prod", auth_methods=["LDAP"], backend=backend))
    assert not r["changed"]
    r = run_module("voltage_district", dict(name="prod", state="absent", backend=backend))
    assert r["changed"] and "/api/districts/prod" not in _Store.data
    srv.shutdown()


# --------------------------------------------------------------------- live modules against the mock appliance
def test_policy_facts_and_probe_against_mock(mock_server):
    _, https, mod = mock_server
    mod._state["scenario"] = "healthy"
    r = run_module("voltage_policy_facts", dict(policy_url=f"{https}/policy/clientPolicy.xml", validate_certs=False))
    facts = r["ansible_facts"]["voltage_policy"]
    assert facts["district"] == "prod" and "CC" in facts["format_names"] and "SharedSecret" in facts["auth_methods"]

    common = dict(policy_url=f"{https}/policy/clientPolicy.xml", validate_certs=False, identity="probe@demo.bank",
                  secret="probe-secret", format="CC", sample="4111111111111111")  # fmt: skip
    r = run_module("voltage_probe", common)
    assert r["ok"] and r["format_preserved"] and r["protected"] != "4111111111111111" and r["protect_seconds"] < 2
    r = run_module("voltage_probe", dict(common, api="soap", identity="monitor", auth_method="password", secret="changeme"))
    assert r["ok"], r
    r = run_module("voltage_probe", dict(common, secret="wrong"))
    assert r.get("failed") and "401" in r["msg"]
    mod._state["scenario"] = "auth-fail"
    r = run_module("voltage_probe", dict(common, fail_on_error=False))
    assert not r["ok"] and not r.get("failed")
    mod._state["scenario"] = "healthy"
