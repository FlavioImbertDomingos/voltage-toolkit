"""Pretend PagerDuty (Events API v2) and Splunk (HTTP Event Collector), for the demo and CI.

It records what Alertmanager sends so the compose smoke test can assert "the masking-leak alert
reached PagerDuty and Splunk" without accounts. Behaves like the real endpoints where it matters:

  POST /v2/enqueue                  PagerDuty Events API v2: validates routing_key (32 chars),
                                    event_action (trigger|acknowledge|resolve), payload.summary;
                                    answers 202 {"status":"success","dedup_key":...}
  POST /services/collector/raw      Splunk HEC raw endpoint: needs `Authorization: Splunk <token>`
  POST /services/collector/event    Splunk HEC event endpoint: same auth, body must carry "event"
  GET  /received[?kind=pagerduty|splunk] everything captured, newest last
  DELETE /received                       forget everything
  GET  /health

stdlib only: no dependencies to install, ~150 lines, nothing clever.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PD_KEY = os.environ.get("MOCK_PAGERDUTY_KEY", "demo0000000000000000000000000000")
HEC_TOKEN = os.environ.get("MOCK_SPLUNK_TOKEN", "demo-hec-token")
PORT = int(os.environ.get("MOCK_INTEGRATIONS_PORT", "8900"))

_lock = threading.Lock()
_received: list[dict] = []


def _record(kind: str, body: object, headers: dict, ok: bool, note: str = "") -> None:
    with _lock:
        _received.append(
            {
                "ts": time.time(),
                "kind": kind,
                "ok": ok,
                "note": note,
                "headers": {
                    k: v for k, v in headers.items() if k.lower() in ("content-type", "user-agent")
                },
                "body": body,
            }
        )
        del _received[:-500]


class Handler(BaseHTTPRequestHandler):
    server_version = "mock-integrations/1"

    def log_message(self, fmt, *args):  # quieter than the default
        print(f"{self.address_string()} {fmt % args}", flush=True)

    # ------------------------------------------------------------------ helpers
    def _send(self, code: int, obj: object) -> None:
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    # ------------------------------------------------------------------ routes
    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True})
        if self.path.startswith("/received"):
            kind = ""
            if "?" in self.path:
                for kv in self.path.split("?", 1)[1].split("&"):
                    if kv.startswith("kind="):
                        kind = kv[5:]
            with _lock:
                items = [r for r in _received if not kind or r["kind"] == kind]
            return self._send(200, {"count": len(items), "received": items})
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        if self.path.startswith("/received"):
            with _lock:
                _received.clear()
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        raw = self._body()
        headers = dict(self.headers.items())
        if self.path == "/v2/enqueue":
            return self._pagerduty(raw, headers)
        if self.path.startswith("/services/collector/raw"):
            return self._splunk(raw, headers, event_required=False)
        if (
            self.path.startswith("/services/collector/event")
            or self.path.rstrip("/") == "/services/collector"
        ):
            return self._splunk(raw, headers, event_required=True)
        self._send(404, {"error": "not found"})

    def _pagerduty(self, raw: bytes, headers: dict):
        try:
            ev = json.loads(raw or b"{}")
        except ValueError:
            _record("pagerduty", raw.decode(errors="replace"), headers, False, "invalid json")
            return self._send(400, {"status": "invalid event", "errors": ["body is not JSON"]})
        errors = []
        if ev.get("routing_key") != PD_KEY:
            errors.append(
                "routing_key is invalid or not 32 characters"
                if len(str(ev.get("routing_key", ""))) != 32
                else "routing_key unknown"
            )
        if ev.get("event_action") not in ("trigger", "acknowledge", "resolve"):
            errors.append("event_action must be trigger, acknowledge or resolve")
        payload = ev.get("payload") or {}
        if ev.get("event_action") == "trigger":
            for req in ("summary", "source", "severity"):
                if not payload.get(req):
                    errors.append(f"payload.{req} is required")
            if payload.get("severity") not in ("critical", "error", "warning", "info", None):
                errors.append("payload.severity must be critical, error, warning or info")
        if errors:
            _record("pagerduty", ev, headers, False, "; ".join(errors))
            return self._send(
                400,
                {"status": "invalid event", "message": "Event object is invalid", "errors": errors},
            )
        _record("pagerduty", ev, headers, True, ev.get("event_action", ""))
        self._send(
            202,
            {
                "status": "success",
                "message": "Event processed",
                "dedup_key": ev.get("dedup_key") or "mock",
            },
        )

    def _splunk(self, raw: bytes, headers: dict, *, event_required: bool):
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if auth != f"Splunk {HEC_TOKEN}":
            _record("splunk", raw.decode(errors="replace"), headers, False, "bad token")
            return self._send(403, {"text": "Invalid token", "code": 4})
        body: object
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = raw.decode(errors="replace")
        if event_required and not (isinstance(body, dict) and "event" in body):
            _record("splunk", body, headers, False, "no event field")
            return self._send(400, {"text": "No data", "code": 5})
        _record("splunk", body, headers, True, "raw" if not event_required else "event")
        self._send(200, {"text": "Success", "code": 0})


if __name__ == "__main__":
    print(f"mock-integrations on :{PORT} (PagerDuty + Splunk HEC)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
