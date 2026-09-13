"""Structured (JSON) logging: one event per target per probe cycle, for a SIEM.  (roadmap R17)

Prometheus answers "is it broken *now*". A SIEM (Splunk, Sentinel, Elastic) answers "when did it
start, what changed just before, and who was affected" -- and it keeps the answer for a year.
Feeding it is not a metric problem, it is a log problem: every probe cycle the exporter emits
one line per target that says everything the dashboard knows, as JSON, so a forwarder can ship
it without parsing anything.

    {"ts": "...", "level": "INFO", "logger": "voltage_exporter.metrics", "event": "probe",
     "target": "demo-prod", "policy_ok": true, "policy_sha256": "…", "server_version": "7.0.3…",
     "probes": [{"format": "CC", "ok": true, "protect_ms": 24.1, "access_ms": 19.7,
                 "roundtrip_ok": true, "error_kind": ""}],
     "integrity_ok": true, "keyservers_up": 2, "keyservers_total": 2,
     "tls_min_days": 21.4, "duration_ms": 208}

Search examples are in docs/INTEGRATIONS.md. Values are hashes and booleans only -- no token,
no sample, no secret ever appears in a log line.
"""

from __future__ import annotations

import json
import logging
import time

from .probes import TargetResult

EVENT_ATTR = "event_fields"  # logging `extra` key carrying the structured payload


class JsonFormatter(logging.Formatter):
    """One JSON object per line. `extra={"event_fields": {...}}` merges into the object."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        obj: dict = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, EVENT_ATTR, None)
        if isinstance(fields, dict):
            obj.update(fields)
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(obj, default=str, separators=(",", ":"))


def configure_logging(level: str, fmt: str) -> None:
    """fmt: 'text' (human, the default) or 'json' (one object per line, for a forwarder)."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _ms(seconds: float | None) -> float | None:
    return round(seconds * 1000, 1) if seconds is not None else None


def target_event(r: TargetResult) -> dict:
    """The structured payload for one target's cycle. Booleans, hashes and numbers only."""
    now = time.time()
    not_afters = [t.not_after for t in r.tls if t.not_after]
    integrity = [i.ok for i in r.integrity if i.ok is not None]
    ev: dict = {
        "event": "probe",
        "target": r.target.name,
        "fleet": r.target.fleet or "",
        "policy_ok": r.policy_ok,
        "policy_error": r.policy_error,
        "policy_ms": _ms(r.policy_seconds),
        "policy_sha256": r.policy.sha256 if r.policy else "",
        "policy_fingerprint": r.policy.config_fingerprint if r.policy else "",
        "server_version": r.policy.server_version if r.policy else "",
        "district": r.policy.district if r.policy else "",
        "formats": len(r.policy.formats) if r.policy else 0,
        "key_tables": {kt.name: kt.current_number for kt in r.policy.key_tables} if r.policy else {},
        "probes": [
            {
                "format": tk.spec.format,
                "identity": tk.spec.identity or r.target.identity,
                "ok": tk.ok,
                "protect_ms": _ms(tk.protect_seconds),
                "access_ms": _ms(tk.access_seconds),
                "roundtrip_ok": tk.roundtrip_ok,
                "format_preserved": tk.format_preserved,
                "token_sha256": tk.token_sha256[:16] if tk.token_sha256 else "",
                "error_kind": tk.error_kind,
                "error": tk.error,
            }
            for tk in r.tokenize
        ],
        "probes_ok": sum(1 for tk in r.tokenize if tk.ok),
        "probes_total": len(r.tokenize),
        "integrity_ok": all(integrity) if integrity else None,
        "integrity_failed": [f"{i.check}:{i.format}" for i in r.integrity if i.ok is False],
        "keyservers_up": sum(1 for ok in r.keyservers.values() if ok),
        "keyservers_total": len(r.keyservers),
        "tls_ok": all(t.ok for t in r.tls) if r.tls else None,
        "tls_min_days": round((min(not_afters) - now) / 86400, 1) if not_afters else None,
        "duration_ms": _ms(r.duration),
    }
    return ev


def summary_line(ev: dict) -> str:
    """The human message that goes with the event (what text-format logs show)."""
    parts = [
        f"[{ev['target']}]",
        "policy ok" if ev["policy_ok"] else f"policy FAIL ({ev['policy_error']})",
        f"probes {ev['probes_ok']}/{ev['probes_total']}",
        f"keyservers {ev['keyservers_up']}/{ev['keyservers_total']}",
    ]
    if ev["integrity_ok"] is False:
        parts.append("INTEGRITY FAIL " + ",".join(ev["integrity_failed"]))
    if ev["tls_min_days"] is not None:
        parts.append(f"tls {ev['tls_min_days']}d")
    parts.append(f"{ev['duration_ms']}ms")
    return " ".join(parts)
