"""Restore-drill freshness: was the identity / master-secret backup restored *and tested* recently?  (R11)

Stateless key management means the district master secret, anchored in an HSM, is the whole
root of trust. There is no per-key revocation and no token vault to rebuild from: lose the
identity backup, or restore it wrong, and every token ever issued is unrecoverable. The
community wiki holds two public restore defects from the same week of November 2024. Nothing
in the product tracks whether anyone has ever proved the backup restores.

This module turns that drill into a metric. The evidence is whatever the drill leaves behind,
read through the same read-only source adapter as everything else:

    restore_drills:
      - name: prod-identity-backup
        district: prod
        max_age: 90d                       # how often the drill must succeed
        source: {type: file, path: /evidence/restore-drills.csv}
        columns: [drill, finished_at, result, operator]
      - name: dr-identity-backup
        district: dr
        max_age: 90d
        source: {type: sql, dsn: postgresql://.../ops}
        query: SELECT drill, finished_at, result, operator FROM restore_drills

Rows: (drill, finished_at, result[, operator]); `result` is SUCCESS / PASS / OK (case-insensitive)
or anything else = failed. Per drill: last success timestamp, last attempt result, overdue.

The drill itself -- restore the identity backup into an isolated appliance, protect a known
value, compare the token to production's -- is documented in docs/ROOT-OF-TRUST.md. The
exporter only asks whether it happened.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from .sdm import _duration, _ts
from .sources import Source, SourceError, query_rows

SUCCESS_WORDS = {"success", "succeeded", "pass", "passed", "ok", "true", "1"}


@dataclass
class RestoreDrill:
    name: str
    district: str
    max_age_seconds: float
    source: Source
    query: str = ""
    columns: list[str] = field(default_factory=lambda: ["drill", "finished_at", "result"])
    match: str = ""  # value of the `drill` column to select; "" = this drill's name


@dataclass
class DrillResult:
    drill: RestoreDrill
    ok: bool | None = None  # None: evidence unreadable
    detail: str = ""
    last_success: float | None = None
    last_attempt: float | None = None
    last_result: str = ""
    attempts: int = 0
    overdue: bool = False
    never_tested: bool = False
    last_failed: bool = False


def parse_config(items: list | None) -> list[RestoreDrill]:
    out: list[RestoreDrill] = []
    for i, d in enumerate(items or []):
        if not isinstance(d, dict) or not d.get("name"):
            raise SourceError(f"restore_drills[{i}]: needs a name")
        src = Source.from_config(d.get("source") or {})
        if src.type == "sql" and not d.get("query"):
            raise SourceError(f"restore_drills[{d['name']}]: sql source needs 'query'")
        cols = d.get("columns") or ["drill", "finished_at", "result"]
        if not isinstance(cols, list) or len(cols) < 3:
            raise SourceError(f"restore_drills[{d['name']}]: columns needs [drill, finished_at, result]")
        out.append(
            RestoreDrill(
                name=str(d["name"]),
                district=str(d.get("district") or ""),
                max_age_seconds=_duration(d.get("max_age"), 90 * 86400.0),
                source=src,
                query=str(d.get("query") or ""),
                columns=[str(c) for c in cols],
                match=str(d.get("match") or ""),
            )
        )
    return out


def evaluate(drill: RestoreDrill, rows: list[tuple], now: float) -> DrillResult:
    res = DrillResult(drill=drill)
    want = (drill.match or drill.name).lower()
    for r in rows:
        if len(r) < 3 or str(r[0] or "").strip().lower() != want:
            continue
        ts = _ts(r[1])
        if ts is None:
            continue
        result = str(r[2] or "").strip()
        res.attempts += 1
        if res.last_attempt is None or ts > res.last_attempt:
            res.last_attempt, res.last_result = ts, result
        if result.lower() in SUCCESS_WORDS and (res.last_success is None or ts > res.last_success):
            res.last_success = ts
    res.never_tested = res.last_success is None
    res.overdue = res.never_tested or (now - res.last_success) > drill.max_age_seconds
    res.last_failed = bool(res.last_attempt) and res.last_result.lower() not in SUCCESS_WORDS
    res.ok = not (res.overdue or res.last_failed)
    if res.never_tested:
        res.detail = "no successful restore drill on record"
    else:
        days = (now - res.last_success) / 86400
        res.detail = f"last successful drill {days:.0f} days ago (limit {drill.max_age_seconds / 86400:.0f})"
        if res.last_failed:
            res.detail += f"; most recent attempt {res.last_result!r}"
    return res


def run(drill: RestoreDrill, now: float | None = None) -> DrillResult:
    now = now if now is not None else _dt.datetime.now(_dt.UTC).timestamp()
    try:
        rows = query_rows(drill.source, drill.query, drill.columns)
    except SourceError as exc:
        return DrillResult(drill=drill, ok=None, detail=f"{drill.source.describe()}: {exc}")
    return evaluate(drill, rows, now)
