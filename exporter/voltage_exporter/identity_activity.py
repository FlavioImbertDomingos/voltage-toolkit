"""Identity activity: who is asking the appliance for keys, how often, and did that just change.  (R10a)

Bulk detokenization is the exfiltration pattern, and a crypto service is the one place that can
see it. But be precise about what it *can* see. The Simple API caches its derived key and runs
FPE locally, so a client can protect and access millions of values without talking to the
appliance at all. What the appliance does observe is the control-plane edge of every workload:
**authentication** (every identity must authenticate to obtain keys) and **key issuance**
(one request per identity, format and key epoch; more when caches expire or the client
restarts). docs/VISIBILITY.md says this plainly. This module watches exactly those events.

Input: an audit export, through the same read-only source adapter as the SDM checks -- SQL
(the Management Console's audit database or a syslog sink that landed in a table) or a CSV
export. Rows: timestamp, identity, event, and optionally a client (host / IP). Event names
are free text; the ones a policy engineer expects are `auth_ok`, `auth_fail`, `key_request`.

Per (identity, event) the module computes the count in the current window and a **baseline**:
the median of the same count over the previous N windows. A ratio well above 1 with enough
events is a step change -- a new batch job, a rotated secret being retried in a loop, or someone
pulling keys for every format at once. Identities that appear for the first time, or that are
active but not declared in the desired-state document, are surfaced on their own series.

Hashes and counts only. The exporter never sees, stores or logs a protected value.
"""

from __future__ import annotations

import datetime as _dt
import statistics
from dataclasses import dataclass, field

from .sdm import _duration, _ts
from .sources import Source, SourceError, query_rows

DEFAULT_EVENTS = ("auth_ok", "auth_fail", "key_request")


@dataclass
class IdentityActivityConfig:
    source: Source
    query: str = ""
    columns: list[str] = field(default_factory=lambda: ["ts", "identity", "event"])
    window_seconds: float = 3600.0
    baseline_windows: int = 24
    spike_ratio: float = 5.0
    min_events: int = 20
    auth_fail_threshold: int = 10
    events: list[str] = field(default_factory=lambda: list(DEFAULT_EVENTS))
    declared_identities: list[str] = field(default_factory=list)
    max_identities: int = 200


@dataclass
class IdentityWindow:
    identity: str
    event: str
    current: int = 0
    baseline: float | None = None  # median over previous windows; None = no history
    ratio: float | None = None  # current / baseline; inf when there is no history


@dataclass
class IdentityActivityReport:
    ok: bool | None = None  # None: source unreadable
    detail: str = ""
    windows: list[IdentityWindow] = field(default_factory=list)
    new_identities: list[str] = field(default_factory=list)  # active now, never seen in the baseline
    undeclared: list[str] = field(default_factory=list)  # active now, absent from declared_identities
    spikes: list[IdentityWindow] = field(default_factory=list)
    auth_failures: dict[str, int] = field(default_factory=dict)  # identity -> auth_fail count now
    rows: int = 0
    newest_ts: float | None = None
    identities: int = 0


def parse_config(doc: dict | None) -> IdentityActivityConfig | None:
    if not doc:
        return None
    if not isinstance(doc, dict):
        raise SourceError("identity_activity must be a mapping")
    src = Source.from_config(doc.get("source") or {})
    cols = doc.get("columns") or ["ts", "identity", "event"]
    if not isinstance(cols, list) or len(cols) < 3:
        raise SourceError("identity_activity.columns needs at least [ts, identity, event]")
    if src.type == "sql" and not doc.get("query"):
        raise SourceError("identity_activity needs 'query' for a sql source (SELECT ts, identity, event ...)")
    declared = doc.get("declared_identities") or []
    if isinstance(declared, str):
        declared = [declared]
    events = doc.get("events") or list(DEFAULT_EVENTS)
    return IdentityActivityConfig(
        source=src,
        query=str(doc.get("query") or ""),
        columns=[str(c) for c in cols],
        window_seconds=_duration(doc.get("window"), 3600.0),
        baseline_windows=max(1, int(doc.get("baseline_windows", 24))),
        spike_ratio=float(doc.get("spike_ratio", 5.0)),
        min_events=int(doc.get("min_events", 20)),
        auth_fail_threshold=int(doc.get("auth_fail_threshold", 10)),
        events=[str(e) for e in events],
        declared_identities=[str(d) for d in declared],
        max_identities=int(doc.get("max_identities", 200)),
    )


def evaluate(cfg: IdentityActivityConfig, rows: list[tuple], now: float) -> IdentityActivityReport:
    """Pure: rows are (ts, identity, event[, client]) tuples; timestamps ISO or epoch."""
    rep = IdentityActivityReport(rows=len(rows))
    w = cfg.window_seconds
    horizon = now - w * (cfg.baseline_windows + 1)
    wanted = {e.lower() for e in cfg.events} if cfg.events else None

    # bucket index 0 = current window, 1..N = previous windows
    counts: dict[tuple[str, str], dict[int, int]] = {}
    seen_before: set[str] = set()
    for r in rows:
        if len(r) < 3:
            continue
        ts = _ts(r[0])
        ident = str(r[1] or "").strip()
        event = str(r[2] or "").strip().lower()
        if ts is None or not ident or not event or ts < horizon or ts > now + 60:
            continue
        if wanted is not None and event not in wanted:
            continue
        bucket = int((now - ts) // w)
        if bucket > cfg.baseline_windows:
            continue
        counts.setdefault((ident, event), {})
        counts[(ident, event)][bucket] = counts[(ident, event)].get(bucket, 0) + 1
        if bucket >= 1:
            seen_before.add(ident)
        rep.newest_ts = ts if rep.newest_ts is None or ts > rep.newest_ts else rep.newest_ts

    active_now: dict[str, int] = {}
    for (ident, event), buckets in counts.items():
        cur = buckets.get(0, 0)
        history = [buckets.get(i, 0) for i in range(1, cfg.baseline_windows + 1)]
        baseline = statistics.median(history) if any(history) else None
        ratio = None
        if cur:
            ratio = (cur / baseline) if baseline else float("inf")
        iw = IdentityWindow(identity=ident, event=event, current=cur, baseline=baseline, ratio=ratio)
        rep.windows.append(iw)
        if cur:
            active_now[ident] = active_now.get(ident, 0) + cur
        if event == "auth_fail" and cur:
            rep.auth_failures[ident] = cur
        if cur >= cfg.min_events and (baseline is None or cur >= cfg.spike_ratio * max(baseline, 1.0)):
            rep.spikes.append(iw)

    # cap cardinality: keep the busiest identities now, then the busiest historically
    if len(active_now) > cfg.max_identities:
        keep = {i for i, _ in sorted(active_now.items(), key=lambda kv: -kv[1])[: cfg.max_identities]}
        rep.windows = [x for x in rep.windows if x.identity in keep]
        rep.spikes = [x for x in rep.spikes if x.identity in keep]
        active_now = {i: n for i, n in active_now.items() if i in keep}
    rep.identities = len(active_now)
    rep.new_identities = sorted(i for i in active_now if i not in seen_before)
    declared = {d.lower() for d in cfg.declared_identities}
    if declared:
        rep.undeclared = sorted(i for i in active_now if i.lower() not in declared)
    rep.ok = True
    bits = [f"{rep.identities} identities active in the last {int(w)}s"]
    if rep.spikes:
        bits.append(
            "spikes: " + ", ".join(f"{s.identity}/{s.event} {s.current} (baseline {s.baseline})" for s in rep.spikes)
        )
    if rep.new_identities:
        bits.append("new: " + ", ".join(rep.new_identities))
    if rep.undeclared:
        bits.append("undeclared: " + ", ".join(rep.undeclared))
    rep.detail = "; ".join(bits)
    return rep


def run(cfg: IdentityActivityConfig, now: float | None = None) -> IdentityActivityReport:
    now = now if now is not None else _dt.datetime.now(_dt.UTC).timestamp()
    try:
        rows = query_rows(cfg.source, cfg.query, cfg.columns)
    except SourceError as exc:
        return IdentityActivityReport(ok=None, detail=f"{cfg.source.describe()}: {exc}")
    return evaluate(cfg, rows, now)
