"""Structured Data Manager checks: masking quality (R8) and batch-job health (R9).

SDM has no public API. What it *does* leave behind is data -- masked rows in a non-production
database or export, and a job history somewhere (its repository, a log table, a CSV the job
runner drops). These checks read those, through `sources.py` (SQL via any DB-API driver, or
CSV), and answer the two questions that matter:

  Masking (R8)
    leak         Do masked values still look live? Two methods, both explicit:
                 * canaries  -- values you planted in production (synthetic but unique) that
                                must never appear in the masked copy. Deterministic, the real
                                test. Given inline or as a file, compared by exact match or
                                by SHA-256 so the canaries need not live in config.
                 * heuristic -- "looks like a real PAN / SSN" (Luhn, ranges). OFF by default,
                                and documented as such: FPE with checksum preservation
                                produces Luhn-valid tokens *by design*, so on FPE-masked data
                                this heuristic flags everything and proves nothing.
    consistency  Referential integrity: the same source key must mask to the same value in
                 every table it appears in. Rows are (key, value_a, value_b); a mismatch means
                 joins on the masked column silently drop rows in the test environment.
    constant     A masked column where every value is identical (a fill-with-X job that
                 "worked"). Cheap, catches a surprisingly common failure.

  Jobs (R9)
    Rows are (job_name, status, finished_at, rows) from wherever job history lives. Emits last
    success time, last status, rows, and flags jobs that have not succeeded within `expect_every`.

Everything is read-only: one SELECT or one file per check, and nothing sensitive is ever
kept -- leak matches are counted, never printed.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from dataclasses import dataclass, field

from .sources import Source, SourceError, query_rows


# --------------------------------------------------------------------------- config
@dataclass
class MaskCheck:
    name: str
    kind: str  # leak | consistency | constant
    source: Source
    query: str = ""
    columns: list[str] = field(default_factory=list)  # file sources
    classification: str = ""  # PAN | SSN | "" (for the heuristic)
    canaries: list[str] = field(default_factory=list)
    canary_file: str = ""
    canaries_hashed: bool = False  # canary list holds sha256 hex digests, not values
    heuristic: bool = False
    min_rows: int = 1


@dataclass
class JobCheck:
    name: str
    source: Source
    query: str = ""
    columns: list[str] = field(default_factory=list)
    expect_every_seconds: float = 86400.0


@dataclass
class SdmConfig:
    masking: list[MaskCheck] = field(default_factory=list)
    jobs: list[JobCheck] = field(default_factory=list)


def _duration(v: object, default: float) -> float:
    """'24h', '90m', '7d', or a number of seconds."""
    if v is None:
        return default
    s = str(v).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s and s[-1] in units and s[:-1].replace(".", "", 1).isdigit():
        return float(s[:-1]) * units[s[-1]]
    return float(s)


def parse_config(doc: dict | None) -> SdmConfig:
    cfg = SdmConfig()
    if not doc:
        return cfg
    for i, m in enumerate(doc.get("masking") or []):
        if not isinstance(m, dict) or not m.get("name"):
            raise SourceError(f"sdm.masking[{i}] needs a name")
        kind = str(m.get("kind") or "leak").lower()
        if kind not in ("leak", "consistency", "constant"):
            raise SourceError(f"sdm.masking[{i}] ({m['name']}): unknown kind {kind!r}")
        src = Source.from_config(m.get("source") or {})
        cans = m.get("canaries") or []
        if isinstance(cans, str):
            cans = [cans]
        cfg.masking.append(
            MaskCheck(
                name=str(m["name"]),
                kind=kind,
                source=src,
                query=str(m.get("query") or ""),
                columns=[str(c) for c in (m.get("columns") or [])],
                classification=str(m.get("classification") or "").upper(),
                canaries=[str(c) for c in cans],
                canary_file=str(m.get("canary_file") or ""),
                canaries_hashed=bool(m.get("canaries_hashed", False)),
                heuristic=bool(m.get("heuristic", False)),
                min_rows=int(m.get("min_rows", 1)),
            )
        )
    for i, j in enumerate(doc.get("jobs") or []):
        if not isinstance(j, dict) or not j.get("name"):
            raise SourceError(f"sdm.jobs[{i}] needs a name")
        cfg.jobs.append(
            JobCheck(
                name=str(j["name"]),
                source=Source.from_config(j.get("source") or {}),
                query=str(j.get("query") or ""),
                columns=[str(c) for c in (j.get("columns") or [])],
                expect_every_seconds=_duration(j.get("expect_every"), 86400.0),
            )
        )
    return cfg


# --------------------------------------------------------------------------- results
@dataclass
class MaskResult:
    check: MaskCheck
    ok: bool | None = None  # None: could not evaluate
    rows: int = 0
    hits: int = 0  # leak: canary/heuristic matches; consistency: inconsistent keys; constant: 1 if constant
    detail: str = ""


@dataclass
class JobStatus:
    job: str
    status: str
    finished_at: float | None
    rows: float | None


@dataclass
class JobResult:
    check: JobCheck
    ok: bool | None = None
    jobs: list[JobStatus] = field(default_factory=list)  # latest row per job name
    last_success: dict[str, float] = field(default_factory=dict)  # job -> last successful finish
    stale: list[str] = field(default_factory=list)
    failing: list[str] = field(default_factory=list)
    detail: str = ""


# --------------------------------------------------------------------------- heuristics
_TEST_PANS = {
    "4111111111111111",
    "4242424242424242",
    "4012888888881881",
    "5500000000000004",
    "5555555555554444",
    "5105105105105100",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "3530111333300000",
}


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def looks_live(value: object, classification: str) -> bool:
    """A value that would pass as real to a naive eye. Deliberately narrow."""
    s = re.sub(r"[\s-]", "", str(value or ""))
    if classification == "PAN":
        return s.isdigit() and 13 <= len(s) <= 19 and luhn_ok(s) and s not in _TEST_PANS
    if classification == "SSN":
        if not (s.isdigit() and len(s) == 9):
            return False
        area, group, serial = s[:3], s[3:5], s[5:]
        return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"
    return False


def _load_canaries(check: MaskCheck) -> tuple[set[str], list[str]]:
    """Canaries as a set of comparable strings (sha256 hex if hashed), plus errors."""
    vals = list(check.canaries)
    errors: list[str] = []
    if check.canary_file:
        try:
            with open(check.canary_file, encoding="utf-8") as fh:
                vals += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            errors.append(f"canary_file: {exc}")
    if check.canaries_hashed:
        return {v.lower() for v in vals}, errors
    return {hashlib.sha256(_norm_val(v).encode()).hexdigest() for v in vals}, errors


def _norm_val(v: object) -> str:
    return re.sub(r"[\s-]", "", str(v or ""))


# --------------------------------------------------------------------------- masking
def run_mask_check(check: MaskCheck) -> MaskResult:
    res = MaskResult(check=check)
    try:
        rows = query_rows(check.source, check.query, check.columns)
    except SourceError as exc:
        res.detail = str(exc)
        return res
    res.rows = len(rows)
    if res.rows < check.min_rows:
        res.detail = f"{res.rows} row(s), fewer than min_rows={check.min_rows}"
        return res

    if check.kind == "leak":
        canaries, errs = _load_canaries(check)
        if not canaries and not check.heuristic:
            res.detail = "leak check needs canaries, canary_file, or heuristic: true"
            return res
        hits = 0
        for r in rows:
            v = r[0] if r else None
            if canaries and hashlib.sha256(_norm_val(v).encode()).hexdigest() in canaries:
                hits += 1
            elif check.heuristic and looks_live(v, check.classification):
                hits += 1
        res.hits = hits
        res.ok = hits == 0
        if errs:
            res.detail = "; ".join(errs)
        elif hits:
            res.detail = f"{hits} of {res.rows} masked value(s) match a canary or look live"
        return res

    if check.kind == "consistency":
        seen: dict[str, str] = {}
        bad: set[str] = set()
        for r in rows:
            if len(r) < 2:
                res.detail = "consistency rows need (key, value_a[, value_b])"
                return res
            key = str(r[0])
            vals = [str(x) for x in r[1:]]
            for v in vals:
                prev = seen.setdefault(key, v)
                if prev != v:
                    bad.add(key)
        res.hits = len(bad)
        res.ok = not bad
        if bad:
            res.detail = f"{len(bad)} key(s) mask to different values across tables"
        return res

    # constant
    distinct = {str(r[0]) for r in rows if r}
    res.hits = 1 if len(distinct) <= 1 else 0
    res.ok = len(distinct) > 1
    if not res.ok:
        res.detail = f"all {res.rows} masked value(s) are identical"
    return res


# --------------------------------------------------------------------------- jobs
def _ts(v: object) -> float | None:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, _dt.datetime):
        return v.timestamp() if v.tzinfo else v.replace(tzinfo=_dt.UTC).timestamp()
    s = str(v).strip()
    try:
        return float(s)
    except ValueError:
        pass
    try:
        d = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d.timestamp() if d.tzinfo else d.replace(tzinfo=_dt.UTC).timestamp()
    except ValueError:
        return None


def run_job_check(check: JobCheck, now: float | None = None) -> JobResult:
    res = JobResult(check=check)
    now = now if now is not None else _dt.datetime.now(_dt.UTC).timestamp()
    try:
        rows = query_rows(check.source, check.query, check.columns)
    except SourceError as exc:
        res.detail = str(exc)
        return res
    latest: dict[str, JobStatus] = {}
    last_success: dict[str, float] = {}
    for r in rows:
        if len(r) < 3:
            res.detail = "job rows need (job_name, status, finished_at[, rows])"
            return res
        job, status = str(r[0]), str(r[1]).lower()
        finished = _ts(r[2])
        nrows = None
        if len(r) > 3 and r[3] not in (None, ""):
            try:
                nrows = float(r[3])
            except (TypeError, ValueError):
                nrows = None
        js = JobStatus(job, status, finished, nrows)
        cur = latest.get(job)
        if cur is None or (finished or 0) >= (cur.finished_at or 0):
            latest[job] = js
        if status in ("success", "succeeded", "ok", "completed", "complete", "done") and finished is not None:
            last_success[job] = max(last_success.get(job, 0.0), finished)
    res.jobs = sorted(latest.values(), key=lambda j: j.job)
    res.last_success = last_success
    for js in res.jobs:
        ok_at = last_success.get(js.job)
        if ok_at is None or now - ok_at > check.expect_every_seconds:
            res.stale.append(js.job)
        if js.status in ("failed", "failure", "error", "aborted", "cancelled", "canceled"):
            res.failing.append(js.job)
    res.ok = not res.stale and not res.failing
    if not res.ok:
        parts = []
        if res.stale:
            parts.append(f"stale: {', '.join(res.stale)}")
        if res.failing:
            parts.append(f"failing: {', '.join(res.failing)}")
        res.detail = "; ".join(parts)
    return res
