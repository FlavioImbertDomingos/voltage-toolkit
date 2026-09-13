"""Prometheus metrics. A background thread runs the probes every `interval` seconds
and updates these; `/metrics` just serves the current state.

Why a background loop instead of probe-on-scrape: tokenize probes hit a production
tokenization service. Their rate should be a deliberate, configured number, not
"however often Prometheus (or a curious engineer) hits /metrics".
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from prometheus_client import Counter, Gauge, Histogram, Info

from . import __version__
from .config import Config
from .coverage import STATES, CoverageReport
from .fleet import FleetCheck
from .fleet import evaluate as evaluate_fleet
from .lifecycle import split_version, support_end
from .policy import MIN_FPE_DOMAIN, format_domain_size, is_efpe
from .probes import TargetResult, run_target
from .sdm import JobResult, MaskResult

log = logging.getLogger(__name__)
NS = "voltage"

BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)

build_info = Info(f"{NS}_exporter_build", "voltage-exporter build info")
build_info.info({"version": __version__})

# ---- policy
policy_up = Gauge(f"{NS}_policy_up", "1 if clientPolicy.xml was downloaded and parsed", ["target"])
policy_latency = Gauge(f"{NS}_policy_fetch_seconds", "Time to download clientPolicy.xml", ["target"])
policy_info = Gauge(
    f"{NS}_policy_info", "Policy facts (always 1)", ["target", "district", "version", "policy_id", "sha256"]
)
policy_formats = Gauge(f"{NS}_policy_formats", "Formats offered by the policy", ["target", "kind"])
policy_format = Gauge(f"{NS}_policy_format", "One series per format (always 1)", ["target", "format", "kind"])
policy_auth_method = Gauge(f"{NS}_policy_auth_method", "Auth methods offered (always 1)", ["target", "method"])
policy_changes = Counter(f"{NS}_policy_changes", "Times the policy hash changed since start", ["target"])
policy_last_change = Gauge(f"{NS}_policy_last_change_timestamp_seconds", "When the policy last changed", ["target"])

# ---- policy: what the file says about the crypto (R1, R2, R5, R12)
key_table_current = Gauge(
    f"{NS}_key_table_current_number", "currentNumber of a keyNumberTable (increments on rotation)", ["target", "table"]
)
key_table_versions = Gauge(f"{NS}_key_table_versions", "Key versions listed in a keyNumberTable", ["target", "table"])
key_info = Gauge(
    f"{NS}_key_info", "One series per key version (always 1)", ["target", "table", "number", "algorithm", "key_size"]
)
key_current_size = Gauge(
    f"{NS}_key_current_size_bits", "Key size of the *current* key in the table (0 if unknown)", ["target", "table"]
)
key_rotations = Counter(f"{NS}_key_rotations", "Times currentNumber changed since exporter start", ["target", "table"])
format_domain = Gauge(
    f"{NS}_format_domain_size",
    "Estimated FPE domain size (radix ** encrypted positions) where the policy says enough to compute it",
    ["target", "format"],
)
format_below_min = Gauge(
    f"{NS}_format_below_minimum_domain",
    f"1 if the format's domain is under NIST SP 800-38G Rev. 1's {MIN_FPE_DOMAIN:,} floor",
    ["target", "format"],
)
format_efpe = Gauge(
    f"{NS}_policy_format_efpe",
    "1 for embedded-FPE formats: ciphertext differs per key epoch, equality joins are unsafe",
    ["target", "format"],
)
appliance_version = Gauge(
    f"{NS}_appliance_version_info",
    "Appliance version from the policy (always 1)",
    ["target", "version", "major", "minor"],
)
support_end_ts = Gauge(
    f"{NS}_support_end_timestamp_seconds",
    "End of vendor maintenance for the running appliance version (only when known)",
    ["target", "version", "release"],
)

# ---- tokenize
probe_success = Gauge(f"{NS}_tokenize_success", "1 if the last protect+access round-trip succeeded",
                      ["target", "format", "identity"])  # fmt: skip
probe_total = Counter(f"{NS}_tokenize_probes", "Round-trip probes run", ["target", "format", "result"])
probe_errors = Counter(f"{NS}_tokenize_errors", "Failed probes by kind", ["target", "format", "kind"])
protect_hist = Histogram(f"{NS}_protect_seconds", "protect (tokenize) latency", ["target", "format"], buckets=BUCKETS)
access_hist = Histogram(f"{NS}_access_seconds", "access (detokenize) latency", ["target", "format"], buckets=BUCKETS)
protect_last = Gauge(f"{NS}_protect_last_seconds", "Last protect latency", ["target", "format"])
access_last = Gauge(f"{NS}_access_last_seconds", "Last access latency", ["target", "format"])
roundtrip_ok = Gauge(f"{NS}_tokenize_roundtrip_ok", "1 if access(protect(x)) == x", ["target", "format"])
format_preserved = Gauge(
    f"{NS}_tokenize_format_preserved", "1 if the token kept the sample's shape", ["target", "format"]
)

# ---- integrity: the failures that produce no error (R3)
integrity_ok = Gauge(
    f"{NS}_integrity_ok",
    "1 if the silent-corruption check passed (check = determinism | double_protect | format_isolation)",
    ["target", "check", "format", "against"],
)
integrity_total = Counter(
    f"{NS}_integrity_checks", "Integrity checks run", ["target", "check", "result"]
)  # result = pass | fail | error

# ---- fleet agreement (R4, R15): several vantage points must give the same answers
fleet_ok = Gauge(
    f"{NS}_fleet_agreement",
    "1 if every member of the fleet agrees (check = policy | version | key_table | token; key = table or format)",
    ["fleet", "check", "key"],
)
fleet_members = Gauge(f"{NS}_fleet_members", "Members that reported for the check", ["fleet", "check", "key"])
fleet_odd = Gauge(
    f"{NS}_fleet_member_diverged",
    "1 if this target disagrees with the fleet majority for the check",
    ["fleet", "check", "key", "target"],
)

# ---- coverage (R6, R7): classified sensitive columns x data map x live policy
coverage_columns = Gauge(
    f"{NS}_coverage_columns",
    "Classified sensitive columns by state (protected | unmapped | broken | unknown)",
    ["state", "classification"],
)
coverage_column_info = Gauge(
    f"{NS}_coverage_column_info",
    "One series per column that is NOT protected (capped by coverage.max_named_columns)",
    ["state", "system", "schema", "table", "column", "classification", "reason"],
)
coverage_dead_format = Gauge(
    f"{NS}_coverage_dead_format",
    "1 for a format the policy offers that no column and no identity uses",
    ["district", "format"],
)
coverage_feed_rows = Gauge(f"{NS}_coverage_feed_rows", "Rows in the classification feed")
coverage_map_entries = Gauge(f"{NS}_coverage_map_entries", "Entries in the data map")
coverage_unclassified_mappings = Gauge(
    f"{NS}_coverage_unclassified_mappings", "Data-map entries the classification feed never mentioned"
)
coverage_feed_mtime = Gauge(f"{NS}_coverage_feed_mtime_seconds", "Modification time of the classification feed")
coverage_errors = Gauge(f"{NS}_coverage_errors", "Parse/consistency errors in the feed or data map")
coverage_ok = Gauge(f"{NS}_coverage_up", "1 if the feed and data map were read and evaluated")

# ---- SDM: masking quality (R8) and batch jobs (R9)
sdm_mask_ok = Gauge(
    f"{NS}_sdm_mask_ok", "1 if the masking check passed (kind = leak | consistency | constant)", ["check", "kind"]
)
sdm_mask_rows = Gauge(f"{NS}_sdm_mask_rows", "Rows the masking check examined", ["check", "kind"])
sdm_mask_hits = Gauge(
    f"{NS}_sdm_mask_hits",
    "leak: canary / looks-live matches; consistency: inconsistently masked keys; constant: 1 if all identical",
    ["check", "kind"],
)
sdm_check_up = Gauge(f"{NS}_sdm_check_up", "1 if the check's source could be read and evaluated", ["check", "kind"])
sdm_job_last_success = Gauge(
    f"{NS}_sdm_job_last_success_timestamp_seconds", "Last successful finish of the job", ["check", "job"]
)
sdm_job_last_finished = Gauge(
    f"{NS}_sdm_job_last_finished_timestamp_seconds", "Most recent finish, any status", ["check", "job"]
)
sdm_job_status = Gauge(f"{NS}_sdm_job_last_status", "Most recent status (always 1)", ["check", "job", "status"])
sdm_job_rows = Gauge(f"{NS}_sdm_job_last_rows", "Rows processed by the most recent run", ["check", "job"])
sdm_job_stale = Gauge(f"{NS}_sdm_job_stale", "1 if the job has not succeeded within expect_every", ["check", "job"])
sdm_job_failing = Gauge(f"{NS}_sdm_job_failing", "1 if the job's most recent run failed", ["check", "job"])

# ---- tls / key servers
cert_expiry = Gauge(f"{NS}_certificate_expiry_timestamp_seconds", "Certificate notAfter", ["target", "host", "subject"])
cert_ok = Gauge(f"{NS}_tls_up", "1 if a TLS handshake with the host succeeded", ["target", "host"])
tls_version = Gauge(f"{NS}_tls_version_info", "Negotiated TLS version (always 1)", ["target", "host", "version"])
keyserver_up = Gauge(f"{NS}_keyserver_up", "1 if the key server URL answered", ["target", "url"])

# ---- exporter
scrape_duration = Gauge(f"{NS}_probe_cycle_seconds", "Time the last full probe cycle took", ["target"])
last_run = Gauge(f"{NS}_probe_last_run_timestamp_seconds", "When the target was last probed", ["target"])
cycles = Counter(f"{NS}_probe_cycles", "Completed probe cycles")

_last_hash: dict[str, str] = {}
_last_current: dict[tuple[str, str], int] = {}
_support_overrides: dict = {}


def configure(config: Config) -> None:
    """Things `apply()` needs from the config (called once from the loop / --once)."""
    _support_overrides.clear()
    _support_overrides.update(config.support_end)


def _apply_policy_crypto(t: str, p) -> None:  # noqa: ANN001 - PolicyInfo
    # key number tables -> rotation observability
    for table in p.key_tables:
        key_rotations.labels(t, table.name)  # exist at 0 so increase() works from the first scrape
        key_table_versions.labels(t, table.name).set(float(len(table.keys)))
        if table.current_number is not None:
            key_table_current.labels(t, table.name).set(float(table.current_number))
            prev = _last_current.get((t, table.name))
            if prev is not None and prev != table.current_number:
                key_rotations.labels(t, table.name).inc()
                log.warning("[%s] key table %s rotated: %s -> %s", t, table.name, prev, table.current_number)
            _last_current[(t, table.name)] = table.current_number
        for k in table.keys:
            key_info.labels(t, table.name, str(k["number"]), k["algorithm"], str(k["key_size"] or "")).set(1.0)
        cur = table.current
        key_current_size.labels(t, table.name).set(float((cur or {}).get("key_size") or 0))
    # formats -> domain size and eFPE
    for f in p.formats:
        n = format_domain_size(f)
        if n is not None:
            format_domain.labels(t, f["name"]).set(float(n))
            format_below_min.labels(t, f["name"]).set(1.0 if n < MIN_FPE_DOMAIN else 0.0)
        if is_efpe(f):
            format_efpe.labels(t, f["name"]).set(1.0)
    # appliance version -> lifecycle
    if p.server_version:
        major, minor = split_version(p.server_version)
        appliance_version.labels(t, p.server_version, major, minor).set(1.0)
        se = support_end(p.server_version, _support_overrides)
        if se:
            release, ts = se
            support_end_ts.labels(t, p.server_version, release).set(ts)


def apply(result: TargetResult) -> None:
    t = result.target.name
    policy_changes.labels(t)  # make the series exist at 0 so increase() works from the first scrape
    policy_up.labels(t).set(1.0 if result.policy_ok else 0.0)
    if result.policy_seconds is not None:
        policy_latency.labels(t).set(result.policy_seconds)
    if result.policy:
        p = result.policy
        policy_info.labels(t, p.district, p.version, p.policy_id, p.sha256[:12]).set(1.0)
        kinds: dict[str, int] = {}
        for f in p.formats:
            kinds[f["kind"]] = kinds.get(f["kind"], 0) + 1
            policy_format.labels(t, f["name"], f["kind"]).set(1.0)
        for k, n in kinds.items():
            policy_formats.labels(t, k).set(float(n))
        for m in p.auth_methods:
            policy_auth_method.labels(t, m).set(1.0)
        _apply_policy_crypto(t, p)
        prev = _last_hash.get(t)
        if prev is not None and prev != p.sha256:
            policy_changes.labels(t).inc()
            policy_last_change.labels(t).set(time.time())
            log.warning("[%s] policy changed: %s -> %s", t, prev[:12], p.sha256[:12])
        _last_hash[t] = p.sha256

    for r in result.tokenize:
        f = r.spec.format
        ident = r.spec.identity or result.target.identity
        probe_success.labels(t, f, ident).set(1.0 if r.ok else 0.0)
        probe_total.labels(t, f, "success" if r.ok else "failure").inc()
        if not r.ok:
            probe_errors.labels(t, f, r.error_kind or "other").inc()
        if r.protect_seconds is not None:
            protect_hist.labels(t, f).observe(r.protect_seconds)
            protect_last.labels(t, f).set(r.protect_seconds)
        if r.access_seconds is not None:
            access_hist.labels(t, f).observe(r.access_seconds)
            access_last.labels(t, f).set(r.access_seconds)
        if r.roundtrip_ok is not None:
            roundtrip_ok.labels(t, f).set(1.0 if r.roundtrip_ok else 0.0)
        if r.format_preserved is not None:
            format_preserved.labels(t, f).set(1.0 if r.format_preserved else 0.0)

    for r in result.integrity:
        if r.ok is None:
            integrity_total.labels(t, r.check, "error").inc()
            continue
        integrity_ok.labels(t, r.check, r.format, r.against).set(1.0 if r.ok else 0.0)
        integrity_total.labels(t, r.check, "pass" if r.ok else "fail").inc()

    for c in result.tls:
        host = f"{c.host}:{c.port}"
        cert_ok.labels(t, host).set(1.0 if c.ok else 0.0)
        if c.ok and c.not_after is not None:
            cert_expiry.labels(t, host, c.subject).set(c.not_after)
            tls_version.labels(t, host, c.tls_version).set(1.0)

    for url, up in result.keyservers.items():
        keyserver_up.labels(t, url).set(1.0 if up else 0.0)

    scrape_duration.labels(t).set(result.duration)
    last_run.labels(t).set(time.time())


def apply_fleet(checks: list[FleetCheck], all_targets: list[str] | None = None) -> None:
    for c in checks:
        fleet_members.labels(c.fleet, c.check, c.key).set(float(c.members))
        if c.ok is None:
            continue
        fleet_ok.labels(c.fleet, c.check, c.key).set(1.0 if c.ok else 0.0)
        for t in all_targets or []:
            fleet_odd.labels(c.fleet, c.check, c.key, t).set(1.0 if t in c.odd_ones else 0.0)
        for t in c.odd_ones:
            fleet_odd.labels(c.fleet, c.check, c.key, t).set(1.0)
        if not c.ok:
            log.error("[fleet %s] %s %s: %s", c.fleet, c.check, c.key or "", c.detail)


def apply_coverage(report: CoverageReport | None, feed_mtime: float | None, max_named: int = 50) -> None:
    coverage_column_info.clear()
    coverage_dead_format.clear()
    if report is None:
        coverage_ok.set(0.0)
        return
    coverage_ok.set(1.0)
    coverage_feed_rows.set(float(report.feed_rows))
    coverage_map_entries.set(float(report.map_entries))
    coverage_unclassified_mappings.set(float(len(report.unclassified_mappings)))
    coverage_errors.set(float(len(report.errors)))
    if feed_mtime is not None:
        coverage_feed_mtime.set(feed_mtime)
    coverage_columns.clear()
    classes = {c.row.classification or "unclassified" for c in report.columns} or {"unclassified"}
    for st in STATES:  # every (state, class) exists at 0 so absence reads as 0, not "no data"
        for cl in classes:
            coverage_columns.labels(st, cl).set(0.0)
    for (st, cl), n in report.counts().items():
        coverage_columns.labels(st, cl).set(float(n))
    named = 0
    for c in report.columns:
        if c.state == "protected":
            continue
        if named >= max_named:
            break
        named += 1
        r = c.row
        coverage_column_info.labels(c.state, r.system, r.schema, r.table, r.column, r.classification, c.reason).set(1.0)
    for district, fmts in report.dead_formats.items():
        for f in fmts:
            coverage_dead_format.labels(district, f).set(1.0)
    for e in report.errors:
        log.warning("coverage: %s", e)


def apply_sdm(masks: list[MaskResult], jobs: list[JobResult]) -> None:
    for m in masks:
        c, k = m.check.name, m.check.kind
        sdm_check_up.labels(c, k).set(0.0 if m.ok is None else 1.0)
        if m.ok is None:
            log.warning("[sdm %s] %s: %s", c, k, m.detail)
            continue
        sdm_mask_ok.labels(c, k).set(1.0 if m.ok else 0.0)
        sdm_mask_rows.labels(c, k).set(float(m.rows))
        sdm_mask_hits.labels(c, k).set(float(m.hits))
        if not m.ok:
            log.error("[sdm %s] MASKING %s: %s", c, k, m.detail)
    for j in jobs:
        c = j.check.name
        sdm_check_up.labels(c, "jobs").set(0.0 if j.ok is None else 1.0)
        if j.ok is None:
            log.warning("[sdm %s] jobs: %s", c, j.detail)
            continue
        sdm_job_status.clear()
        for js in j.jobs:
            if js.finished_at is not None:
                sdm_job_last_finished.labels(c, js.job).set(js.finished_at)
            if js.job in j.last_success:
                sdm_job_last_success.labels(c, js.job).set(j.last_success[js.job])
            sdm_job_status.labels(c, js.job, js.status).set(1.0)
            if js.rows is not None:
                sdm_job_rows.labels(c, js.job).set(js.rows)
            sdm_job_stale.labels(c, js.job).set(1.0 if js.job in j.stale else 0.0)
            sdm_job_failing.labels(c, js.job).set(1.0 if js.job in j.failing else 0.0)
        if not j.ok:
            log.error("[sdm %s] JOBS: %s", c, j.detail)


def probe_loop(config: Config, stop: threading.Event) -> None:
    configure(config)
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(config.targets)))) as pool:
        while not stop.is_set():
            started = time.perf_counter()
            results = list(pool.map(run_target, config.targets))
            for res in results:
                apply(res)
            apply_fleet(evaluate_fleet(results), [t.name for t in config.targets if t.fleet])
            if config.coverage:
                from .coverage_runner import run_coverage

                rep, mtime = run_coverage(config.coverage, results)
                apply_coverage(rep, mtime, config.coverage.max_named_columns)
            if config.sdm:
                from .sdm import parse_config, run_job_check, run_mask_check

                sc = parse_config(config.sdm)
                apply_sdm([run_mask_check(m) for m in sc.masking], [run_job_check(j) for j in sc.jobs])
            cycles.inc()
            elapsed = time.perf_counter() - started
            log.info("probe cycle done in %.2fs (%d target(s))", elapsed, len(config.targets))
            stop.wait(max(1.0, config.interval - elapsed))
