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
from .probes import TargetResult, run_target

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


def probe_loop(config: Config, stop: threading.Event) -> None:
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(config.targets)))) as pool:
        while not stop.is_set():
            started = time.perf_counter()
            for res in pool.map(run_target, config.targets):
                apply(res)
            cycles.inc()
            elapsed = time.perf_counter() - started
            log.info("probe cycle done in %.2fs (%d target(s))", elapsed, len(config.targets))
            stop.wait(max(1.0, config.interval - elapsed))
