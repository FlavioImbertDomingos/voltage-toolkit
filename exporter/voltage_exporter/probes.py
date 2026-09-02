"""The probes. Each returns plain data; metrics.py turns it into Prometheus series.

policy     GET clientPolicy.xml -> reachable, latency, parsed formats/auth/key servers, hash
tokenize   protect(sample) then access(token) -> latency of each, round-trip correctness,
           format preservation (same length, same character classes as the sample)
tls        certificate expiry of the policy host, the WS host, every key server, extra hosts
keyserver  HTTPS reachability of each key server URL from the policy

A tokenize probe uses a *synthetic* sample (a test PAN / SSN from config), never real
data, and the exporter never logs the protected value.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from .client import VoltageClient, VoltageError, host_port
from .config import ProbeSpec, Target
from .policy import PolicyInfo, parse_policy

log = logging.getLogger(__name__)


@dataclass
class TokenizeResult:
    spec: ProbeSpec
    ok: bool = False
    protect_seconds: float | None = None
    access_seconds: float | None = None
    roundtrip_ok: bool | None = None
    format_preserved: bool | None = None
    error: str = ""
    error_kind: str = ""  # auth | http | timeout | connection | mismatch | other


@dataclass
class TlsResult:
    host: str
    port: int
    ok: bool = False
    subject: str = ""
    not_after: float | None = None
    tls_version: str = ""
    error: str = ""


@dataclass
class TargetResult:
    target: Target
    policy_ok: bool = False
    policy_seconds: float | None = None
    policy: PolicyInfo | None = None
    policy_error: str = ""
    tokenize: list[TokenizeResult] = field(default_factory=list)
    tls: list[TlsResult] = field(default_factory=list)
    keyservers: dict[str, bool] = field(default_factory=dict)
    duration: float = 0.0


def _classify(exc: Exception) -> str:
    text = str(exc).lower()
    if "401" in text or "403" in text or "auth" in text:
        return "auth"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "connection" in text or "name or service" in text or "refused" in text:
        return "connection"
    if "http" in text:
        return "http"
    return "other"


def _same_shape(a: str, b: str) -> bool:
    """FPE promise: same length, digits stay digits, letters stay letters, punctuation stays put."""
    if len(a) != len(b):
        return False
    cls = lambda ch: "d" if ch.isdigit() else "a" if ch.isalpha() else ch  # noqa: E731
    return all(cls(x) == cls(y) for x, y in zip(a, b, strict=True))


def run_tokenize(client: VoltageClient, spec: ProbeSpec) -> TokenizeResult:
    res = TokenizeResult(spec=spec)
    try:
        p = client.protect(spec.format, spec.sample, spec.identity)
        res.protect_seconds = p.seconds
        token = str(p.value)
        if token == spec.sample:
            res.error, res.error_kind = "protect returned the input unchanged", "mismatch"
            return res
        res.format_preserved = _same_shape(spec.sample, token) if not spec.tokenization else len(token) > 0
        a = client.access(spec.format, token, spec.identity)
        res.access_seconds = a.seconds
        res.roundtrip_ok = str(a.value) == spec.sample
        if not res.roundtrip_ok:
            res.error, res.error_kind = "access did not return the original value", "mismatch"
            return res
        res.ok = True
    except VoltageError as exc:
        res.error, res.error_kind = str(exc), _classify(exc)
    except Exception as exc:  # noqa: BLE001 - network stack errors of every flavour
        res.error, res.error_kind = f"{type(exc).__name__}: {exc}", _classify(exc)
    return res


def run_tls(host: str, port: int, timeout: float) -> TlsResult:
    res = TlsResult(host=host, port=port)
    try:
        info = VoltageClient.certificate(host, port, timeout)
        res.ok = True
        res.subject = info["subject"]
        res.not_after = info["not_after"]
        res.tls_version = info["tls_version"] or ""
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"
    return res


def run_target(target: Target) -> TargetResult:
    started = time.perf_counter()
    out = TargetResult(target=target)
    client = VoltageClient(target)

    # 1. policy
    try:
        t = client.fetch_policy()
        out.policy_seconds = t.seconds
        out.policy = parse_policy(t.value)
        out.policy_ok = True
    except Exception as exc:  # noqa: BLE001
        out.policy_error = f"{type(exc).__name__}: {exc}"
        log.warning("[%s] policy: %s", target.name, out.policy_error)

    # 2. tokenize round-trips
    for spec in target.probes:
        r = run_tokenize(client, spec)
        if not r.ok:
            log.warning("[%s] tokenize %s: %s", target.name, spec.format, r.error)
        out.tokenize.append(r)

    # 3. TLS: policy host, WS host, key servers, extras (deduplicated)
    hosts: list[tuple[str, int]] = []
    for url in (
        [target.policy_url, target.ws_url] + (out.policy.key_servers if out.policy else []) + target.extra_tls_hosts
    ):
        if not url:
            continue
        hp = host_port(url)
        if hp[0] and hp not in hosts and (url.startswith("https") or "://" not in url):
            hosts.append(hp)
    for host, port in hosts:
        out.tls.append(run_tls(host, port, target.timeout))

    # 4. key servers reachable?
    if out.policy:
        for url in out.policy.key_servers:
            try:
                r = client.session.get(url, timeout=target.timeout, verify=target.verify_tls)
                out.keyservers[url] = r.status_code < 500
            except Exception:  # noqa: BLE001
                out.keyservers[url] = False

    out.duration = time.perf_counter() - started
    return out


_DIGITS = re.compile(r"\d")
