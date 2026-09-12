"""The probes. Each returns plain data; metrics.py turns it into Prometheus series.

policy     GET clientPolicy.xml -> reachable, latency, parsed formats/auth/key servers, hash
tokenize   protect(sample) then access(token) -> latency of each, round-trip correctness,
           format preservation (same length, same character classes as the sample)
tls        certificate expiry of the policy host, the WS host, every key server, extra hosts
keyserver  HTTPS reachability of each key server URL from the policy
integrity  the failures that produce no error at all (roadmap R3):
             determinism      protect(x) == protect(x) -- referential integrity across tables
                              depends on it; skipped for eFPE formats, which legitimately differ
                              per key epoch
             double-protect   access(protect(protect(x))) == protect(x) -- protecting an
                              already-protected value must still be reversible, not garbage
             format-isolation access(protect_A(x)) under format B must not return x -- an
                              error is fine, a different value is fine, the plaintext is not

A tokenize probe uses a *synthetic* sample (a test PAN / SSN from config), never real
data, and the exporter never logs the protected value.
"""

from __future__ import annotations

import hashlib
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
    token_sha256: str = ""  # hash of the protected value, for cross-target equivalence; the value itself is never kept
    error: str = ""
    error_kind: str = ""  # auth | http | timeout | connection | mismatch | other


@dataclass
class IntegrityResult:
    check: str  # determinism | double_protect | format_isolation
    format: str
    against: str = ""  # format_isolation only: the format access was attempted under
    ok: bool | None = None  # None = could not evaluate (protect failed etc.)
    detail: str = ""


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
    integrity: list[IntegrityResult] = field(default_factory=list)
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
        res.token_sha256 = hashlib.sha256(token.encode()).hexdigest()
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


def _protect(client: VoltageClient, spec: ProbeSpec, value: str) -> str:
    return str(client.protect(spec.format, value, spec.identity).value)


def run_integrity(client: VoltageClient, target: Target, efpe_formats: set[str]) -> list[IntegrityResult]:
    """The silent ones. Every check here is a failure mode that returns HTTP 200 and plausible data."""
    out: list[IntegrityResult] = []
    fpe_specs = [s for s in target.probes if not s.tokenization]

    # 1. determinism: same plaintext, same identity, same format -> same ciphertext
    if target.integrity_determinism:
        for spec in fpe_specs:
            if spec.format in efpe_formats:
                log.debug("[%s] determinism: skipping eFPE format %s", target.name, spec.format)
                continue
            r = IntegrityResult("determinism", spec.format)
            try:
                a, b = _protect(client, spec, spec.sample), _protect(client, spec, spec.sample)
                r.ok = a == b
                if not r.ok:
                    r.detail = "protect(x) returned two different values for the same input"
            except Exception as exc:  # noqa: BLE001
                r.detail = f"{type(exc).__name__}: {exc}"
            out.append(r)

    # 2. double protect: protect(protect(x)) must be reversible back to protect(x)
    if target.integrity_double_protect:
        for spec in fpe_specs:
            r = IntegrityResult("double_protect", spec.format)
            try:
                once = _protect(client, spec, spec.sample)
                twice = _protect(client, spec, once)
                back = str(client.access(spec.format, twice, spec.identity).value)
                r.ok = back == once
                if not r.ok:
                    r.detail = "access(protect(protect(x))) != protect(x)"
            except Exception as exc:  # noqa: BLE001
                r.detail = f"{type(exc).__name__}: {exc}"
            out.append(r)

    # 3. format isolation: a token made under A, accessed under B, must not yield the plaintext
    if target.integrity_format_isolation:
        pairs = list(target.isolation_pairs)
        if not pairs and len(fpe_specs) >= 2:
            names = [s.format for s in fpe_specs]
            pairs = [(names[i], names[(i + 1) % len(names)]) for i in range(len(names))]
        by_name = {s.format: s for s in fpe_specs}
        for a, b in pairs:
            spec = by_name.get(a)
            r = IntegrityResult("format_isolation", a, against=b)
            if spec is None:
                r.detail = f"no probe configured for format {a!r}"
                out.append(r)
                continue
            try:
                token = _protect(client, spec, spec.sample)
                try:
                    leaked = str(client.access(b, token, spec.identity).value)
                except VoltageError:
                    leaked = None  # the appliance refused: that is isolation working
                r.ok = leaked != spec.sample
                if not r.ok:
                    r.detail = f"access under {b} returned the plaintext protected under {a}"
            except Exception as exc:  # noqa: BLE001
                r.detail = f"{type(exc).__name__}: {exc}"
            out.append(r)
    return out


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

    # 2b. integrity: the failures that return 200 and wrong data
    efpe = set(out.policy.efpe_formats) if out.policy else set()
    out.integrity = run_integrity(client, target, efpe)
    for r in out.integrity:
        if r.ok is False:
            where = f"{r.format}->{r.against}" if r.against else r.format
            log.error("[%s] INTEGRITY %s %s: %s", target.name, r.check, where, r.detail)

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
