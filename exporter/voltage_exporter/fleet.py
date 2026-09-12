"""Fleet agreement: ask several vantage points the same question, alert when the answers differ.

Targets that share a `fleet` name are supposed to be the same district seen from different
places -- two appliances behind a load balancer, a primary and a DR region, the policy host
as seen from two data centres. The stateless design makes them *cheap* to keep identical,
which is exactly why nobody checks. Two things go wrong silently:

* **Policy propagation is lazy and per node** (roadmap R4). Vertica's own docs say it:
  "Policy on other nodes will be refreshed the next time a Voltage operation is run on
  them." Between a Management Console change and full propagation, different nodes enforce
  different policy.

* **A DR region that was not restored from the same backup** (roadmap R15) has the same
  policy, the same formats and a different master secret or token table -- so it protects
  the same value to a different token, and nothing errors. Failover then writes tokens the
  primary cannot detokenize.

Everything here compares hashes. The exporter never keeps or exports a protected value.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .probes import TargetResult


@dataclass
class FleetCheck:
    fleet: str
    check: str  # policy | key_table | version | token
    key: str = ""  # key_table: table name; token: format
    ok: bool | None = None  # None: fewer than two members answered
    members: int = 0
    odd_ones: list[str] = field(default_factory=list)  # targets disagreeing with the majority
    detail: str = ""


def _majority(values: dict[str, str]) -> tuple[str, list[str]]:
    """(majority value, targets that differ). Ties: the first seen wins, deterministically."""
    if not values:
        return "", []
    counts = Counter(values.values())
    top = max(counts.values())
    majority = next(v for v in values.values() if counts[v] == top)
    return majority, sorted(t for t, v in values.items() if v != majority)


def _compare(fleet: str, check: str, key: str, values: dict[str, str]) -> FleetCheck:
    fc = FleetCheck(fleet=fleet, check=check, key=key, members=len(values))
    if len(values) < 2:
        fc.detail = "fewer than two members reported"
        return fc
    _, odd = _majority(values)
    fc.ok = not odd
    fc.odd_ones = odd
    if odd:
        fc.detail = f"{', '.join(odd)} differ from the rest of fleet {fleet!r}"
    return fc


def evaluate(results: list[TargetResult]) -> list[FleetCheck]:
    fleets: dict[str, list[TargetResult]] = {}
    for r in results:
        if r.target.fleet:
            fleets.setdefault(r.target.fleet, []).append(r)

    out: list[FleetCheck] = []
    for fleet, members in sorted(fleets.items()):
        with_policy = [m for m in members if m.policy]

        # policy *configuration* fingerprint: formats, auth, key tables, version -- not hostnames
        out.append(_compare(fleet, "policy", "", {m.target.name: m.policy.config_fingerprint for m in with_policy}))

        # appliance version
        versions = {m.target.name: m.policy.server_version for m in with_policy if m.policy.server_version}
        if versions:
            out.append(_compare(fleet, "version", "", versions))

        # key tables: currentNumber per table -- rotation skew between regions
        tables: dict[str, dict[str, str]] = {}
        for m in with_policy:
            for kt in m.policy.key_tables:
                tables.setdefault(kt.name, {})[m.target.name] = str(kt.current_number)
        for name, vals in sorted(tables.items()):
            out.append(_compare(fleet, "key_table", name, vals))

        # tokens: the same (format, sample) must protect to the same value everywhere
        tokens: dict[tuple[str, str], dict[str, str]] = {}
        for m in members:
            for tk in m.tokenize:
                if tk.token_sha256:
                    tokens.setdefault((tk.spec.format, tk.spec.sample), {})[m.target.name] = tk.token_sha256
        seen_formats: set[str] = set()
        for (fmt, _sample), vals in sorted(tokens.items()):
            if fmt in seen_formats:
                continue  # one verdict per format; the first configured sample decides
            seen_formats.add(fmt)
            out.append(_compare(fleet, "token", fmt, vals))
    return out
