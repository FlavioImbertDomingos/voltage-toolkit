"""Appliance version -> support lifecycle.

OpenText publishes an end-of-maintenance date per release in the community release
notes, and the appliance reports its version inside `clientPolicy.xml`
(`<server name="SecureDataAppliance" version="7.0.3.xxxxx"/>`). Put the two together and
"are we running something out of support" becomes a metric instead of a spreadsheet.

The built-in table holds only what is public. It is deliberately short: the support
portal is login-walled, so the operator can (and should) extend it from the exporter
config:

    exporter:
      support_end:
        "7.0.4": 2027-11-30
        "7.1":   2028-06-30

Matching is by longest version prefix ("7.0.3.100100" matches "7.0.3" before "7.0"
before "7"). Unknown versions produce no `voltage_support_end_timestamp_seconds` series
rather than a guess.
"""

from __future__ import annotations

import datetime as _dt

#: version prefix -> (release name, end of maintenance ISO date).
#: Sources: OpenText community release notes for DPP Foundation CE 24.4 (SecureData
#: Appliance v7.0.3) — maintenance ends 2027-11-30.
BUILTIN_SUPPORT_END: dict[str, tuple[str, str]] = {
    "7.0.3": ("DPP Foundation CE 24.4", "2027-11-30"),
}


def _parse_date(value: str | _dt.date) -> float:
    if isinstance(value, _dt.datetime):
        d = value.date()
    elif isinstance(value, _dt.date):
        d = value
    else:
        d = _dt.date.fromisoformat(str(value).strip())
    # end of maintenance == end of that day, UTC
    return _dt.datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=_dt.UTC).timestamp()


def support_end(version: str, overrides: dict | None = None) -> tuple[str, float] | None:
    """(release name, end-of-maintenance unix timestamp) for an appliance version, or None.

    `overrides` maps version prefix -> ISO date or {"release": ..., "end": ...}.
    """
    if not version:
        return None
    table: dict[str, tuple[str, str]] = dict(BUILTIN_SUPPORT_END)
    for prefix, spec in (overrides or {}).items():
        known_release = table.get(str(prefix), (str(prefix), ""))[0]
        if isinstance(spec, dict):
            table[str(prefix)] = (str(spec.get("release", known_release)), str(spec.get("end")))
        else:
            table[str(prefix)] = (known_release, str(spec))
    v = version.strip()
    for prefix in sorted(table, key=len, reverse=True):
        if v == prefix or v.startswith(prefix + "."):
            release, end = table[prefix]
            try:
                return release, _parse_date(end)
            except (TypeError, ValueError):
                return None
    return None


def split_version(version: str) -> tuple[str, str]:
    """('7', '7.0') from '7.0.3.100100' — for coarse labels without exploding cardinality."""
    parts = [p for p in version.strip().split(".") if p]
    major = parts[0] if parts else ""
    minor = ".".join(parts[:2]) if len(parts) >= 2 else major
    return major, minor
