"""Coverage: is everything that *should* be protected actually protected?  (roadmap R6, R7)

(Identical to exporter/voltage_exporter/coverage.py -- keep the two in sync; the exporter tests cover it.)

The exporter can prove tokenization works. Discovery tools (Structured Data Manager, Core
Data Discovery, a hand-built spreadsheet) can say where sensitive data lives. Nothing joins
the two -- and the join is where audits are failed. This module is that join.

Three inputs, all files, no product coupling:

* **Classification feed** -- CSV, one row per sensitive column:

      system,schema,table,column,classification,confidence
      cards-db,public,customers,pan,PAN,0.99

  `schema` and `confidence` may be empty. Anything can produce it.

* **Data map** (`voltage-data-map.yml`) -- config-as-code, the statement of intent:

      version: 1
      columns:
        - {system: cards-db, schema: public, table: customers, column: pan,
           district: prod, format: CC, identities: [payments@demo.bank], classification: PAN}

* **Live policy per district** and, optionally, the **desired-state document**
  (`voltage-config.yml`) so identities can be checked too.

Every classified column ends up in exactly one state:

    protected   mapped, the format exists in the district's live policy, and every
                identity named consumes it (when the desired state is available)
    unmapped    classified as sensitive, no data-map entry -- the PCI scope-drift case
    broken      mapped, but the mapping no longer holds: format not offered, identity not
                declared or not allowed the format, classification disagrees with the feed
    unknown     below the confidence threshold, or the district's policy is unavailable

Plus the other direction (R7): **dead formats** -- offered by the policy, referenced by no
column and no identity, whose keys keep rotating for nothing.

stdlib only, and the Ansible collection's module_utils carries an identical copy.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

STATES = ("protected", "unmapped", "broken", "unknown")


def _norm(v: object) -> str:
    return str(v or "").strip().lower()


def _key(system: object, schema: object, table: object, column: object) -> tuple[str, str, str, str]:
    return (_norm(system), _norm(schema), _norm(table), _norm(column))


@dataclass
class FeedRow:
    system: str
    schema: str
    table: str
    column: str
    classification: str
    confidence: float | None = None

    @property
    def key(self) -> tuple[str, str, str, str]:
        return _key(self.system, self.schema, self.table, self.column)

    @property
    def qualified(self) -> str:
        parts = [self.system, self.schema, self.table, self.column]
        return ".".join(p for p in parts if p)


@dataclass
class MapEntry:
    system: str
    schema: str
    table: str
    column: str
    district: str
    format: str
    identities: list[str] = field(default_factory=list)
    classification: str = ""

    @property
    def key(self) -> tuple[str, str, str, str]:
        return _key(self.system, self.schema, self.table, self.column)

    @property
    def qualified(self) -> str:
        parts = [self.system, self.schema, self.table, self.column]
        return ".".join(p for p in parts if p)


@dataclass
class ColumnVerdict:
    row: FeedRow
    state: str
    reason: str = ""
    entry: MapEntry | None = None

    def to_dict(self) -> dict:
        return {
            "column": self.row.qualified,
            "classification": self.row.classification,
            "confidence": self.row.confidence,
            "state": self.state,
            "reason": self.reason,
            "district": self.entry.district if self.entry else "",
            "format": self.entry.format if self.entry else "",
        }


@dataclass
class CoverageReport:
    columns: list[ColumnVerdict] = field(default_factory=list)
    dead_formats: dict[str, list[str]] = field(default_factory=dict)  # district -> formats
    unclassified_mappings: list[MapEntry] = field(default_factory=list)  # mapped, but the feed never saw them
    feed_rows: int = 0
    map_entries: int = 0
    errors: list[str] = field(default_factory=list)

    def counts(self) -> dict[tuple[str, str], int]:
        """{(state, classification): n}"""
        out: dict[tuple[str, str], int] = {}
        for c in self.columns:
            k = (c.state, c.row.classification or "unclassified")
            out[k] = out.get(k, 0) + 1
        return out

    def by_state(self, state: str) -> list[ColumnVerdict]:
        return [c for c in self.columns if c.state == state]

    def to_dict(self) -> dict:
        totals = {s: len(self.by_state(s)) for s in STATES}
        return {
            "totals": totals,
            "feed_rows": self.feed_rows,
            "map_entries": self.map_entries,
            "columns": [c.to_dict() for c in self.columns],
            "dead_formats": self.dead_formats,
            "unclassified_mappings": [m.qualified for m in self.unclassified_mappings],
            "errors": self.errors,
        }


# --------------------------------------------------------------------------- parsing
def parse_feed(text: str) -> tuple[list[FeedRow], list[str]]:
    """CSV with a header. Column names are case-insensitive; unknown columns are ignored."""
    rows: list[FeedRow] = []
    errors: list[str] = []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return rows, ["classification feed is empty"]
    names = {n.strip().lower(): n for n in reader.fieldnames if n}
    for req in ("system", "table", "column"):
        if req not in names:
            return rows, [f"classification feed has no '{req}' column (header: {reader.fieldnames})"]

    def get(r: dict, n: str) -> str:
        return (r.get(names[n]) or "").strip() if n in names else ""

    for i, r in enumerate(reader, start=2):
        conf: float | None = None
        raw = get(r, "confidence")
        if raw:
            try:
                conf = float(raw)
            except ValueError:
                errors.append(f"line {i}: confidence {raw!r} is not a number")
        if not (get(r, "system") and get(r, "table") and get(r, "column")):
            errors.append(f"line {i}: system, table and column are required")
            continue
        rows.append(
            FeedRow(
                system=get(r, "system"),
                schema=get(r, "schema"),
                table=get(r, "table"),
                column=get(r, "column"),
                classification=get(r, "classification"),
                confidence=conf,
            )
        )
    return rows, errors


def parse_data_map(doc: dict | None) -> tuple[list[MapEntry], list[str]]:
    """`doc` is the already-parsed YAML/JSON document (this module has no YAML dependency)."""
    entries: list[MapEntry] = []
    errors: list[str] = []
    if not doc:
        return entries, ["data map is empty"]
    cols = doc.get("columns") if isinstance(doc, dict) else None
    if not isinstance(cols, list):
        return entries, ["data map needs a top-level 'columns' list"]
    for i, c in enumerate(cols):
        if not isinstance(c, dict):
            errors.append(f"columns[{i}]: not a mapping")
            continue
        missing = [k for k in ("system", "table", "column", "district", "format") if not c.get(k)]
        if missing:
            errors.append(f"columns[{i}]: missing {', '.join(missing)}")
            continue
        ids = c.get("identities") or []
        if isinstance(ids, str):
            ids = [ids]
        entries.append(
            MapEntry(
                system=str(c["system"]),
                schema=str(c.get("schema") or ""),
                table=str(c["table"]),
                column=str(c["column"]),
                district=str(c["district"]),
                format=str(c["format"]),
                identities=[str(x) for x in ids],
                classification=str(c.get("classification") or ""),
            )
        )
    return entries, errors


def identities_from_desired_state(doc: dict | None) -> dict[str, dict]:
    """{identity name: {"district": ..., "formats": [...]}} from voltage-config.yml, if given."""
    out: dict[str, dict] = {}
    if not isinstance(doc, dict):
        return out
    for name, spec in (doc.get("identities") or {}).items():
        if isinstance(spec, dict):
            out[str(name)] = {
                "district": str(spec.get("district") or ""),
                "formats": [str(f) for f in (spec.get("formats") or [])],
            }
    return out


# --------------------------------------------------------------------------- the join
def evaluate(
    feed: list[FeedRow],
    data_map: list[MapEntry],
    policy_formats: dict[str, list[str]],
    identities: dict[str, dict] | None = None,
    *,
    min_confidence: float = 0.0,
    sensitive_classes: list[str] | None = None,
) -> CoverageReport:
    """
    policy_formats   {district: [format names the live policy offers]}; a district missing here
                     means its policy was unavailable this cycle -> its columns are 'unknown'.
    identities       from identities_from_desired_state(); None = do not check identities.
    sensitive_classes  only these classifications count (case-insensitive); None = all rows.
    """
    rep = CoverageReport(feed_rows=len(feed), map_entries=len(data_map))
    by_key: dict[tuple[str, str, str, str], MapEntry] = {}
    for e in data_map:
        if e.key in by_key:
            rep.errors.append(f"data map: duplicate entry for {e.qualified}")
        by_key[e.key] = e
    classes = {c.lower() for c in sensitive_classes} if sensitive_classes else None
    offered = {d.lower(): {f.lower() for f in fs} for d, fs in policy_formats.items()}
    seen_keys: set[tuple[str, str, str, str]] = set()

    for row in feed:
        if classes is not None and row.classification.lower() not in classes:
            continue
        seen_keys.add(row.key)
        entry = by_key.get(row.key)
        if row.confidence is not None and row.confidence < min_confidence:
            rep.columns.append(ColumnVerdict(row, "unknown", f"confidence {row.confidence} < {min_confidence}", entry))
            continue
        if entry is None:
            rep.columns.append(ColumnVerdict(row, "unmapped", "no data-map entry"))
            continue
        if entry.classification and row.classification and entry.classification.lower() != row.classification.lower():
            rep.columns.append(
                ColumnVerdict(row, "broken", f"map says {entry.classification}, feed says {row.classification}", entry)
            )
            continue
        fmts = offered.get(entry.district.lower())
        if fmts is None:
            rep.columns.append(
                ColumnVerdict(row, "unknown", f"policy for district {entry.district!r} unavailable", entry)
            )
            continue
        if entry.format.lower() not in fmts:
            rep.columns.append(
                ColumnVerdict(row, "broken", f"format {entry.format} not offered by district {entry.district}", entry)
            )
            continue
        if identities is not None and entry.identities:
            bad = []
            for ident in entry.identities:
                spec = identities.get(ident)
                if spec is None:
                    bad.append(f"{ident} not declared")
                elif spec["district"] and spec["district"].lower() != entry.district.lower():
                    bad.append(f"{ident} belongs to district {spec['district']}")
                elif spec["formats"] and entry.format.lower() not in {f.lower() for f in spec["formats"]}:
                    bad.append(f"{ident} not allowed format {entry.format}")
            if bad:
                rep.columns.append(ColumnVerdict(row, "broken", "; ".join(bad), entry))
                continue
        rep.columns.append(ColumnVerdict(row, "protected", "", entry))

    # the other direction: mappings the feed never saw, and formats nothing uses
    rep.unclassified_mappings = [e for e in data_map if e.key not in seen_keys]
    used: dict[str, set[str]] = {}
    for e in data_map:
        used.setdefault(e.district.lower(), set()).add(e.format.lower())
    for spec in (identities or {}).values():
        if spec.get("district"):
            used.setdefault(spec["district"].lower(), set()).update(f.lower() for f in spec.get("formats", []))
    for district, fmts in policy_formats.items():
        dead = sorted(f for f in fmts if f.lower() not in used.get(district.lower(), set()))
        if dead:
            rep.dead_formats[district] = dead
    return rep
