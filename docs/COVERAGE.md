# Coverage — is everything that *should* be protected actually protected?

The exporter proves tokenization works. A discovery tool — Structured Data Manager, Core Data
Discovery & Risk Insights, or a spreadsheet — says where sensitive data lives. Nobody joins the
two, and the join is where audits are failed: the column that was classified PAN last quarter
and that nothing tokenizes. This is that join (roadmap R6 and R7).

## Three inputs, all files

**1. Classification feed** — CSV, one row per sensitive column. Anything can produce it.

```csv
system,schema,table,column,classification,confidence
cards-db,public,customers,pan,PAN,0.99
crm,,contacts,ssn,SSN,0.95
```

`schema` and `confidence` may be empty. Column names are case-insensitive; unknown columns are
ignored. SDM / Core Data Discovery exports need at most a column rename to fit.

**2. Data map** — `voltage-data-map.yml`, config-as-code, the statement of intent. Commit it next
to `voltage-config.yml`.

```yaml
version: 1
columns:
  - system: cards-db
    schema: public
    table: customers
    column: pan
    classification: PAN          # optional; if given, must agree with the feed
    district: prod
    format: CC
    identities: [payments@demo.bank]   # who is supposed to tokenize it
```

**3. The live policy** per district (the exporter already has it; the audit role fetches it) and,
optionally, **`voltage-config.yml`** so identities can be checked.

## Every classified column ends up in one state

| State | Meaning | Alert |
|---|---|---|
| `protected` | mapped; the format exists in the district's live policy; every named identity is declared and allowed the format | — |
| `unmapped` | classified sensitive, no data-map entry. **PCI scope drift** | `VoltageUnprotectedSensitiveColumn` (warning, 30m) |
| `broken` | mapped, but the mapping no longer holds: format not offered, identity not declared / not allowed the format, classification disagrees with the feed | `VoltageBrokenProtectionMapping` (critical, 10m) |
| `unknown` | below `min_confidence`, or the district's policy was unavailable this cycle | — |

And in the other direction: **dead formats** — offered by a district, referenced by no column and
no declared identity. Their keys still rotate; they are still an authorisable capability
(`VoltageDeadFormat`, info, 24h). Plus mapped columns the feed never mentioned, reported but
not alerted — discovery may simply not scan that system.

## Where it runs

Both places, from one stdlib module (`coverage.py`, byte-identical in the exporter and the
collection's `module_utils`; CI diffs them):

- **Exporter** — `coverage:` block in the config; evaluated every cycle against the districts the
  targets' policies declare. Metrics in [METRICS.md](METRICS.md). `--once` prints unmapped and
  broken columns and exits non-zero.
- **Audit role** — `voltage_audit_classification_csv` + `voltage_audit_data_map_path`; the report
  gains a Coverage section, and unmapped/broken columns count as drift for `fail_on_drift`
  (`voltage_audit_coverage_is_drift: false` to report only).

## The demo

`config/classification.demo.csv` classifies `warehouse.dw.fact_orders.card_no` as PAN and
`config/voltage-data-map.demo.yml` has no entry for it — on purpose, so the finding is visible
from the first scrape, like the 20-day certificate and the last-4 SSN. Map it and watch the
alert clear:

```yaml
  - {system: warehouse, schema: dw, table: fact_orders, column: card_no,
     district: prod, format: CC, identities: [payments@demo.bank]}
```

## Honest limits

- Coverage is only as current as discovery. `VoltageClassificationFeedStale` fires when the feed
  is older than 7 days.
- "Protected" means *the mapping is coherent with the live policy and declared identities*. It does
  not prove the application actually calls protect() on that column — that is what the
  application's own tests, or database-side sampling (R8), are for.
- Identities are not visible in `clientPolicy.xml`; identity checks depend on `voltage-config.yml`
  being truthful, which is what the audit role's drift detection is for.
