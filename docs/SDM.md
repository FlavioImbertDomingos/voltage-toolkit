# Structured Data Manager — masked data and batch jobs

SDM archives inactive data, enforces retention, and builds **masked** non-production
environments. It has no public API. What it leaves behind is *data*: masked rows in a
non-prod database or export, and a job history somewhere — its repository, a log table, a CSV
the scheduler drops. These checks read those (roadmap R8 and R9).

## Sources

One `source:` per check. Read-only by construction — a single `SELECT`/`WITH`, or a file.

```yaml
source: {type: sql, dsn: "sqlite:////data/nonprod.db"}                       # stdlib sqlite3
source: {type: sql, driver: psycopg, dsn: "postgresql://ro@db/cards", password_env: NONPROD_DB_PASSWORD}
source: {type: sql, driver: pyodbc,  connect: {DSN: nonprod, UID: ro}, password_env: NONPROD_DB_PASSWORD}
source: {type: file, path: /exports/customers_masked.csv}                     # + columns: [pan]
```

Any DB-API 2.0 driver works if it is installed in the exporter image; the DSN is redacted in
logs. Give the exporter a **read-only** database account — the code refuses anything but
`SELECT`, and the account should refuse it too.

## Masking checks (R8)

| `kind` | Rows expected | Passes when | Alert |
|---|---|---|---|
| `leak` | `(value)` | no value matches a **canary** — and, if `heuristic: true`, none looks live | `SDMMaskLeak` (critical, pages) |
| `consistency` | `(key, value_a, value_b…)` | every key masks to one value across all tables | `SDMMaskInconsistent` (warning, 30m) |
| `constant` | `(value)` | more than one distinct value | `SDMMaskConstant` (warning, 30m) |

**Canaries are the real leak test.** Plant a handful of synthetic-but-unique values in
production (a customer that does not exist, with a PAN that will never be issued). They must
never appear in the masked copy. Give them inline (`canaries: [...]`), or in a file
(`canary_file:`), or as SHA-256 digests (`canaries_hashed: true`) so the values need not live
in config. Matches are **counted, never printed**.

**The heuristic is off by default, and here is why.** "Looks like a real PAN" means
13–19 digits, Luhn-valid, not a well-known test number. Voltage FPE with checksum preservation
produces Luhn-valid output *by design* — that is the point of format preservation. On
FPE-masked data the heuristic flags every row and proves nothing. Use it only where masking is
FPH, scrambling or synthetic generation, and say so in the check's name.

**Consistency** is referential integrity in the test environment: `customers.pan` and
`orders.pan` for the same customer must mask to the same value, or every join in the test
suite silently loses rows and the tests lie. Write the query as a join returning the key and
the masked value from each table.

## Job checks (R9)

Rows are `(job_name, status, finished_at, rows)`; `finished_at` may be ISO-8601 or epoch
seconds. Per job: last successful finish, most recent status, rows processed, and two flags —
**stale** (no success within `expect_every`) and **failing** (latest run failed).

| Alert | Fires when |
|---|---|
| `SDMJobStale` (warning, 1h) | no success within `expect_every` — archive/retention/masking runs fail quietly; the first symptom is otherwise a storage bill or a retention violation |
| `SDMJobFailing` (warning) | most recent run failed |
| `SDMSourceUnreadable` (warning, 15m) | the check's source cannot be read |

## Config

```yaml
sdm:
  masking:
    - name: nonprod-cards-pan
      kind: leak
      source: {type: sql, driver: psycopg, dsn: "postgresql://ro@nonprod-db/cards", password_env: NONPROD_DB_PASSWORD}
      query: "SELECT pan FROM customers"
      canary_file: /etc/voltage-exporter/canaries.sha256
      canaries_hashed: true
    - name: nonprod-cards-ri
      kind: consistency
      source: {type: sql, driver: psycopg, dsn: "postgresql://ro@nonprod-db/cards", password_env: NONPROD_DB_PASSWORD}
      query: "SELECT c.customer_id, c.pan, o.pan FROM customers c JOIN orders o USING (customer_id)"
  jobs:
    - name: sdm
      source: {type: file, path: /exports/sdm-jobs.csv}
      columns: [job_name, status, finished_at, rows]
      expect_every: 24h
```

## The demo

`docker compose up` runs `nonprod-seed`, which builds a pretend masked database
(`demo/seed_nonprod.py`) into a shared volume the exporter mounts read-only. Planted on purpose:

- **one customer row still holds a canary** — the masking job skipped it (`SDMMaskLeak`)
- `customers.ssn` is a constant `XXX-XX-XXXX` (`SDMMaskConstant`)
- `mask-nonprod-refresh` last succeeded three days ago and its latest run failed
  (`SDMJobStale`, `SDMJobFailing`); `archive-orders-2019` is healthy
- `orders.pan` is consistent with `customers.pan` — that check passes

`--once` prints every verdict:

```
[sdm nonprod-pan-leak] leak: FAIL (40 rows) 1 of 40 masked value(s) match a canary or look live
[sdm nonprod-pan-ri] consistency: ok (80 rows)
[sdm nonprod-ssn-constant] constant: FAIL (40 rows) all 40 masked value(s) are identical
[sdm sdm] jobs: FAIL (2 job(s)) stale: mask-nonprod-refresh; failing: mask-nonprod-refresh
```

## Honest limits

- These checks see what the *data* shows. They cannot see SDM's own configuration or why a job
  failed — that is in SDM's logs.
- A canary proves a row leaked; it does not prove every row was masked. Plant several, in the
  tables that matter, and rotate them.
- Nothing here talks to the Voltage appliance. Masking quality is a property of the data, and
  that is where it is measured.
