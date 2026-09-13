# Root of trust: the HSM, the identity backup, and the drill nobody tracks (roadmap R11)

Stateless key management means there is no token vault to replicate and no per-key store to
back up. Everything derives from the **district master secret**, anchored in an HSM. That is
elegant operationally and unforgiving in one specific way: the identity / master-secret backup
is the only thing between a district and the permanent loss of every token it ever issued.
There is no per-key revocation, no "rebuild from the vault". If the backup does not restore,
the data is gone.

Two facts sharpen this:

* The HSM generation matters. nShield Connect XC was retired from sale in October 2025 with
  mainstream support ending **2027-12-31**; Voltage SecureData 7.1.1 with Entrust Security
  World client 13.6.15 is certified for nShield 5c (FIPS 140-3 Level 3, native PQC support).
  A migration is on every deployment's calendar whether it is written down or not, and a
  migration is a restore.
* There are **two public restore defects** in the community wiki from the same week of
  November 2024. Restores fail in ways that look successful until a token is compared.

Nothing in the product tracks whether anyone has proved the backup restores. This page and
the `restore_drills:` block make that a metric.

## The drill

Quarterly, or after any change to the appliance version, HSM firmware or Security World:

1. Restore the identity backup into an **isolated** appliance (or the DR region during a
   maintenance window) with the same district domain name and, where applicable, the same
   token tables.
2. Authenticate as the probe identity and protect a known synthetic value for each format
   in use.
3. Compare each token to the one production produces for the same value — the fleet-agreement
   probe (`voltage_fleet_agreement{check="token"}`) does exactly this comparison if the
   restored appliance is added as a target in the same `fleet:`.
4. Record the outcome where the exporter can read it: a row `(drill, finished_at, result,
   operator)` in an ops table, or a line in a CSV. `result` is `SUCCESS` / `PASS` / `OK`;
   anything else is a failure and is kept as the failure text.

A drill that restores cleanly but produces **different tokens** has failed. That is the master
secret mismatch, the district name typo, or the token-table mismatch — the same three
conditions that silently break DR (`docs/ARCHITECTURE.md`, fleet agreement).

## What the exporter reports

```yaml
restore_drills:
  - name: prod-identity-backup
    district: prod
    max_age: 90d
    source: {type: sql, dsn: postgresql://ro@ops-db/ops, driver: psycopg2, password_env: OPS_DB_PASSWORD}
    query: SELECT drill, finished_at, result FROM restore_drills
```

| Series | Meaning |
|---|---|
| `voltage_identity_backup_restore_tested_timestamp_seconds{drill,district}` | last successful, tested restore |
| `voltage_restore_drill_ok` | 1 = within `max_age` and the latest attempt succeeded |
| `voltage_restore_drill_overdue` | 1 = never tested, or older than `max_age` |
| `voltage_restore_drill_last_failed` | 1 = the most recent attempt failed |
| `voltage_restore_drill_last_attempt_timestamp_seconds` | when someone last tried |
| `voltage:restore_drill_days_since_success` | recording rule, for dashboards and the overdue alert |

Alerts: `VoltageRestoreDrillNeverTested`, `VoltageRestoreDrillOverdue` (warning),
`VoltageRestoreDrillFailed` (critical: assume the district cannot be rebuilt until it passes),
`VoltageRestoreDrillEvidenceUnreadable`.

## The HSM row (luna-exporter)

The Grafana dashboard's **Root of trust** row joins these drill panels with the HSM itself,
read from the sister project [luna-exporter](https://github.com/FlavioImbertDomingos/luna-exporter):
`luna_up`, `luna_hsm_info` (model, firmware, serial), `luna_hsm_tamper_events`,
`luna_hsm_fips_mode_enabled`. `prometheus/prometheus.yml` carries a commented scrape job for
it; until that job exists the HSM panels read *No data*, on purpose — a blank panel is a more
honest statement than a green one fed by nothing.

Why the two belong on one row: the HSM is where the master secret lives, the drill is the proof
that what lives there can be recovered. Firmware changed (`luna_hsm_info`) and no drill since
(`voltage:restore_drill_days_since_success`) is the combination worth a change ticket.

## Demo

`demo/seed_nonprod.py` seeds two drills: `prod-identity-backup` proven 12 days ago, and
`dr-identity-backup` last proven 190 days ago with a failed attempt 100 days ago ("master
secret mismatch"). The second fires `VoltageRestoreDrillFailed` and `VoltageRestoreDrillOverdue`
from the first scrape.
