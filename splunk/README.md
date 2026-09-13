# Splunk app: `voltage_toolkit`

A small, installable Splunk app: one dashboard, four macros, three scheduled searches, and the
`props.conf` that makes the two sourcetypes searchable. Nothing in it is product-specific to
Splunk Enterprise vs Cloud; it is plain Simple XML and `.conf` files.

```
splunk/voltage_toolkit/
├── default/app.conf                         name, version
├── default/props.conf                       voltage-exporter (JSON, ts field) · alertmanager (JSON, never split)
├── default/macros.conf                      `voltage_index`, `voltage_probe_events`, `voltage_probes_expanded`, `voltage_alerts`
├── default/savedsearches.conf               policy changed outside a window · exporter went silent · masking-leak time to clear
├── default/data/ui/views/voltage_tokenization.xml   the dashboard
├── default/data/ui/nav/default.xml
└── metadata/default.meta
```

## Install

```bash
tar -C splunk -czf voltage_toolkit.tgz voltage_toolkit
# Splunk Web → Apps → Manage Apps → Install app from file → voltage_toolkit.tgz
# or: cp -r splunk/voltage_toolkit $SPLUNK_HOME/etc/apps/ && splunk restart
```

Then edit **one** thing: the `voltage_index` macro (Settings → Advanced search → Search macros)
if your events do not land in `index=security`.

## What the dashboard is built around

Four rows, each one question, top to bottom in the order an on-call person asks them:

| Row | Question | Source |
|---|---|---|
| Right now | Can apps tokenize? Is the data right? Will TLS break? What is open? | latest probe event per target; latest Alertmanager notification per alert |
| History | When did it start, which format, why | `probes[]` exploded: failures, p95 latency, error kinds |
| Change | What changed just before — policy hash, key numbers, versions | `streamstats` transitions on `policy_sha256` and `key_tables.*` |
| Alert audit | Every firing/resolution, and time-to-clear | Alertmanager webhook payloads |

Design choices worth defending in a review:

* **Latest-per-target, then aggregate.** Single values use `stats latest(...) BY target | stats ...`
  so a target that stopped reporting keeps its last known state instead of vanishing from a
  percentage. "Exporter went silent" is a separate scheduled search, on purpose.
* **Transitions, not values.** The change row does not chart the policy hash; it lists the moments
  it *changed*, with before/after — that is the row an assessor reads next to the change tickets.
* **Alerts are the Alertmanager's words.** The audit table shows what was sent, to which receiver,
  when — not a re-derivation from metrics. If it paged, it is here; if it is here, it paged.
* **No cardinality traps.** Nothing groups by `policy_sha256` or `token_sha256` in a timechart.
* **Only the fields the exporter emits.** `docs/INTEGRATIONS.md` lists them; anything else is left
  to a saved search you write, not guessed.

## Scheduled searches (Splunk-side alerts)

Prometheus alerts on the last few minutes. These three use the SIEM's memory instead:

* **Policy changed outside a change window** — a hash transition on a weekday outside
  20:00–23:59 UTC (edit the window in the search). PCI DSS change control.
* **Exporter went silent** — no probe event for 5 minutes. Prometheus cannot raise this if the
  exporter host is what died.
* **Masking leak time to clear** — weekly, per target, from resolved `SDMMaskLeak` notifications.

## Honesty

The XML is schema-valid Simple XML and the SPL uses only documented commands (`spath`,
`mvexpand`, `streamstats`, `foreach`, `timechart`); the field names match what `structured.py`
and Alertmanager emit. It has not yet been run on a licensed Splunk instance from this repo's CI
— there is no Splunk in `docker compose`. Load it, open the dashboard with a few hours of demo
events, and file an issue for any panel that disagrees with `curl localhost:8900/received`.
