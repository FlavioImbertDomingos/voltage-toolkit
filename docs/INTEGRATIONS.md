# Enterprise integrations: PagerDuty and Splunk (roadmap R17)

Grafana and Alertmanager stay exactly as they are. PagerDuty and Splunk attach at seams that
already exist, and nothing in the toolkit learns a vendor name — the same way a bank's platform
team would want it: the exporter emits clean signals, the enterprise observability stack owns
delivery.

```
                     ┌─────────────┐   rules    ┌──────────────┐  route: every alert ──▶ Splunk HEC (audit trail)
 voltage-exporter ──▶│ Prometheus  │──────────▶ │ Alertmanager │  route: pager ─────────▶ PagerDuty Events v2
   /metrics          └──────┬──────┘            └──────────────┘  route: default ───────▶ Slack / email
        │                   │ Grafana reads it
        │ stdout, JSON      ▼
        └──────────────▶ log forwarder (Docker splunk driver / Universal Forwarder / OTel) ──▶ Splunk index
```

Three flows, in the order you would turn them on.

## 1. PagerDuty — one receiver

`alertmanager/alertmanager.yml` already had the `pager` route: data-integrity and outage alerts
(`VoltageRoundTripMismatch`, `VoltageRegionDivergence`, `SDMMaskLeak`, `VoltageTokenizationFailing`,
`VoltagePolicyUnreachable`, …) with `group_wait: 0s`, plus anything `severity=critical`. The
receiver now delivers to PagerDuty's Events API v2:

```yaml
  - name: pager
    pagerduty_configs:
      - routing_key_file: /etc/alertmanager/secrets/pagerduty.key
        severity: '{{ if eq .CommonLabels.severity "critical" }}critical{{ else }}warning{{ end }}'
        description: '{{ .CommonAnnotations.summary }}'
        component: '{{ .CommonLabels.target }}'
        class: '{{ .CommonLabels.alertname }}'
        details: { target, format, description, runbook, firing }
```

What you get for free from Alertmanager: **deduplication** (one incident per `alertname,target`
group, not one per scrape), **auto-resolve** (`send_resolved: true` closes the incident when the
alert clears), and the existing **inhibition** rules — a dead policy server produces one page, not
one per format. `class` and `component` become PagerDuty's grouping keys, so "SDMMaskLeak on
demo-nonprod" stays one incident across re-fires.

Setup: PagerDuty → Services → your service → Integrations → *Events API v2* → copy the 32-character
integration key into `pagerduty.key`.

## 2. Alerts into Splunk — a `continue: true` route

A first route matches every alert, delivers to the `splunk` receiver and continues, so the same
alert still reaches the pager or default receiver. Splunk therefore holds the complete history of
every firing *and* resolution — the audit trail an assessor asks for ("show me every time a masking
leak was detected and how long it took to clear").

```yaml
  routes:
    - matchers: ['alertname =~ ".+"']
      receiver: splunk
      continue: true
```

The receiver is a plain webhook to the **HEC raw endpoint**, because Alertmanager's webhook payload
has no top-level `event` key and the `/event` endpoint rejects it:

```yaml
  - name: splunk
    webhook_configs:
      - url_file: /etc/alertmanager/secrets/splunk.url     # https://splunk:8088/services/collector/raw?sourcetype=alertmanager
        http_config:
          authorization: { type: Splunk, credentials_file: /etc/alertmanager/secrets/splunk.token }
```

Set `sourcetype=alertmanager` in the URL and Splunk's JSON auto-extraction gives you
`alerts{}.labels.alertname`, `alerts{}.status`, `alerts{}.startsAt`, `alerts{}.endsAt`.

## 3. Metrics and probe events into Splunk — structured logs

Prometheus answers "is it broken now"; a SIEM answers "when did it start, what changed just before,
and was anything else happening" — and keeps the answer for a year. That is a log problem, not a
metric problem. With `log_format: json` (env `VOLTAGE_EXPORTER_LOG_FORMAT=json`, or
`--log-format json`; the compose stack defaults to it) the exporter writes one JSON object per
target per probe cycle:

```json
{"ts":"2026-09-13T20:41:38.726Z","level":"INFO","logger":"voltage_exporter.metrics",
 "message":"[demo-prod] policy ok probes 2/2 keyservers 2/2 tls 19.8d 208.4ms",
 "event":"probe","target":"demo-prod","fleet":"demo","policy_ok":true,"policy_ms":6.2,
 "policy_sha256":"9c1e…","policy_fingerprint":"b71a…","server_version":"7.0.3.100100",
 "district":"demo","formats":14,"key_tables":{"PCI":4,"PII":1},
 "probes":[{"format":"CC","identity":"probe@demo.bank","ok":true,"protect_ms":24.1,"access_ms":19.7,
            "roundtrip_ok":true,"format_preserved":true,"token_sha256":"3f2a9c…","error_kind":"","error":""}],
 "probes_ok":2,"probes_total":2,"integrity_ok":true,"integrity_failed":[],
 "keyservers_up":2,"keyservers_total":2,"tls_ok":true,"tls_min_days":19.8,"duration_ms":208.4}
```

Hashes, booleans and numbers only: no token, no sample, no secret is ever logged.

Ship it any of three ways: the Docker `splunk` logging driver (see
`docker-compose.override.example.yml`), a Universal Forwarder tailing the container's json-file
log, or an OpenTelemetry collector with the `filelog` receiver and the Splunk HEC exporter. For the
**metrics** themselves, uncomment the `remote_write` stanza in `prometheus/prometheus.yml` to send
them to Splunk's Prometheus-compatible ingest (`/services/collector/metrics`, or the Splunk
Observability endpoint) — Grafana keeps reading Prometheus locally either way.

Searches that earn their keep:

```
index=security sourcetype=voltage-exporter event=probe policy_ok=false
| stats earliest(ts) AS since count BY target                       -- when did it start

index=security sourcetype=voltage-exporter event=probe
| stats dc(policy_sha256) AS versions BY target span=1h             -- who changed the policy, when

index=security sourcetype=voltage-exporter event=probe probes{}.error_kind=auth
| timechart count BY target                                         -- "somebody rotated the shared secret"

index=security sourcetype=alertmanager alerts{}.labels.alertname=SDMMaskLeak
| eval mins=(strptime('alerts{}.endsAt',"%Y-%m-%dT%H:%M:%S")-strptime('alerts{}.startsAt',"%Y-%m-%dT%H:%M:%S"))/60
| stats avg(mins) max(mins)                                         -- time-to-clear for the assessor
```

## Proving it without accounts

`mock-integrations/` is a 160-line stdlib server that speaks both protocols where it matters:
`POST /v2/enqueue` validates the routing key (32 characters), `event_action` and the required
payload fields exactly as PagerDuty does and answers `202 {"status":"success"}`; the HEC endpoints
demand `Authorization: Splunk <token>` and answer `403 Invalid token` otherwise. Everything it
accepts (and rejects) is readable:

```bash
docker compose up -d
sleep 60
curl -s 'localhost:8900/received?kind=pagerduty' | jq '.received[].body | {event_action, dedup_key, summary: .payload.summary}'
curl -s 'localhost:8900/received?kind=splunk'    | jq '.received[].body.alerts[].labels.alertname'
```

The seeded masking leak (`SDMMaskLeak`) fires within the first minute, so the first PagerDuty
`trigger` is that one. CI's compose smoke test asserts exactly this: a `trigger` with
`severity=critical`, `class=SDMMaskLeak` arrived at the PagerDuty mock, and the same alert reached
the Splunk mock with a valid token.

## Going live

1. Create the three secret files from your secrets manager — never in the repo — and mount the
   directory over `/etc/alertmanager/secrets` (`docker-compose.override.example.yml`).
2. Delete the two `url:` lines marked `DEMO` in `alertmanager/alertmanager.yml`.
3. `amtool check-config alertmanager/alertmanager.yml` (CI runs it on every push).
4. `docker compose up -d alertmanager` and `curl -XPOST localhost:8800/mock/scenario/policy-down`
   once against a non-production stack: you should see one PagerDuty incident, one Splunk event
   per firing/resolution, and nothing for the inhibited tokenization alerts.
