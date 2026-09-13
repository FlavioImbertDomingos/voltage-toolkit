# Alertmanager secrets

Demo values, committed on purpose. They point at `mock-integrations` in docker compose, so
nothing leaves the stack.

For a real deployment do **not** edit these files in the repo. Mount a directory from your secrets
manager over `/etc/alertmanager/secrets` instead (see `docker-compose.override.example.yml`):

| file | content |
|---|---|
| `pagerduty.key` | PagerDuty *Events API v2* integration key (Service → Integrations → Events API v2) |
| `splunk.token` | Splunk HTTP Event Collector token (Settings → Data Inputs → HTTP Event Collector) |
| `splunk.url` | `https://<splunk>:8088/services/collector/raw?sourcetype=alertmanager` |

and delete the two `url:` lines marked `DEMO` in `alertmanager.yml`.
