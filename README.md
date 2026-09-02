# voltage-toolkit

**Monitoring and automation for OpenText Voltage SecureData — the tokenization service nobody
can see inside.**

Two things in one repo:

1. **`voltage-exporter`** — a Prometheus exporter that *actually tokenizes something* every
   30 seconds and reports latency, error rate, data integrity, policy drift and certificate expiry.
2. **`flavioimbertdomingos.voltage`** — an Ansible collection: policy facts, a synthetic-probe
   module, config-as-code for identities / districts / auth methods with drift detection, and a
   role that deploys the exporter.

Plus a mock appliance, so all of it runs with `docker compose up` and no Voltage licence.

[![CI](https://github.com/FlavioImbertDomingos/voltage-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/FlavioImbertDomingos/voltage-toolkit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## The 10-year-old explanation

A bank has a machine that turns card numbers into fake-looking card numbers (a *token*) so
the real ones never sit in databases. Every payment, every night batch, every customer
lookup asks that machine: "tokenize this", "un-tokenize that". That machine is
**Voltage SecureData**.

Here's the problem: the machine's own dashboard tells you it's *switched on*. It does not
tell you whether an application, right now, can get a token back in under half a second,
whether the token can be turned back into the right card number, or whether the certificate
every application checks expires on Tuesday.

**voltage-exporter is a robot that stands in line like a real application.** Every 30 seconds
it hands the machine a fake card number, gets a token, hands the token back, and checks it got
the same fake number. It times both steps and writes the results on a whiteboard for
Prometheus. If anything is slow, wrong or broken, an alert fires before customers notice.

**The Ansible collection is the rulebook.** It writes down, in git, which districts should
exist, which formats they offer, which applications (identities) may use them and how they
log in — and every night it checks the machine still agrees with the rulebook.

```
                      every 30s: protect(4111…) → token → access(token) == 4111…?
  ┌──────────────────┐                                     ┌──────────────────┐
  │ Voltage          │◄── clientPolicy.xml ────────────────│ voltage-exporter │──► /metrics ──► Prometheus ──► alerts
  │ SecureData       │◄── REST / SOAP protect+access ──────│  (synthetic      │                      │
  │ (policy, WS API, │◄── TLS handshake (cert expiry) ─────│   probes)        │                   Grafana
  │  key server)     │                                     └──────────────────┘
  │                  │◄── voltage_policy_facts ────────────┐
  └──────────────────┘                                     │  Ansible collection
                          voltage-config.yml (git) ──diff──┤  voltage_district / voltage_identity /
                                                           │  voltage_auth_method  +  voltage_policy_audit role
```

---

## Try it in 3 minutes (no Voltage needed)

```bash
git clone https://github.com/FlavioImbertDomingos/voltage-toolkit.git
cd voltage-toolkit
docker compose up -d
```

| What | Where |
|---|---|
| Grafana dashboard | http://localhost:3000 (admin / admin) |
| Prometheus alerts | http://localhost:9090/alerts |
| Raw metrics | http://localhost:9743/metrics |
| The mock appliance's policy | https://localhost:8443/policy/clientPolicy.xml |

### Break it on purpose

```bash
curl -X POST localhost:8800/mock/scenario/slow            # p95 latency alert
curl -X POST localhost:8800/mock/scenario/errors          # error-rate alert
curl -X POST localhost:8800/mock/scenario/auth-fail       # auth-failure alert (rotated a secret?)
curl -X POST localhost:8800/mock/scenario/policy-down     # nothing can start: critical
curl -X POST localhost:8800/mock/scenario/keyserver-down  # key server alert
curl -X POST localhost:8800/mock/scenario/policy-changed  # drift: a format appeared
curl -X POST localhost:8800/mock/scenario/healthy
```

The mock's HTTPS certificate is valid for 20 days on purpose, so the certificate-expiry
warning is visible from the first scrape.

### What the metrics look like

```
voltage_policy_up{target="demo-prod"} 1.0
voltage_policy_info{district="prod",policy_id="prod-2026-09",sha256="04315d3301d6",target="demo-prod",version="7.0.2"} 1.0
voltage_tokenize_success{format="CC",identity="probe@demo.bank",target="demo-prod"} 1.0
voltage_tokenize_roundtrip_ok{format="CC",target="demo-prod"} 1.0
voltage_protect_seconds_bucket{format="CC",le="0.1",target="demo-prod"} 41.0
voltage_tokenize_errors_total{format="CC",kind="auth",target="demo-prod"} 0.0
voltage_policy_changes_total{target="demo-prod"} 0.0
voltage_certificate_expiry_timestamp_seconds{host="voltage:8443",subject="CN=voltage:8443,O=Mock Voltage",target="demo-prod"} 1.79e+09
voltage_keyserver_up{target="demo-prod",url="https://voltage:8443/vibekeys/"} 1.0
```

### Try the Ansible side

```bash
pip install ansible-core
export ANSIBLE_COLLECTIONS_PATH=$PWD
ansible-playbook flavioimbertdomingos.voltage.configure                  # writes voltage-config.yml (config as code)
VOLTAGE_SHARED_SECRET=probe-secret ansible-playbook flavioimbertdomingos.voltage.probe -e voltage_validate_certs=false
ansible-playbook flavioimbertdomingos.voltage.audit -e voltage_audit_validate_certs=false \
    -e voltage_audit_config_path=$PWD/ansible_collections/flavioimbertdomingos/voltage/playbooks/voltage-config.yml
curl -X POST localhost:8800/mock/scenario/policy-changed && ansible-playbook flavioimbertdomingos.voltage.audit \
    -e voltage_audit_validate_certs=false -e voltage_audit_fail_on_drift=true ...   # → "DRIFT: PHONE not declared"
```

(Point `voltage_policy_url` at `https://localhost:8443/...` when running outside compose.)

---

## Point it at a real appliance

**Exporter:**

```bash
cp config/voltage-exporter.example.yml config/voltage-exporter.yml   # your districts + probe identity
cp .env.example .env                                                 # VOLTAGE_SHARED_SECRET_PROD=...
docker compose up -d voltage-exporter prometheus alertmanager grafana
```

You need: a **dedicated, low-privilege probe identity** allowed to use the formats you probe,
its shared secret (or an LDAP user), network access to the policy host and Web Services host,
and the CA that signed the appliance certificate. Use **synthetic samples only** (test PANs).
See [docs/REAL-VOLTAGE.md](docs/REAL-VOLTAGE.md).

**Ansible:** see the [collection README](ansible_collections/flavioimbertdomingos/voltage/README.md).

---

## What you get

| Signal | Metric / rule | Why it matters |
|---|---|---|
| Can apps tokenize right now? | `voltage_tokenize_success`, `VoltageTokenizationFailing` | The only question that matters at 3 a.m. |
| Is the data coming back right? | `voltage_tokenize_roundtrip_ok`, `VoltageRoundTripMismatch` | A wrong detokenize silently corrupts data |
| How slow? | `voltage_protect_seconds` histogram, `VoltageLatencyHigh` (p95) | Checkout latency budgets |
| How often does it fail? | `voltage_tokenize_probes_total{result}`, `VoltageErrorRateHigh` | Intermittent failures apps retry around |
| Why did it fail? | `voltage_tokenize_errors_total{kind=auth\|http\|timeout\|connection\|mismatch}` | "Somebody rotated the shared secret" vs "the box is down" |
| Can new apps start? | `voltage_policy_up`, `VoltagePolicyUnreachable` | Every client downloads the policy at startup |
| Did someone change the config? | `voltage_policy_changes_total`, `VoltagePolicyChanged` | PCI change control; drift |
| Will TLS break on Tuesday? | `voltage_certificate_expiry_timestamp_seconds`, `VoltageCertificateExpiring*` | The #1 cause of "everything stopped" |
| Are key servers up? | `voltage_keyserver_up` | New identities and key rotation depend on them |

18 alert rules with runbook-style descriptions (unit-tested with promtool), Alertmanager
routing with inhibition, a Grafana dashboard.

---

## Repository map

```
voltage-toolkit/
├── docker-compose.yml                  one command → mock + exporter + Prometheus + Alertmanager + Grafana
├── exporter/                           voltage-exporter (Python; pip-installable; Dockerfile; tests)
├── mock-voltage/                       pretend appliance: clientPolicy.xml, REST + SOAP WS API, key server, scenarios
├── ansible_collections/flavioimbertdomingos/voltage/
│   ├── plugins/modules/                voltage_policy_facts, voltage_probe, voltage_district, voltage_identity, voltage_auth_method
│   ├── plugins/module_utils/           policy parser (shared with the exporter), WS client, desired-state backends
│   ├── roles/                          voltage_policy_audit, voltage_exporter
│   ├── playbooks/                      configure, audit, probe, deploy_exporter
│   ├── docs/ADAPTER.md                 the http / command adapter contract
│   └── tests/unit/                     modules run as Ansible runs them, against the mock
├── prometheus/                         config + 18 alert rules + promtool tests
├── alertmanager/ · grafana/            routing, inhibition, generated dashboard
└── docs/                               METRICS, ALERTS, REAL-VOLTAGE, ARCHITECTURE, FAQ
```

## Status & honesty

- **Voltage SecureData has no public API documentation.** The policy URL pattern
  (`https://voltage-pp-0000.<domain>/policy/clientPolicy.xml`) and the SOAP Web Services
  endpoint (`/vibesimple/services/VibeSimpleSOAP`, `ProtectFormattedData` / `AccessFormattedData`)
  are taken from OpenText's public integration guides and Vertica's SecureData docs. The
  **REST** field names and paths, and the **policy XML element names**, are configurable and the
  parser is deliberately forgiving — because the real ones are behind a support login.
  **If you run Voltage, a redacted `clientPolicy.xml` and one REST request/response is the most
  useful issue you can open.**
- The mock's "FPE" is a toy substitution, not FF1. It preserves shape so the probes and the
  round-trip logic are exercised for real; it is not cryptography.
- The config modules manage a desired-state document and adapters, because OpenText publishes
  no configuration API for the Management Console. That is stated plainly in the collection
  README rather than pretended away.
- Read-only towards the appliance, always: the exporter and the modules only ever call the
  policy download and the protect/access operations you'd use from any application.

## Sister projects

- [luna-exporter](https://github.com/FlavioImbertDomingos/luna-exporter) — Prometheus monitoring for Thales Luna HSMs
- [keycensus](https://github.com/FlavioImbertDomingos/keycensus) — cryptographic inventory / CBOM scanner (reads Voltage exports too)

## License

Apache-2.0, except the Ansible collection (`ansible_collections/…`), which is GPL-3.0-or-later as Ansible requires
for modules. Not affiliated with OpenText. "Voltage" and "SecureData" are trademarks of Open Text Corporation.
