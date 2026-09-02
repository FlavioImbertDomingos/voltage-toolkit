# Pointing it at a real Voltage SecureData deployment

## What you need from the Voltage team

1. **The policy URL** for each district you monitor:
   `https://voltage-pp-0000.<domain>/policy/clientPolicy.xml` (the `voltage-pp-0000` hostname
   convention is what SecureData clients resolve; yours may differ).
2. **The Web Services host** — usually the same appliance; REST under `/vibesimple/rest/...`,
   SOAP at `/vibesimple/services/VibeSimpleSOAP`. Confirm which is enabled and the exact REST
   paths; set `api`, `rest_path_protect`, `rest_path_access`, `auth_in_body` in config accordingly.
3. **A dedicated probe identity** (e.g. `monitor-probe@<domain>`) with a shared secret, or an
   LDAP user, allowed to use *only* the formats you probe. Never reuse an application identity.
4. **The CA** that signed the appliance certificates (`ca_cert:` in config).
5. **Network**: TCP 443 (or your WS port) from the exporter host to the policy host, WS host and
   key servers.

## Samples

Use synthetic values that exercise each format but are not real data:

| Format family | Sample |
|---|---|
| Credit card | `4111111111111111`, `5500000000000004`, `4242424242424242` |
| SSN | `123-45-6789` (reserved / never issued) |
| Alphanumeric | `Order7781X` |
| SST tokenization | a test PAN with `tokenization: true` |

## Probe rate

Each probe = 2 Web Services calls per interval. 3 formats × 30 s = 6 calls/min per district —
noise next to production traffic, but agree it with the Voltage team and pick an interval
accordingly (`interval_seconds`).

## Verify before you deploy

```bash
# policy reachable?
curl --cacert corp-ca.pem https://voltage-pp-0000.example.com/policy/clientPolicy.xml | head

# one REST protect (adjust path / auth to your appliance)
curl --cacert corp-ca.pem -u 'monitor-probe@example.com:SECRET' \
  -H 'content-type: application/json' \
  -d '{"identity":"monitor-probe@example.com","format":"CC","data":["4111111111111111"]}' \
  https://voltage-pp-0000.example.com/vibesimple/rest/v1/protect

# one-shot exporter run with your config
VOLTAGE_SHARED_SECRET_PROD=... voltage-exporter -c config/voltage-exporter.yml --once
```

If the REST call's shape differs from what the mock implements, set the `rest_path_*` /
`auth_in_body` options — and please open an issue with the redacted request/response so the
defaults improve for everyone.

## Hardening checklist

- [ ] Probe identity is separate, minimal, and its secret lives in `.env` / a secret store, never in YAML
- [ ] `ca_cert` set; `verify_tls: false` only in the lab
- [ ] Exporter port 9743 reachable only from Prometheus
- [ ] Interval agreed with the Voltage owners
- [ ] `VoltageRoundTripMismatch` and `VoltageTokenizationFailing` route to a pager
- [ ] `VoltagePolicyChanged` routes to the change-management channel
- [ ] Ansible `voltage_policy_audit` runs nightly with `voltage_audit_fail_on_drift: true` in a pipeline

## Kubernetes

Plain Deployment: image `ghcr.io/flavioimbertdomingos/voltage-exporter`, mount the config at
`/config/voltage-exporter.yml`, pass secrets as env from a Secret, annotate for scraping on 9743.
The `voltage_exporter` Ansible role covers Docker hosts and systemd VMs.
