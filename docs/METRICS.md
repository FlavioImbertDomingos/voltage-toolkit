# Metrics reference

All metrics carry `target` (the name you gave the district in config).

## Policy (`GET clientPolicy.xml`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_policy_up` | gauge | — | 1 if the policy downloaded and parsed |
| `voltage_policy_fetch_seconds` | gauge | — | Download time |
| `voltage_policy_info` | gauge | `district`, `version`, `policy_id`, `sha256` | Facts, always 1 |
| `voltage_policy_formats` | gauge | `kind` (fpe / tokenization) | Number of formats offered |
| `voltage_policy_format` | gauge | `format`, `kind` | One series per format, always 1 |
| `voltage_policy_auth_method` | gauge | `method` | One series per auth method |
| `voltage_policy_changes_total` | counter | — | Policy content hash changed since exporter start |
| `voltage_policy_last_change_timestamp_seconds` | gauge | — | When it last changed |

## Tokenization probes (`protect` then `access`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_tokenize_success` | gauge | `format`, `identity` | 1 if the last round-trip succeeded |
| `voltage_tokenize_probes_total` | counter | `format`, `result` (success / failure) | Round-trips run |
| `voltage_tokenize_errors_total` | counter | `format`, `kind` (auth / http / timeout / connection / mismatch / other) | Failures by cause |
| `voltage_protect_seconds` | histogram | `format` | protect latency (buckets 10 ms – 10 s) |
| `voltage_access_seconds` | histogram | `format` | access latency |
| `voltage_protect_last_seconds` / `voltage_access_last_seconds` | gauge | `format` | Last observed latency |
| `voltage_tokenize_roundtrip_ok` | gauge | `format` | 1 if `access(protect(x)) == x` |
| `voltage_tokenize_format_preserved` | gauge | `format` | 1 if the token kept the sample's length and character classes (FPE) |

## TLS and key servers

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_tls_up` | gauge | `host` | TLS handshake succeeded |
| `voltage_certificate_expiry_timestamp_seconds` | gauge | `host`, `subject` | notAfter of the presented certificate |
| `voltage_tls_version_info` | gauge | `host`, `version` | Negotiated TLS version |
| `voltage_keyserver_up` | gauge | `url` | Key server URL (from the policy) answered |

Hosts probed for TLS: the policy host, the Web Services host, every key server in the policy,
and `extra_tls_hosts` from config.

## Exporter

| Metric | Type | Meaning |
|---|---|---|
| `voltage_probe_cycle_seconds` | gauge | Time the last full cycle for the target took |
| `voltage_probe_last_run_timestamp_seconds` | gauge | When the target was last probed |
| `voltage_probe_cycles_total` | counter | Cycles completed |
| `voltage_exporter_build_info` | info | Version |

## Recording rules

| Rule | Meaning |
|---|---|
| `voltage:tokenize_error_ratio_10m` | failures / all probes over 10 min, per target and format |
| `voltage:protect_p95_seconds_10m` / `voltage:access_p95_seconds_10m` | p95 latency over 10 min |
| `voltage:certificate_days_until_expiry` | days left per certificate |

## Useful queries

```promql
# Is anything broken anywhere?
min(voltage_tokenize_success) == 0

# Slowest format right now
topk(3, voltage:protect_p95_seconds_10m)

# Why are probes failing?
sum by (kind) (increase(voltage_tokenize_errors_total[1h]))

# Certificates expiring within 30 days
voltage:certificate_days_until_expiry < 30
```
