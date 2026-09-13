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

## What the policy says about the cryptography

All from `clientPolicy.xml` alone — no protect/access calls, so these work with a read-only,
unauthenticated probe. The policy schema is not public; the parser is forgiving about attribute
names (see `policy.py`) and emits nothing rather than guessing when the file does not say enough.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_key_table_current_number` | gauge | `table` | `currentNumber` of a `<keyNumberTable>` — **this increments on key rotation** |
| `voltage_key_table_versions` | gauge | `table` | Key versions listed in the table (old numbers stay so old ciphertext still decrypts) |
| `voltage_key_info` | gauge | `table`, `number`, `algorithm`, `key_size` | One series per key version, always 1 |
| `voltage_key_current_size_bits` | gauge | `table` | Key size of the current key (0 if the policy does not say) |
| `voltage_key_rotations_total` | counter | `table` | Times `currentNumber` changed since exporter start |
| `voltage_format_domain_size` | gauge | `format` | Estimated FPE domain: `radix ** (length − preserved chars)`, minimum length if a range; only when computable |
| `voltage_format_below_minimum_domain` | gauge | `format` | 1 if the domain is under NIST SP 800-38G Rev. 1's 10^6 floor for FF1 |
| `voltage_policy_format_efpe` | gauge | `format` | 1 for embedded-FPE formats — ciphertext differs per key epoch, so equality joins on the column are unsafe |
| `voltage_appliance_version_info` | gauge | `version`, `major`, `minor` | Appliance version from `<server version=…/>`, always 1 |
| `voltage_support_end_timestamp_seconds` | gauge | `version`, `release` | End of vendor maintenance for that version — only for versions in the built-in table or `exporter.support_end` in config |

Why the domain size matters: a 16-digit card format that preserves BIN(6) and last 4 encrypts
6 digits — a domain of exactly 10^6, right at the floor. An SSN format that keeps the last 4
encrypts 5 digits — 10^5, *under* it. The appliance will encrypt both without complaint.

## Tokenization probes (`protect` then `access`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_tokenize_success` | gauge | `format`, `identity` | 1 if the last round-trip succeeded |
| `voltage_tokenize_probes_total` | counter | `format`, `result` (success / failure) | Round-trips run. Both `result` series exist from the first cycle (the failure one at 0), so ratios are 0 rather than absent on a healthy target |
| `voltage_tokenize_errors_total` | counter | `format`, `kind` (auth / http / timeout / connection / mismatch / other) | Failures by cause; every kind is pre-created at 0 |
| `voltage_protect_seconds` | histogram | `format` | protect latency (buckets 10 ms – 10 s) |
| `voltage_access_seconds` | histogram | `format` | access latency |
| `voltage_protect_last_seconds` / `voltage_access_last_seconds` | gauge | `format` | Last observed latency |
| `voltage_tokenize_roundtrip_ok` | gauge | `format` | 1 if `access(protect(x)) == x` |
| `voltage_tokenize_format_preserved` | gauge | `format` | 1 if the token kept the sample's length and character classes (FPE) |

## Integrity probes — the failures that produce no error

Each of these returns HTTP 200 and plausible-looking data on a real appliance. The ordinary
round-trip probe stays green through all of them.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_integrity_ok` | gauge | `check`, `format`, `against` | 1 if the check passed. `check` ∈ `determinism` (protect(x) == protect(x); **skipped for eFPE**), `double_protect` (access(protect(protect(x))) == protect(x)), `format_isolation` (a token made under `format`, accessed under `against`, must not yield the plaintext — an error counts as isolation working) |
| `voltage_integrity_checks_total` | counter | `check`, `result` (pass / fail / error) | Checks run; `error` = could not evaluate (e.g. protect itself failed) |

Configure per target under `integrity:` — each check can be turned off, and `isolation_pairs`
overrides the default pairing (each FPE probe against the next one, round-robin).

## Coverage — classified sensitive columns × data map × live policy

See [COVERAGE.md](COVERAGE.md). Evaluated once per cycle when `coverage:` is configured; no
`target` label.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_coverage_up` | gauge | — | 1 if the feed and data map were read and evaluated |
| `voltage_coverage_columns` | gauge | `state` (protected / unmapped / broken / unknown), `classification` | Classified columns per state. Every (state, class) pair exists, at 0 if empty |
| `voltage_coverage_column_info` | gauge | `state`, `system`, `schema`, `table`, `column`, `classification`, `reason` | One series per column that is **not** protected; capped by `coverage.max_named_columns` |
| `voltage_coverage_dead_format` | gauge | `district`, `format` | 1 for a format offered by the district that no column and no declared identity uses |
| `voltage_coverage_feed_rows`, `voltage_coverage_map_entries`, `voltage_coverage_unclassified_mappings`, `voltage_coverage_errors` | gauge | — | Sizes and input problems |
| `voltage_coverage_feed_mtime_seconds` | gauge | — | Modification time of the classification feed (→ `voltage:coverage_feed_age_days`) |

## Structured Data Manager — masked data and jobs

See [SDM.md](SDM.md). No `target` label; `check` is the configured check name.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_sdm_check_up` | gauge | `check`, `kind` | 1 if the source was read and the check evaluated |
| `voltage_sdm_mask_ok` | gauge | `check`, `kind` (leak / consistency / constant) | 1 if the masking check passed |
| `voltage_sdm_mask_rows` | gauge | `check`, `kind` | Rows examined |
| `voltage_sdm_mask_hits` | gauge | `check`, `kind` | leak: canary / looks-live matches; consistency: inconsistently masked keys; constant: 1 if all identical |
| `voltage_sdm_job_last_success_timestamp_seconds` | gauge | `check`, `job` | Last successful finish (→ `voltage:sdm_job_hours_since_success`) |
| `voltage_sdm_job_last_finished_timestamp_seconds` | gauge | `check`, `job` | Most recent finish, any status |
| `voltage_sdm_job_last_status` | gauge | `check`, `job`, `status` | Most recent status, always 1 |
| `voltage_sdm_job_last_rows` | gauge | `check`, `job` | Rows processed by the most recent run |
| `voltage_sdm_job_stale` / `voltage_sdm_job_failing` | gauge | `check`, `job` | 1 if no success within `expect_every` / latest run failed |

## Fleet agreement — several vantage points, one district

Targets that share a `fleet:` name are expected to be the same district seen from different
places (two appliances behind a load balancer, primary and DR). These series have no `target`
label — they are about the fleet.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `voltage_fleet_agreement` | gauge | `fleet`, `check`, `key` | 1 if every member agrees. `check` ∈ `policy` (configuration fingerprint: formats, auth, key tables, version — **not** hostnames), `version`, `key_table` (`key` = table; `currentNumber` equal), `token` (`key` = format; the same synthetic sample protects to the same value on every member) |
| `voltage_fleet_members` | gauge | `fleet`, `check`, `key` | Members that reported; agreement is only evaluated with ≥ 2 |
| `voltage_fleet_member_diverged` | gauge | `fleet`, `check`, `key`, `target` | 1 for the member(s) disagreeing with the fleet majority |

Token comparison is by SHA-256 of the protected value; the exporter never keeps or exports a
token. `check="token"` failing while every member round-trips fine on its own is the DR-readiness
finding: a region built from its own district instead of the shared backup.

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
| `voltage:sdm_job_hours_since_success` | Hours since an SDM job last succeeded |
| `voltage:coverage_feed_age_days` | Age of the classification feed |
| `voltage:support_days_remaining` | Days until the running appliance version leaves vendor maintenance (negative = out of support) |
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
