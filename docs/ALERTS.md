# Alerts reference

Rules: [`prometheus/alerts/voltage.rules.yml`](../prometheus/alerts/voltage.rules.yml), unit-tested by
`voltage.rules.test.yml` (`promtool test rules`).

| Alert | Fires when | for | Severity | What to do |
|---|---|---|---|---|
| `VoltageExporterDown` | exporter not scraped | 2m | critical | Check the exporter container / service |
| `VoltageProbesStale` | no probe cycle in 5 min | 1m | warning | Loop stuck or every call timing out; read exporter logs |
| `VoltagePolicyUnreachable` | `voltage_policy_up == 0` | 2m | critical | New app instances cannot start. Check the policy host, load balancer, DNS (`voltage-pp-0000`), TLS |
| `VoltageKeyServerDown` | key server URL failing | 2m | critical | Cached keys keep working; new identities / rotations fail. Check `/vibekeys` host |
| `VoltageConsoleUnreachable` | `voltage_console_up == 0` | 5m | warning | **Control plane only** — tokenization is unaffected. No policy change, new identity or audit review until fixed; do not page, do fix before the next change window |
| `VoltageTokenizationFailing` | round-trip failing | 2m | critical | Look at `voltage_tokenize_errors_total{kind}`: auth → credential rotated; http → appliance error; timeout/connection → network or load |
| `VoltageAuthFailures` | any `kind="auth"` error in 10m | — | warning | Probe identity's secret rejected: rotated secret, LDAP change, identity disabled |
| `VoltageRoundTripMismatch` | `access(protect(x)) != x` | — | critical | **Data integrity.** Stop writes; check district / key configuration before tokens are persisted |
| `VoltageFormatIsolationBroken` | token made under A detokenizes under B | — | critical | **Data exposure.** Two formats share a key or an identity is over-authorized; anyone allowed format B can read format A data. Incident |
| `VoltageNonDeterministic` | `protect(x) != protect(x)` | — | critical | **Referential integrity.** Joins on the column silently drop rows. Rotation without eFPE, per-call tweak, client bug. eFPE formats are excluded on purpose |
| `VoltageDoubleProtectCorrupts` | `access(protect(protect(x))) != protect(x)` | 5m | warning | An ETL step that protects twice would corrupt silently. Check format definition and client version |
| `VoltageRegionDivergence` | fleet members protect the same value differently | — | critical | **DR divergence.** Same policy, different master secret / token tables. Do not fail over until fixed |
| `VoltagePolicyFleetDivergent` | fleet members serve different policy configuration | 10m | warning | Lazy per-node propagation is normal for minutes, not tens of minutes |
| `VoltageFleetKeyTableSkew` | `currentNumber` differs across members | 10m | warning | A rotation reached some members only; finish or roll back before any failover |
| `VoltageFleetVersionSkew` | members on different appliance versions | 30m | info | Fine mid-upgrade, not as steady state |
| `VoltageUnprotectedSensitiveColumn` | classified column with no data-map entry | 30m | warning | **PCI scope drift.** Map it or dispute the classification; named in `voltage_coverage_column_info` |
| `VoltageBrokenProtectionMapping` | mapped, but format not offered / identity not declared or not allowed | 10m | critical | The app believes it tokenizes; the appliance will refuse. Fix the map, the policy or the identity |
| `VoltageDeadFormat` | format offered, used by nothing | 24h | info | Retire it or map what uses it |
| `VoltageClassificationFeedStale` | feed older than 7 days | — | warning | Coverage is only as current as discovery |
| `VoltageCoverageInputsUnreadable` | `voltage_coverage_up == 0` | 15m | warning | Missing/invalid feed or data map; see exporter logs |
| `SDMMaskLeak` | a canary (or live-looking value) in masked data | — | critical | **Non-prod holds production data.** Re-mask before anyone gets the environment |
| `SDMMaskInconsistent` | same key masks differently across tables | 30m | warning | Joins in the test environment silently drop rows; re-mask the tables together |
| `SDMMaskConstant` | every masked value identical | 30m | warning | A fill-with-X job; the column is useless for testing |
| `SDMJobStale` | no success within `expect_every` | 1h | warning | Archive / retention / masking runs fail quietly |
| `SDMJobFailing` | latest run failed | — | warning | Check the job's own log |
| `SDMSourceUnreadable` | check cannot read its source | 15m | warning | DB / credentials / query / export file |
| `VoltageIdentityActivitySpike` | key requests ≥ `spike_ratio` × baseline for one identity | 5m | warning | New batch job, restart storm, rotated secret retried, or keys pulled for every format at once — the control-plane shadow of bulk detokenization. Match to a change or job schedule |
| `VoltageIdentityAuthFailures` | ≥ 10 `auth_fail` in a window | 5m | warning | A secret rotated and one client missed it, or credential guessing; the client host in the audit export names the source |
| `VoltageNewIdentityActive` | identity active, never seen in baseline | — | info | Expected after onboarding; otherwise ask who created it (a console admin action) |
| `VoltageUndeclaredIdentity` | active but not in `declared_identities` | 10m | warning | Rulebook behind reality (fix config-as-code) or something nobody approved |
| `VoltageIdentityAuditStale` | newest audit event older than 2 windows | 15m | warning | Export/forwarding stopped; the identity alerts are blind |
| `VoltageIdentityAuditUnreadable` | audit export unreadable | 15m | warning | DB / credentials / query / export file |
| `VoltageRestoreDrillNeverTested` | no successful tested restore on record | 1h | warning | Schedule the drill (docs/ROOT-OF-TRUST.md); an unrestorable identity backup means every token is unrecoverable |
| `VoltageRestoreDrillOverdue` | last success older than `max_age` | 1h | warning | Run the drill; version, firmware or Security World may have changed since |
| `VoltageRestoreDrillFailed` | most recent attempt failed | — | critical | Assume the district cannot be rebuilt until it passes; check the two public restore defects first |
| `VoltageRestoreDrillEvidenceUnreadable` | evidence source unreadable | 1h | warning | Fix the source before trusting the freshness alert either way |
| `VoltageErrorRateHigh` | > 5 % failures over 10m | 5m | warning | Intermittent errors apps are retrying around |
| `VoltageLatencyHigh` | p95 protect > 500 ms | 5m | warning | Appliance load, key server, network path, key rotation in progress |
| `VoltageFormatNotPreserved` | token shape ≠ sample shape | 2m | warning | Wrong format bound to the identity, or a tokenization format used where FPE expected |
| `VoltagePolicyChanged` | policy hash changed | — | info | Expected after a change window; otherwise investigate (PCI DSS 12.3.3) |
| `VoltageCertificateExpiringSoon` | 7 ≤ days < 30 | — | warning | Schedule renewal; every client validates this cert |
| `VoltageCertificateExpiringCritical` | days < 7 | — | critical | Renew now |
| `VoltageTlsHandshakeFailing` | `voltage_tls_up == 0` | 5m | warning | Host down, port filtered, cipher/cert problem |
| `VoltageKeyRotated` | `currentNumber` of a key table changed | — | info | Expected in a crypto-period change window; otherwise investigate. eFPE columns now hold two ciphertext epochs |
| `VoltageWeakCurrentKey` | current key < 256 bits | 10m | warning | Rotate to a 256-bit key number; the vendor's PQC argument depends on it |
| `VoltageFormatBelowMinimumDomain` | FPE domain < 10^6 | 10m | warning | NIST SP 800-38G Rev. 1 floor. CVV, last-4 SSN, state codes: use SST / FPH / AES with a schema change instead |
| `VoltageVersionApproachingEndOfSupport` | < 180 days of vendor maintenance | — | warning | Plan the upgrade; **test the identity/master-secret restore first** |
| `VoltageVersionOutOfSupport` | maintenance ended | — | critical | No security fixes; PCI DSS 6.3.3 finding |

Alertmanager routing (`alertmanager/alertmanager.yml`): mismatch / format-isolation /
non-determinism / region-divergence / masking-leak / tokenization-failing / policy-unreachable page immediately; inhibition stops symptom storms (policy down silences
tokenize alerts; tokenize-failing silences error-rate/latency/auth for the same format).
Receivers: `pager` → PagerDuty Events API v2, `splunk` → every alert (firing and resolved) to
Splunk HEC via a `continue: true` route, `default` → Slack/email. Keys come from files under
`alertmanager/secrets/`; the demo ones point at the `mock-integrations` container. See
[INTEGRATIONS.md](INTEGRATIONS.md).

Thresholds are in the rule expressions — edit, then `promtool test rules` and
`curl -X POST localhost:9090/-/reload`.
