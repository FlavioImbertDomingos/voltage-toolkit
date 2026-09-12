# Alerts reference

Rules: [`prometheus/alerts/voltage.rules.yml`](../prometheus/alerts/voltage.rules.yml), unit-tested by
`voltage.rules.test.yml` (`promtool test rules`).

| Alert | Fires when | for | Severity | What to do |
|---|---|---|---|---|
| `VoltageExporterDown` | exporter not scraped | 2m | critical | Check the exporter container / service |
| `VoltageProbesStale` | no probe cycle in 5 min | 1m | warning | Loop stuck or every call timing out; read exporter logs |
| `VoltagePolicyUnreachable` | `voltage_policy_up == 0` | 2m | critical | New app instances cannot start. Check the policy host, load balancer, DNS (`voltage-pp-0000`), TLS |
| `VoltageKeyServerDown` | key server URL failing | 2m | critical | Cached keys keep working; new identities / rotations fail. Check `/vibekeys` host |
| `VoltageTokenizationFailing` | round-trip failing | 2m | critical | Look at `voltage_tokenize_errors_total{kind}`: auth → credential rotated; http → appliance error; timeout/connection → network or load |
| `VoltageAuthFailures` | any `kind="auth"` error in 10m | — | warning | Probe identity's secret rejected: rotated secret, LDAP change, identity disabled |
| `VoltageRoundTripMismatch` | `access(protect(x)) != x` | — | critical | **Data integrity.** Stop writes; check district / key configuration before tokens are persisted |
| `VoltageFormatIsolationBroken` | token made under A detokenizes under B | — | critical | **Data exposure.** Two formats share a key or an identity is over-authorized; anyone allowed format B can read format A data. Incident |
| `VoltageNonDeterministic` | `protect(x) != protect(x)` | — | critical | **Referential integrity.** Joins on the column silently drop rows. Rotation without eFPE, per-call tweak, client bug. eFPE formats are excluded on purpose |
| `VoltageDoubleProtectCorrupts` | `access(protect(protect(x))) != protect(x)` | 5m | warning | An ETL step that protects twice would corrupt silently. Check format definition and client version |
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
non-determinism / tokenization-failing / policy-unreachable page immediately; inhibition stops symptom storms (policy down silences
tokenize alerts; tokenize-failing silences error-rate/latency/auth for the same format).

Thresholds are in the rule expressions — edit, then `promtool test rules` and
`curl -X POST localhost:9090/-/reload`.
