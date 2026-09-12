# Changelog

## [Unreleased]

### Added
- **Fleet agreement** (roadmap R4, R15): targets sharing `fleet:` must agree. `voltage_fleet_agreement{check=policy|
  version|key_table|token}`, `voltage_fleet_members`, `voltage_fleet_member_diverged`; alerts `VoltageRegionDivergence`
  (critical, pages), `VoltagePolicyFleetDivergent` (10m), `VoltageFleetKeyTableSkew` (10m), `VoltageFleetVersionSkew`.
  Policy is compared by a configuration fingerprint (formats, auth, key tables, version), not bytes, so hostnames may
  differ. Tokens compared by SHA-256; never kept. Compose gains a second region `voltage-dr` (:8801/:8444) and the mock a
  `diverged-keys` scenario; `make scenario-dr`. `voltage_policy_facts` returns `config_fingerprint`.
- **Silent-corruption probes** (roadmap R3): `voltage_integrity_ok{check=determinism|double_protect|format_isolation}`
  and `voltage_integrity_checks_total`; alerts `VoltageFormatIsolationBroken` (critical, pages),
  `VoltageNonDeterministic` (critical, pages), `VoltageDoubleProtectCorrupts` (warning). Determinism is skipped for
  eFPE formats (completing R5). Per-target `integrity:` config with `isolation_pairs`. Mock scenarios `format-leak`
  and `nondeterministic`, and the mock's eFPE now actually changes ciphertext across key epochs while old ciphertext
  still decrypts.
- **Policy intelligence** (roadmap R1, R2, R5, R12) — everything below is read from `clientPolicy.xml` alone:
  - Key number tables: `voltage_key_table_current_number`, `voltage_key_table_versions`, `voltage_key_info`,
    `voltage_key_current_size_bits`, `voltage_key_rotations_total`; alerts `VoltageKeyRotated`, `VoltageWeakCurrentKey`.
  - Small-domain linter: `voltage_format_domain_size`, `voltage_format_below_minimum_domain` (NIST SP 800-38G Rev. 1's
    10^6 floor for FF1); alert `VoltageFormatBelowMinimumDomain`.
  - eFPE detection: `voltage_policy_format_efpe` (ciphertext differs per key epoch; equality joins unsafe).
  - Appliance version and support lifecycle: `voltage_appliance_version_info`, `voltage_support_end_timestamp_seconds`,
    recording rule `voltage:support_days_remaining`; alerts `VoltageVersionApproachingEndOfSupport`,
    `VoltageVersionOutOfSupport`. Built-in table holds the public dates; extend via `exporter.support_end` in config.
  - `--once` prints the appliance version, key tables and any format findings.
  - `voltage_policy_facts` (Ansible) now returns `server_version`, `key_tables`, `efpe_formats`, `format_domain_sizes`.
  - Mock: `<server>`, `<keyNumberConfig>`, format attributes (alphabet / length / preserved chars), an eFPE format,
    scenarios `key-rotated` and `weak-key`. The mock's SSN format keeps the last 4 on purpose so the small-domain
    alert is visible from the first scrape, like the 20-day certificate.
  - Grafana: a "What the policy says about the crypto" row.

## [0.1.0] - 2026-09-02

### Added
- voltage-exporter: synthetic protect/access round-trip probes (REST and SOAP), policy download + parse + change
  detection, key-server reachability, TLS certificate expiry; Prometheus histograms/counters/gauges; `--once` mode.
- Mock Voltage SecureData appliance (policy XML, REST + SOAP Web Services, key server, HTTPS, runtime scenarios).
- 18 Prometheus alert rules with promtool tests; Alertmanager routing with inhibition; generated Grafana dashboard.
- Ansible collection `flavioimbertdomingos.voltage`: `voltage_policy_facts`, `voltage_probe`, `voltage_district`,
  `voltage_identity`, `voltage_auth_method` (file / http / command backends, check mode, diff), roles
  `voltage_policy_audit` (drift report, optional probe, fail-on-drift) and `voltage_exporter` (docker / systemd),
  playbooks `configure`, `audit`, `probe`, `deploy_exporter`.
- CI: exporter tests on 3.11/3.12 against the live mock, collection unit tests + ansible-test sanity + playbook run,
  promtool, docker compose smoke test, GHCR image publish.
