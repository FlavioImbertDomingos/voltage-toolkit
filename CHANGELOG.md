# Changelog

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
