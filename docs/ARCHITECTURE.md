# Architecture

## Exporter

```
config.yml ─► voltage_exporter.config.load()
                 │
                 ▼ every interval_seconds (background thread, one worker per target)
           probes.run_target(target)
                 ├─ client.fetch_policy()  ──► policy.parse_policy()   (formats, auth, key servers, sha256)
                 ├─ for each probe: client.protect() ─► client.access() ─► compare
                 ├─ client.certificate() for policy host, WS host, key servers, extras
                 └─ GET each key server URL
                 │
                 ▼
           metrics.apply(result)  ──► prometheus_client Gauges / Counters / Histograms
                 │
                 ▼
           /metrics  (start_http_server)
```

**Why a background loop, not probe-on-scrape:** the probes hit a production tokenization
service. Their rate must be a deliberate config value, not a side effect of how many
Prometheus instances (or engineers with curl) scrape `/metrics`.

**Why protect *and* access:** protect alone proves the API is up. access proves the *keys* are
right — a district pointed at the wrong key server can happily hand out tokens nobody can
reverse. `voltage_tokenize_roundtrip_ok` is the metric that catches that.

**Why hash the policy:** clientPolicy.xml is the only unauthenticated view of the district's
configuration. A hash change is either a change window or an incident.

## Collection

```
voltage_policy_facts ──► module_utils/client.fetch_policy + module_utils/policy.parse_policy
voltage_probe        ──► module_utils/client.ws_call (rest | soap)
voltage_district ┐
voltage_identity ├──► module_utils/desired_state.apply(module, kind, name, state, spec)
voltage_auth_method ┘        ├─ file backend     read-modify-write YAML/JSON, check mode, diff
                             ├─ http backend     GET / PUT / DELETE <url>/<kind>/<name>
                             └─ command backend  JSON on stdin → JSON on stdout
voltage_policy_audit role ─► voltage_policy_facts per district, diff vs voltage-config.yml, report, optional probe
voltage_exporter role      ─► config + env file + (docker run | venv + systemd)
```

`module_utils/policy.py` is a verbatim copy of `exporter/voltage_exporter/policy.py` so the
collection has zero third-party dependencies (Ansible module_utils cannot import pip packages).
The exporter's tests cover the parser; a CI step checks the two files are identical.

## Mock appliance

`mock-voltage/app.py` implements the documented touch-points (policy XML, REST + SOAP
protect/access, a key server path) with a toy shape-preserving substitution and runtime
scenarios. It is a demo/test fixture, not an emulator — it exists so the pipeline can be
built and tested without a licence.

## Adding a probe kind

1. Add a dataclass + `run_*` function in `probes.py`, call it from `run_target`.
2. Add metrics in `metrics.py` and set them in `apply()`.
3. Teach the mock to fail it (a scenario) and add a test in `exporter/tests`.
4. Document in `docs/METRICS.md`; add an alert + promtool test if it deserves one.
