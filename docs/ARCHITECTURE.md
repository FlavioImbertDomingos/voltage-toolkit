# Architecture

## Exporter

```
config.yml ─► voltage_exporter.config.load()
                 │
                 ▼ every interval_seconds (background thread, one worker per target)
           probes.run_target(target)
                 ├─ client.fetch_policy()  ──► policy.parse_policy()   (formats, auth, key servers, sha256,
                 │                                                       key tables, server version, format attrs)
                 ├─ for each probe: client.protect() ─► client.access() ─► compare
                 ├─ client.certificate() for policy host, WS host, key servers, extras
                 └─ GET each key server URL
                 │
                 ▼
           metrics.apply(result)  ──► prometheus_client Gauges / Counters / Histograms
                 ├─ policy.format_domain_size() / is_efpe()   per format  (R2, R5)
                 ├─ key tables → current number, rotation counter, key size  (R1)
                 └─ lifecycle.support_end(server_version)       (R12; built-in table + config overrides)
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

**Why read the key tables:** `<keyNumberTable currentNumber=…>` is how the appliance actually
rotates keys (old numbers stay listed so old ciphertext still decrypts). A `currentNumber` change
is a crypto-period event, and it is visible in a file every client already fetches. The exporter
keeps the last seen number per table and counts changes.

**Why estimate domain sizes:** FF1 is a permutation on the format's domain, and NIST SP 800-38G
Rev. 1 makes a minimum domain of 10^6 a requirement. The appliance will encrypt a 5-digit domain
without complaint. `format_domain_size()` computes `radix ** (length − preserved chars)` only
when the policy carries enough attributes; unknown means no series, never a guess. The attribute
names it recognises are the mock's vocabulary plus obvious spellings — the real schema is not
public, which is why the parser stays forgiving.

**Why lifecycle from the policy:** `<server version=…/>` names the running version; OpenText's
release notes give end-of-maintenance dates. `lifecycle.py` holds the public ones and merges
`exporter.support_end` from config, longest version prefix first.

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
