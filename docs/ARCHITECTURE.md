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
                 ├─ probes.run_integrity(): determinism, double-protect, format-isolation
                 │     (skips determinism for formats the policy marks eFPE)
                 ├─ client.certificate() for policy host, WS host, key servers, extras
                 └─ GET each key server URL
                 │
                 ▼
           metrics.apply(result)  ──► prometheus_client Gauges / Counters / Histograms
           fleet.evaluate(all results) ──► metrics.apply_fleet()   (targets sharing `fleet:` must agree)
           coverage_runner.run_coverage() ──► coverage.evaluate() ──► metrics.apply_coverage()
                 (classification CSV × voltage-data-map.yml × the districts' live formats)
           sdm.run_mask_check() / run_job_check() ──► metrics.apply_sdm()
                 (sources.py: one SELECT over any DB-API driver, or a CSV — read-only)
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

**Why the integrity probes:** the dangerous Voltage failures are not crashes. Vertica's own
docs list three that return wrong data with no error: decrypting under a mismatched format
"produces incorrect plaintext", accessing an unencrypted column "returns scrambled values", and
the `auto` date format yields values that fail to cast downstream. A round-trip probe cannot
see any of them — it asks one format one question. So `run_integrity()` asks the questions that
distinguish *working* from *correct*: is protection deterministic (joins depend on it), is a
doubly-protected value still reversible (ETL does that by accident), and is a token made under
one format unreadable under another (the whole point of formats being separate key spaces).
The mock has scenarios for the last two (`format-leak`, `nondeterministic`) precisely because
they leave every other metric green.

**Why compare across targets:** the stateless design makes two appliances in one district
cheap to keep identical — no vault to replicate — and that is exactly why nobody verifies it.
Two things drift silently: policy propagates lazily per node (Vertica: *"Policy on other nodes
will be refreshed the next time a Voltage operation is run on them"*), and a DR region built
from its own district instead of the restored backup has the same policy and a different master
secret, so it protects the same value to a different token while round-tripping perfectly on its
own. `fleet.evaluate()` compares, per fleet, a *configuration* fingerprint of the policy (not the
bytes — hostnames legitimately differ), each key table's `currentNumber`, the appliance version,
and the SHA-256 of each probe's token. One assertion covers master-secret parity, district
naming, token-table parity and format parity. It runs after every cycle, across all targets,
which is why the loop collects results before applying them.

**Why the coverage join lives here and not in keycensus:** keycensus inventories *keys,
certificates and endpoints*. Coverage is about *data columns* and which format protects them —
a different subject with different inputs (a discovery feed, a data map). Keeping it here also
means the audit role and the exporter share one stdlib module, exactly like the policy parser.
keycensus can consume the output later. See [COVERAGE.md](COVERAGE.md).

**Why the SDM checks read data, not SDM:** SDM has no public API, and masking quality is a
property of the *result*, not of the job that claims to have produced it. So `sdm.py` reads
masked rows and job history through one adapter (`sources.py`: SQL via any DB-API driver, or a
CSV export) and asks three questions of the data — did a planted canary survive, does the same
key mask the same way in every table, is the column a constant — plus when each job last
succeeded. The leak heuristic is off by default because FPE with checksum preservation is
Luhn-valid by design; canaries are the honest test. See [SDM.md](SDM.md).

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

`module_utils/policy.py` and `module_utils/coverage.py` are verbatim copies of the exporter's so the
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
