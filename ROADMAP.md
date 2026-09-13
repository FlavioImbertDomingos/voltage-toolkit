# Roadmap

Where voltage-toolkit goes next. Today it answers *"can an application protect a value right
now?"* — synthetic probes, policy drift, cert expiry. Everything below extends that in one of
three directions: **coverage** (is everything that should be protected actually protected),
**correctness** (is the protection right, not just alive), and **lifecycle** (the data, key and
platform changes that silently break a working deployment).

Each item states why it exists. Where the reason comes from a public OpenText source it is
cited; where it comes from reasoning about the architecture it is marked *(inference)*. Sizes
are rough: **S** ≈ a weekend, **M** ≈ a week of evenings, **L** ≈ a sustained project.

Nothing here changes the project's rule: **read-only towards the appliance**, synthetic test
data only, no production values.

## Status

| Item | Status |
|---|---|
| R1 key-version metrics | ✅ shipped — `feat: policy intelligence` |
| R2 small-domain linter | ✅ shipped — `feat: policy intelligence` |
| R3 silent-corruption probes | ✅ shipped — `feat: silent-corruption probes` |
| R4 policy propagation lag | ✅ shipped — `feat: fleet agreement` |
| R5 eFPE awareness | ✅ shipped — detection in `feat: policy intelligence`, determinism exclusion in `feat: silent-corruption probes` |
| R6 coverage metrics | ✅ shipped — `feat: coverage` |
| R7 data map | ✅ shipped — `feat: coverage` |
| R8 masking-quality probes | ✅ shipped — `feat: sdm checks` |
| R9 batch-job exporter | ✅ shipped — `feat: sdm checks` (inside voltage-exporter, not a sibling repo) |
| R16 console reachability | next |
| R17 enterprise integrations | ✅ shipped — `feat: enterprise integrations` |
| R10–R11, R13–R14 | planned |
| R12 version and lifecycle | ✅ shipped — `feat: policy intelligence` |
| R15 cross-region token equivalence | ✅ shipped — `feat: fleet agreement` |

---

## Horizon 1 — correctness of what we already monitor

### R1. Parse `keyNumberTable` and export key-version metrics · **S** · ✅ shipped

The live public demo policy at `voltage-pp-0000.dataprotection.voltage.com/policy/clientPolicy.xml`
shows the real rotation mechanism: a `<keyNumberConfig>` block with named `<keyNumberTable
name="PCI" currentNumber="4">` and one `<keyNumber number="N" algorithm="FPE" keySize="256"/>`
per version. The exporter's policy parser ignores this today.

Ship: `voltage_key_table_current_number{table}`, `voltage_key_versions_total{table}`,
`voltage_key_info{table,number,algorithm,key_size}`. Alerts on an unexpected `currentNumber`
increment (crypto period changed outside change control) and on a key size below policy
(e.g. anything not 256).

This is the single highest-value parser change: **key rotation becomes observable**, and it is
observable from a file every client already downloads.

### R2. Small-domain / weak-format linter · **S** · ✅ shipped

NIST SP 800-38G Rev. 1 promotes the minimum FPE domain size from a recommendation to a
**requirement of 10^6**, and it applies to FF1 — the mode Voltage uses — not just the broken
FF3. (Rev. 1 is still not final: 2019 IPD, second public draft Feb 2025.) A CVV, a state code,
a constrained date or a short alphanumeric format can fall under that bound and nobody notices,
because the appliance will happily encrypt it.

Ship: an Ansible module / exporter check that computes the domain size of every format in the
policy from its alphabet and length, and emits `voltage_format_domain_size{format}` plus
`VoltageFormatBelowMinimumDomain`. Runs entirely off `clientPolicy.xml` — no appliance calls.

This is the item most likely to be genuinely novel to a reviewer. It turns a standards
footnote into an alert.

### R3. Silent-corruption probes · **M** · ✅ shipped

Vertica's integration docs document three failure modes that produce **no error at all**:
decrypting with a mismatched format "produces incorrect plaintext"; `VoltageSecureAccess()` on
an unencrypted column "returns scrambled values"; the `auto` format on dates yields values like
`45-86-8651` that fail to cast downstream. These are the dangerous failures — wrong data lands
in the warehouse and passes format validation.

Ship, against synthetic data only:

- **format-mismatch probe** — protect under format A, attempt access under format B, assert the
  result is *not* equal to the original (`voltage_format_isolation_ok`);
- **double-protect probe** — protect an already-protected value, assert round-trip still
  recovers the ciphertext, not garbage;
- **determinism probe** — same plaintext + same identity + same tweak → same ciphertext
  (`voltage_determinism_ok`). Referential integrity across tables depends on this, and it is
  exactly what breaks when a key rotates underneath you.

### R4. Policy propagation lag · **M** · ✅ shipped

Vertica's `VoltageSecureRefreshPolicy()` response says it outright: *"Policy on other nodes will
be refreshed the next time a Voltage operation is run on them."* Policy changes propagate
**lazily and non-atomically** across a client fleet. Between a Management Console change and
full propagation, different nodes enforce different policy — the root of most "it works on one
node" tickets.

Ship: multi-target policy scraping with a fleet view —
`voltage_policy_sha256_agreement{targets}` and `VoltagePolicyFleetDivergent`, firing when two
probe locations report different policy hashes for longer than a grace window. Needs the mock
to grow a per-client-IP policy version so divergence is demonstrable in `docker compose`.

### R5. eFPE awareness · **S** · ✅ shipped

Embedded FPE embeds a key identifier in the ciphertext, so the same plaintext produces
different ciphertext per key epoch — which breaks equality joins. The vendor's answer is
`VoltageSecureProtectAllKeys()`, returning one row per active key.

Ship: detect eFPE formats in the policy, exclude them from the determinism probe (they will
legitimately fail it), and export `voltage_efpe_formats` so the dashboard can show which
columns are join-unsafe. Getting this wrong is how a monitoring tool cries wolf.

---

## Horizon 2 — coverage, and the SDM/discovery seam

This is the half the toolkit does not touch at all. SecureData answers *"can this app protect a
value?"* Structured Data Manager and Core Data Discovery & Risk Insights answer *"where does
sensitive data live, and is it classified, masked, retained or archived?"* Nobody monitors the
seam, and the seam is where audits are failed.

### R6. Coverage metrics from a classification feed · **M** · ✅ shipped

Discovery output is a list of columns classified as PAN / SSN / PII. Join it against the policy
facts and the keycensus inventory and emit
`voltage_coverage_columns_total{state="protected|cleartext|unknown"}`, with
`VoltageUnprotectedSensitiveColumn` firing on a newly classified sensitive column that no
format covers.

PCI scope drift, detected in Prometheus rather than in next year's ROC. Input format should be
a plain CSV contract (`system,schema,table,column,classification,confidence`) so it works with
SDM, Core Data Discovery, or a hand-built inventory — do not couple to a product with no public
API.

*Design note, resolved:* keycensus inventories keys, certificates and endpoints; coverage is
about data columns. The join lives here (`coverage.py`, shared with the collection); keycensus
can consume its output.

### R7. `voltage-data-map.yml` in config-as-code · **S** · ✅ shipped

`voltage-config.yml` already declares districts, formats, identities and auth methods. Add a
data map: column → format → district → consuming identity. Then `voltage_policy_audit` drifts in
both directions — a format defined in policy that nothing consumes (a dead format whose keys
still rotate), and a classified column the map never declared.

### R8. Masking-quality probes for test data · **M** · ✅ shipped

SDM's test-data masking fails in two specific, checkable ways: output that still looks live
(passes Luhn, or matches a real-PAN pattern), and broken referential integrity — the same input
masked differently across two tables, so joins silently drop rows. Format-Preserving Hash is
the irreversible primitive here, and irreversibility is itself testable.

Ship: `sdm_mask_leak_detected`, `sdm_mask_consistency_ok`, `sdm_fph_irreversible_ok`, run
against a non-prod schema. Small to build, instantly legible to an auditor.

### R9. Batch-job exporter for archive / masking runs · **M** · ✅ shipped

Archive, retention and masking runs are batch. They fail quietly; the first symptom is a
storage bill or a retention violation. `sdm_job_last_success_timestamp_seconds`,
`sdm_job_rows_total{result}`, `sdm_job_duration_seconds`,
`SDMJobStale` / `SDMJobFailing`. Same exporter skeleton as today — a second collector, or a
sibling repo if the config surface diverges.

---

## Horizon 3 — the things that break a working deployment

### R10. Detokenize-rate anomaly detection · **M**

Bulk `access` is the exfiltration pattern, and it is the one thing a crypto service is uniquely
placed to see. Per-identity counters with a step-change alert covers PCI DSS requirement 10 and
demonstrates thinking about *abuse* of the service, not just its uptime.

**Honest constraint, and it is the interesting part:** the Common Criteria Security Target's
audit scope is authentication and administrative actions — not per-transaction crypto. And
because the Simple API caches its derived key and performs FPE locally, a client can protect and
access millions of values **without contacting the appliance at all**. Appliance-side
per-operation logging is therefore architecturally impossible for cached workloads *(inference,
from the stateless-key design)*. So this item is really two:

- **R10a** — rate anomaly on what *is* observable: key-issuance and authentication events per
  identity.
- **R10b** — document the gap plainly in `docs/`, including the question to put to a vendor SE:
  *is there a per-protect/per-access transaction log, and does it survive client-side key
  caching?* An honest "here is what this cannot see" is worth more than a metric that implies
  coverage it does not have.

### R11. HSM root-of-trust and migration monitoring · **M**

Stateless key management anchors the district master secret in an HSM — that is the whole
root of trust, and there is no per-key revocation. Two live pressures:

- nShield Connect XC was **retired from sale in October 2025**, with mainstream support ending
  **2027-12-31**. Voltage SecureData 7.1.1 with Entrust Security World client 13.6.15 is
  certified for nShield 5c (FIPS 140-3 Level 3, native PQC support).
- The identity/master-secret backup is the only thing between a district and unrecoverable
  data loss, and there are **two public restore defects** in the community wiki from the same
  week of Nov 2024.

Ship: join the existing `luna-exporter` work into a single "root of trust" dashboard row, and
add a **restore-drill freshness metric** — `voltage_identity_backup_restore_tested_timestamp`,
fed by a periodic tested-restore job. Restore-testing the identity backup is the highest-value
operational drill in this product, and nothing tracks whether it happened.

### R12. Version and lifecycle awareness · **S** · ✅ shipped

The policy file reports the appliance version (`<server name="SecureDataAppliance"
version="7.1.1.100286"/>`). OpenText publishes per-release support-end dates (DPP Foundation
CE 24.4 / v7.0.3 → 2027-11-30; Sentry CE 25.4 → 2028-01-31), and the CE YY.Q scheme now runs
alongside the old 6.x/7.x numbering.

Ship: `voltage_appliance_version_info` and a curated support-end table →
`voltage_support_end_timestamp_seconds`, `VoltageVersionApproachingEndOfSupport`. Also detect
SST3 (introduced in CE 24.4), because a tokenization-engine change is a detokenization
compatibility event, not a patch.

### R13. Sentry monitoring · **L**

Sentry is the no-code path — proxy / ICAP / JDBC / ODBC / SMTP interception for SaaS and COTS
apps that cannot be recompiled. It is a *network element in the data path*, which means it fails
like a proxy: TLS interception, latency, connection pool exhaustion, and the failure nobody
catches — **fail-open**, where interception silently stops and cleartext flows through.

Ship eventually: a Sentry probe that pushes a synthetic record through the intercepted path and
asserts it arrives protected (`sentry_interception_ok`). This is the highest-value probe in the
whole roadmap and also the hardest to build without a licence. Needs a mock Sentry first.

### R14. Crypto-agility / PQC posture · **L**

OpenText's public PQC position is that symmetric encryption is already quantum-resistant —
AES-256 retaining 128-bit security under Grover. That is true for FPE and SST. But the Common
Criteria Security Target also documents **IBE using Boneh–Franklin and Boneh–Boyen at
3072/4096-bit over RFC 5091 supersingular curves** — pairing-based, and *not* quantum-resistant.
No public OpenText material addresses this *(the gap is our analysis, not a published finding)*.

Ship: extend keycensus's CBOM output to classify every algorithm found in a Voltage policy by
quantum posture, and flag pairing-based IBE usage separately from symmetric FPE/SST. This is
the harvest-now-decrypt-later question for archived data, and it is the right thing for a CBOM
tool to answer.

### R15. Cross-region token equivalence probe (DR readiness) · **S** · ✅ shipped

The stateless design makes multi-region DR cheap — no token vault to replicate — but it depends
on three things being identical in both regions: the district master secret, the district domain
name, and the SST token tables. Miss any one and failover does not produce an outage. It
produces **silent divergence**: the DR region starts emitting tokens the primary cannot
detokenize, and nothing errors.

Ship: protect the same synthetic value against two targets and assert the outputs are
**identical** — `voltage_cross_target_equivalence_ok{a,b}` and `VoltageRegionDivergence`. One
assertion covers master-secret parity, district naming, token-table parity and format parity.

Also worth a cheap companion: alert when the **policy URL** resolves or certifies differently
per region. Clients cold-start by URL, so a failover that moves the web service but not the
policy host means existing clients keep running on cache while new processes cannot initialize —
an outage that arrives over hours and passes a naive failover test.

### R16. Management Console reachability · **S**

The Common Criteria Security Target states only **one Management Console instance is active per
deployment**. The data path is active/active; the control plane is not. A console outage costs
no transactions but blocks every policy change, new identity and audit review — and its database
is what the upgrade path backs up, which has its own documented failure mode.

Ship: `voltage_console_up` as a distinct series from `voltage_keyserver_up`, with a
lower-severity alert and a runbook line saying plainly that protection is unaffected. Monitoring
that cries "Voltage is down" for a control-plane outage trains people to ignore it.

### R17. Enterprise integrations: PagerDuty and Splunk · **S** · ✅ shipped

A bank does not run Grafana and Alertmanager as the system of record. It runs a paging platform
and a SIEM, and the platform team's question is "does your thing feed ours cleanly?" The answer
should be yes without the toolkit learning a single vendor name.

Shipped: Alertmanager receivers for **PagerDuty** (Events API v2, key from a file, severity /
class / component mapped from labels, auto-resolve) and **Splunk** (HEC raw endpoint, token from a
file, every alert via a `continue: true` route so Splunk has the full firing/resolved history);
`log_format: json` in the exporter — one structured event per target per cycle, hashes and
booleans only — for a log forwarder; a commented `remote_write` stanza for metrics; and a
stdlib **mock** of both APIs so the compose stack proves delivery end to end (CI asserts the
seeded `SDMMaskLeak` reached both). `docs/INTEGRATIONS.md` has the Splunk searches worth keeping.

Deliberately not done: a Splunk app / dashboards XML, and PagerDuty service provisioning via
Terraform. Both are the platform team's, not the toolkit's.

---

## Non-goals

- **Writing to the appliance.** No configuration pushes, no key operations, no detokenization of
  real data. The Ansible config modules manage a desired-state document and adapters precisely
  because OpenText publishes no configuration API.
- **Claiming PCI compliance.** OpenText's own tokenization overview concedes that a token vault
  functions as a key; by symmetry, so do SST token tables. Scope reduction is a QSA judgment,
  not a property of the math, and this project will not assert otherwise.
- **Reimplementing FF1.** The mock's FPE is a shape-preserving toy and stays one. Anyone who
  needs real FPE needs a licence.
- **Shipping real PANs, anywhere, ever.**

## How to contribute to this roadmap

The most useful contribution remains unchanged: if you run Voltage, **a redacted
`clientPolicy.xml` and one real REST request/response**. R1, R2, R5 and R12 all parse structures
that are currently inferred from a single public demo policy and a handful of integration
guides. The REST surface is asserted by OpenText's datasheets but has no published endpoint
paths, verbs or schemas anywhere public — only the SOAP WSDL at
`/vibesimple/services/VibeSimpleSOAP`.

## Sources

- NIST SP 800-38G and Rev. 1 (2nd public draft, Feb 2025) — FF1, FF3-1, minimum domain size
- Common Criteria Security Target, SecureData Appliance 7.0.2 (Sept 2025) — components,
  stateless KDF, districts, identities, audit scope, IBE algorithms
- Live public demo policy — `voltage-pp-0000.dataprotection.voltage.com/policy/clientPolicy.xml`
- Vertica SecureData integration docs — eFPE, `VoltageSecureProtectAllKeys`, policy refresh
  semantics, silent-corruption modes
- OpenText Greenplum and SQL-to-XML integration guides — client config, trustStore, SOAP
- OpenText DPP release notes (CE 24.4, CE 25.4) and the nShield 5c certification post (Aug 2026)
