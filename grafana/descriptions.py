"""What every panel on the dashboard means, why it is there, and where its number comes from.

build_dashboard.py attaches each entry as the panel's Grafana `description` (the (i) tooltip in
the panel header) and renders the same text into docs/DASHBOARD.md, so the tooltip, the docs
and the panel can never disagree. The build fails if a panel has no entry.

Each entry: (what the panel shows, why it matters, where the data comes from).
Write for the person who has never seen Voltage: an on-call engineer at 3 a.m., an auditor,
or an interviewer. The metric names are in docs/METRICS.md; the alerts in docs/ALERTS.md.
"""

ROWS = {
    "Can we tokenize right now?": (
        "The 3 a.m. row. Every tile here is the answer to one question an on-call engineer asks "
        "first, computed from the exporter's own synthetic round-trips in the last probe cycle. "
        "Green across the board means applications can tokenize and detokenize *right now*; "
        "nothing else on the dashboard matters until this row is green."
    ),
    "Latency & errors": (
        "How the service behaves over time, not just this instant. Latency and error ratio are "
        "computed from Prometheus histograms and counters the exporter increments on every probe; "
        "the recording rules in prometheus/alerts/voltage.rules.yml pre-compute p95 and error ratio."
    ),
    "Configuration & certificates": (
        "What the appliance is currently offering and when TLS will break. All of it is read from "
        "clientPolicy.xml (the file every client downloads at startup) and from TLS handshakes to "
        "each host — no privileged access, nothing the appliance would not tell any client."
    ),
    "What the policy says about the crypto": (
        "Findings that need no probe at all: parsed straight from the policy file. Key rotation, "
        "formats too small to be safe, eFPE formats that cannot be joined, key sizes and the vendor "
        "support clock. These are the questions a crypto reviewer asks and the appliance never "
        "answers on its own."
    ),
    "Fleet agreement — do all members give the same answers?": (
        "Targets that share a `fleet:` name in the exporter config are supposed to be the same "
        "district seen from different places: two appliances behind a load balancer, or prod and "
        "DR. The exporter asks each of them the same question and alerts when the answers differ. "
        "The stateless design makes members cheap to keep identical — which is exactly why nobody checks."
    ),
    "Coverage — is every classified sensitive column protected?": (
        "The join nobody owns: a discovery tool (Structured Data Manager, Core Data Discovery, a "
        "spreadsheet) says where the sensitive columns are; voltage-data-map.yml says which format "
        "and identity protect each one; the live policy says what actually exists. Every classified "
        "column lands in exactly one state. This is PCI scope drift, visible this week instead of in "
        "next year's assessment."
    ),
    "Structured Data Manager — masked data and jobs": (
        "Did masking actually mask, and did the batch job run? Read from the masked non-production "
        "database itself (read-only, via SQL or CSV) and from the job history table. Planted canaries, "
        "not Luhn checks, are the honest test: FPE with checksum preservation is Luhn-valid by design."
    ),
    "Identity activity — what the appliance can see (auth + key issuance)": (
        "Who is asking the appliance for keys, how often, and did that just change. Read from the "
        "appliance's audit export. Be precise about the limit: clients cache keys and run FPE locally, "
        "so the appliance cannot count individual protect/access calls — but every identity must "
        "authenticate and obtain keys, and that is what this row watches. docs/VISIBILITY.md has the "
        "full argument."
    ),
    "Root of trust — HSM (luna-exporter) and the identity backup restore drill": (
        "The district master secret lives in an HSM and there is no token vault to rebuild from: the "
        "identity backup is the only thing between a district and the permanent loss of every token. "
        "This row pairs the HSM's health (from the sister project luna-exporter) with proof that the "
        "backup restores. HSM panels read 'No data' until a luna-exporter scrape job exists — on purpose."
    ),
}

PANELS = {
    # ------------------------------------------------------------------ row 1
    "Policy server": (
        "UP if the exporter could download clientPolicy.xml from every selected target in the last cycle.",
        "Every SecureData client downloads this file at startup. While it is unreachable, running "
        "applications keep working on their cached copy, but no new pod, batch job or server can start "
        "tokenizing. This is the difference between 'degraded' and 'nothing new can start'.",
        "`voltage_policy_up` — HTTP GET of the policy URL by the exporter, every probe cycle.",
    ),
    "Key servers": (
        "UP if every key server URL listed inside the policy answered an HTTP request.",
        "Clients with cached keys keep working; anything that needs a *new* key — a new identity, a key "
        "rotation, a cold start — fails. A key server outage is silent until something restarts.",
        "`voltage_keyserver_up{url}` — the exporter GETs each `<KeyServer url>` it finds in the policy.",
    ),
    "Round-trips OK": (
        "Percentage of configured synthetic probes whose protect → access round-trip succeeded.",
        "The only question that matters at 3 a.m. The exporter does what an application does: protects "
        "a synthetic value, then accesses (detokenizes) the result. Below 100 % means at least one "
        "format on at least one target cannot tokenize.",
        "`voltage_tokenize_success{target,format}` — one series per probe; success = both calls "
        "returned and the shape was preserved.",
    ),
    "Data integrity": (
        "OK if access(protect(x)) returned exactly x for every probe.",
        "A wrong detokenize is worse than an error: it returns HTTP 200 with the wrong data, and the "
        "application writes it to a database. This tile is the one that pages a human at any hour.",
        "`voltage_tokenize_roundtrip_ok` — byte-for-byte comparison of the original sample and the "
        "detokenized result.",
    ),
    "p95 protect (10m)": (
        "95th-percentile latency of the protect call over the last 10 minutes, worst target.",
        "Checkout and batch pipelines have latency budgets; tokenization sits inside them. A rising p95 "
        "with a flat p50 is the classic sign of a key server or network path in trouble.",
        "`voltage:protect_p95_seconds_10m` — recording rule over the `voltage_protect_seconds` histogram.",
    ),
    "Error rate (10m)": (
        "Share of probes that failed in the last 10 minutes, worst target/format.",
        "Intermittent failures that applications retry around never show up as an outage; they show up "
        "here. Above 5 % fires VoltageErrorRateHigh.",
        "`voltage:tokenize_error_ratio_10m` — failed / total from `voltage_tokenize_probes_total`. The "
        "exporter pre-creates the failure series at 0 so this reads 0 %, not 'No data', on a healthy stack.",
    ),
    "Nearest cert expiry": (
        "Days until the soonest-expiring TLS certificate among the policy host, Web Services host, key "
        "servers and any extra hosts.",
        "The number-one cause of 'everything stopped at once': every SecureData client validates the "
        "appliance certificate, so one expiry takes down every application simultaneously. Orange at "
        "30 days, red at 7.",
        "`voltage:certificate_days_until_expiry` — from `notAfter` of the certificate presented during "
        "the exporter's TLS handshake to each host.",
    ),
    "Formats in policy": (
        "Count of formats (FPE, tokenization, eFPE) the selected targets' policies offer.",
        "A sudden change is a configuration change somebody made in the Management Console. Compare "
        "with 'Policy changes (24h)'.",
        "`voltage_policy_formats{kind}` — parsed from `<FormatMappings>` and `<TokenizationFormats>` in "
        "clientPolicy.xml. Summed across selected targets.",
    ),
    "Policy changes (24h)": (
        "How many times the policy file's hash changed in the last 24 hours.",
        "PCI DSS change control: every policy change should match a ticket. A change outside a "
        "window is either drift or an unauthorised admin action.",
        "`voltage_policy_changes_total` — incremented when the SHA-256 of clientPolicy.xml differs from "
        "the previous cycle.",
    ),
    "Probe cycle": (
        "Wall-clock time the last full probe cycle took for the slowest target.",
        "If this approaches the probe interval, probes overlap and the exporter falls behind; it also "
        "reflects appliance responsiveness end to end.",
        "`voltage_probe_cycle_seconds` — measured by the exporter around the whole cycle.",
    ),
    "Last probe": (
        "Seconds since the last completed probe cycle.",
        "If this grows past a few intervals the dashboard is stale, and every other tile is showing "
        "old news. VoltageProbesStale fires at 5 minutes.",
        "`time() - voltage_probe_last_run_timestamp_seconds`.",
    ),
    "Mgmt Console": (
        "UP if the Management Console answered an HTTP request. Shown in orange (not red) when down.",
        "Control plane only. Only one console instance is active per deployment; its outage blocks "
        "policy changes, new identities and audit review — but not tokenization. An alert that cries "
        "'Voltage is down' for a control-plane outage trains people to ignore the one that matters, so "
        "this is deliberately a warning.",
        "`voltage_console_up` — GET of `console_url` from the target config (any answer below HTTP 500 "
        "counts as up; a login page is a healthy console).",
    ),
    "Silent-corruption checks": (
        "OK if the three integrity probes passed: determinism, double-protect, format isolation.",
        "Three failures that return HTTP 200 and corrupt data anyway: protect(x) ≠ protect(x) (joins "
        "silently break), protect(protect(x)) corrupting the value, and a token detokenizing under the "
        "wrong format (formats sharing a key). None of them shows as an error; all of them show here.",
        "`voltage_integrity_ok{check}` — extra protect/access calls the exporter makes each cycle.",
    ),
    # ------------------------------------------------------------------ row 2
    "protect latency p50 / p95 / p99": (
        "Latency distribution of the protect call, across all selected targets, 5-minute windows.",
        "The gap between p50 and p99 is the story: a flat p50 with a jumping p99 is a key server or "
        "connection-pool problem, not general load. The red line is the 500 ms alert threshold.",
        "`histogram_quantile` over `voltage_protect_seconds_bucket` — the exporter observes every "
        "protect call into a histogram.",
    ),
    "access latency p95 by format": (
        "95th-percentile latency of the access (detokenize) call, one line per target and format.",
        "Access is the call on the read path — customer lookups, statements, reports. A single format "
        "being slow points at that format's key table or a tokenization (SST) table lookup.",
        "`voltage:access_p95_seconds_10m` — recording rule over `voltage_access_seconds`.",
    ),
    "Error ratio by format (10m)": (
        "Failed probes as a share of all probes, per target and format, rolling 10 minutes.",
        "One format failing while the others succeed is a policy or identity permission problem, not an "
        "outage. Everything failing at once is the appliance, the network or a rotated secret.",
        "`voltage:tokenize_error_ratio_10m` — from `voltage_tokenize_probes_total{result}`.",
    ),
    "Failures by kind (per 10m)": (
        "Count of failed probes in the last 10 minutes, stacked by cause.",
        "'Why' before 'what': auth = somebody rotated the shared secret; http = the appliance returned "
        "an error; timeout / connection = network or load; mismatch = data integrity. The kind tells "
        "you which team to call.",
        "`voltage_tokenize_errors_total{kind}` — the exporter classifies every failure; every kind is "
        "pre-created at 0 so the panel shows flat lines, not 'No data', when healthy.",
    ),
    # ------------------------------------------------------------------ row 3
    "Formats offered by the policy": (
        "Every format the policy currently offers, with its kind (fpe, tokenization, efpe) per target.",
        "The list an application developer needs and an auditor asks for. Compare targets: a format "
        "present on one and missing on another is propagation lag or drift.",
        "`voltage_policy_format{format,kind}` — parsed from clientPolicy.xml each cycle.",
    ),
    "Certificates: days to expiry": (
        "Each TLS certificate the exporter saw, its subject, and days until it expires.",
        "The tile above shows the nearest; this table shows all of them so the renewal ticket names "
        "the right host. Key-server certificates are the ones people forget.",
        "`voltage:certificate_days_until_expiry{host,subject}` — from the TLS handshake to each host.",
    ),
    "Policy": (
        "District, policy id, policy hash, appliance version and target, one row per target.",
        "Two targets in the same district with different hashes may be fine (hostnames differ) or may "
        "be drift — the fleet row decides. The hash is the value to quote in a change ticket.",
        "`voltage_policy_info` — attributes of `<clientPolicy>` and `<server>` in the policy file.",
    ),
    # ------------------------------------------------------------------ row 4
    "Formats under NIST's 10^6 domain floor": (
        "Number of FPE formats whose input domain is smaller than one million values.",
        "NIST SP 800-38G Rev. 1 requires a domain of at least 10^6 for FF1. The appliance will happily "
        "encrypt a 5-digit domain (an SSN keeping its last four digits, a CVV): the ciphertext is then "
        "brute-forceable. Use SST, FPH or AES with a schema change instead.",
        "`voltage_format_below_minimum_domain` — radix^(length − preserved characters), computed from "
        "the format attributes in the policy.",
    ),
    "eFPE formats (not join-safe)": (
        "Number of formats that use embedded FPE (eFPE).",
        "eFPE embeds the key epoch in the ciphertext, so the same value protects differently after a "
        "rotation. Columns protected with it cannot be joined or deduplicated across epochs and are "
        "excluded from the determinism check for that reason.",
        '`voltage_policy_format_efpe` — `encryption="eFPE"` on the format in the policy.',
    ),
    "Key rotations (24h)": (
        "How many key tables changed their current key number in the last 24 hours.",
        "Rotation in Voltage is `currentNumber` ticking up in the policy — there is no other visible "
        "event. Expected in a crypto-period change window; otherwise investigate. eFPE columns now hold "
        "two ciphertext epochs.",
        "`voltage_key_rotations_total{table}` — incremented when `<keyNumberTable currentNumber>` changes.",
    ),
    "Weakest current key (bits)": (
        "Smallest key size among the *current* keys of all key tables.",
        "The vendor's post-quantum argument depends on AES-256 (128-bit security under Grover). A key "
        "table whose current key is 128 bits does not get that argument. Red below 256.",
        "`voltage_key_current_size_bits{table}` — the `size` attribute of the current key number in the policy.",
    ),
    "Days of vendor support left": (
        "Days until the running appliance version leaves OpenText maintenance.",
        "After that date: no security fixes, and a PCI DSS 6.3.3 finding. The version comes from the "
        "policy file, the dates from the release notes (built-in table plus `support_end` config).",
        "`voltage:support_days_remaining` — from `voltage_support_end_timestamp_seconds` and "
        "`<server version>` in the policy.",
    ),
    "Key tables": (
        "Each key table (PCI, PII, …) with its current key number, per target.",
        "The current number is the rotation state. Two targets in one district showing different "
        "numbers means a rotation reached one region and not the other — DR would then produce "
        "different tokens.",
        "`voltage_key_table_current_number{table}` — `<keyNumberConfig>` in clientPolicy.xml.",
    ),
    "FPE domain size per format": (
        "The computed input domain (number of possible values) for each FPE format, smallest first.",
        "Domain size is the brute-force budget of the ciphertext. Anything under 10^6 is flagged in the "
        "tile above; this table lets you see how far under, and which format to redesign.",
        "`voltage_format_domain_size{format}` — radix^(length − preserved) from the format definition.",
    ),
    "Appliance version": (
        "Running appliance version, major/minor split, and release name per target.",
        "The version is what the lifecycle clock and the support-end alert key on; it also confirms "
        "that all regions run the same build (the fleet row checks this too).",
        "`voltage_appliance_version_info` — `<server version>` in the policy file.",
    ),
    # ------------------------------------------------------------------ row 5
    "Tokens agree": (
        "OK if every member of every fleet protects the same synthetic value to the same token.",
        "The DR readiness test. Same policy, same formats, different master secret or token table → "
        "different tokens, and nothing errors. Failover would then write tokens production cannot "
        "detokenize. This pages a human.",
        '`voltage_fleet_agreement{check="token"}` — SHA-256 of each member\'s token, compared. The '
        "token itself is never stored.",
    ),
    "Policy agrees": (
        "OK if every fleet member serves the same policy *configuration* (formats, auth, key tables, version).",
        "Policy propagation is lazy and per node: after a Management Console change, nodes update when "
        "they next serve a request. Until then, different nodes enforce different policy.",
        '`voltage_fleet_agreement{check="policy"}` — a fingerprint that ignores hostnames and key-server '
        "URLs, which legitimately differ per region.",
    ),
    "Key tables agree": (
        "OK if each key table has the same current key number on every fleet member.",
        "A rotation that reached only one region: tokens issued there use a key the other region does "
        "not have yet.",
        '`voltage_fleet_agreement{check="key_table"}` — per-table comparison of `currentNumber`.',
    ),
    "Versions agree": (
        "OK if every fleet member reports the same appliance version.",
        "Mixed versions across regions are an upgrade in progress or one that was never finished; "
        "either way the support clock and behaviour differ per region.",
        '`voltage_fleet_agreement{check="version"}`.',
    ),
    "Diverged members": (
        "The specific targets that disagree with the majority of their fleet, and on which check.",
        "Names the odd one out so the runbook can start with the right appliance.",
        "`voltage_fleet_member_diverged{fleet,check,key,target} == 1`.",
    ),
    # ------------------------------------------------------------------ row 6
    "Unmapped sensitive columns": (
        "Classified sensitive columns (PAN, SSN, …) with no entry in voltage-data-map.yml.",
        "Discovery says PAN, the data map says nothing: the column is in scope and unprotected. This "
        "is the PCI scope-drift finding, surfaced by the toolkit instead of the assessor.",
        '`voltage_coverage_columns{state="unmapped"}` — classification feed × data map join, every cycle.',
    ),
    "Broken mappings": (
        "Columns that are mapped, but whose mapping no longer holds.",
        "The format is no longer offered by the district, the identity is not declared or not allowed "
        "the format, or the classification disagrees with the feed. Protected on paper only.",
        '`voltage_coverage_columns{state="broken"}` — data map checked against the live policy and '
        "desired-state identities.",
    ),
    "Protected columns": (
        "Columns whose mapping checks out end to end: format exists, identity allowed.",
        "The number to put in the scope statement.",
        '`voltage_coverage_columns{state="protected"}`.',
    ),
    "Dead formats": (
        "Formats offered by the policy that no column and no identity references.",
        "Keys for them keep rotating and every rotation is a change to review — for nothing. Also a "
        "hint that something is protected outside the data map.",
        "`voltage_coverage_dead_format{district,format} == 1`.",
    ),
    "Feed age (days)": (
        "Days since the classification feed file was last modified.",
        "Discovery that has not run in months is not discovery. VoltageClassificationFeedStale fires "
        "when the feed is older than configured.",
        "`voltage:coverage_feed_age_days` — mtime of the classification CSV.",
    ),
    "Columns not protected": (
        "Every unmapped, broken or unknown column with its classification and the reason.",
        "The worklist: each row is either a data-map entry to add or a mapping to fix.",
        "`voltage_coverage_column_info{column,classification,state,reason}` — capped at "
        "`max_named_columns` to keep cardinality bounded.",
    ),
    # ------------------------------------------------------------------ row 7
    "Masking checks failing": (
        "Number of masking checks (leak, consistency, constant) currently failing.",
        "Non-production holding production-looking data is an incident, not a finding. Any value above "
        "zero means the masked environment should not be handed to developers until re-masked.",
        "`voltage_sdm_mask_ok{check,kind} == 0` — read from the masked database via SQL or CSV.",
    ),
    "Jobs stale": (
        "Masking / archive / retention jobs that have not succeeded within their expected interval.",
        "Batch jobs fail quietly; the first symptom is otherwise a storage bill or a retention "
        "violation.",
        "`voltage_sdm_job_stale{job}` — from the job-history table against `expect_every`.",
    ),
    "Jobs failing": (
        "Jobs whose most recent run failed.",
        "If it is the masking refresh, the masked environment may be partial — see the leak and "
        "consistency checks.",
        "`voltage_sdm_job_failing{job}` — status of the latest row per job in the job history.",
    ),
    "Sources unreadable": (
        "SDM checks whose database or export file could not be read this cycle.",
        "Every other SDM number is stale until this is zero; do not trust green tiles while this is red.",
        "`voltage_sdm_check_up == 0`.",
    ),
    "Masking checks": (
        "Every masking check with its kind and pass/fail.",
        "leak = a planted canary appeared in the masked copy; consistency = the same input masked "
        "differently across tables (joins silently drop rows); constant = every value identical (a "
        "fill-with-X job that 'worked').",
        "`voltage_sdm_mask_ok{check,kind}` with `voltage_sdm_mask_hits` for the count of offending rows.",
    ),
    "Jobs: hours since last success": (
        "Each job and how long ago it last succeeded, longest first.",
        "The table an operator reads before deciding whether last night's refresh actually happened.",
        "`voltage:sdm_job_hours_since_success` — recording rule over "
        "`voltage_sdm_job_last_success_timestamp_seconds`.",
    ),
    # ------------------------------------------------------------------ row 8
    "Identities active": (
        "Number of identities with at least one audit event in the current window.",
        "The size of the population the anomaly checks watch. A sudden jump is onboarding — or "
        "something enumerating identities.",
        "`voltage_identities_active` — from the appliance audit export (SQL or CSV).",
    ),
    "Spikes now": (
        "Identity/event pairs whose current-window count is a step change against their baseline.",
        "Key issuance stepping up for one identity is the control-plane shadow of bulk detokenization "
        "by anyone who did not already hold the keys — or a new batch job, or a rotated secret being "
        "retried. Match it to a change; if none, treat it as a precursor.",
        "`voltage_identity_activity_spike{identity,event} == 1` — current ≥ spike_ratio × median of "
        "the previous windows, and ≥ min_events.",
    ),
    "Auth failures (window)": (
        "Failed authentications across all identities in the current window.",
        "Benign: a secret rotated and one client was not updated. Malicious: credential guessing "
        "against a service identity. The client host in the audit export names the source.",
        '`voltage_identity_events{event="auth_fail"}`.',
    ),
    "New / undeclared": (
        "Identities active now that were never seen in the baseline period, plus identities active "
        "but absent from `declared_identities`.",
        "New identities are a Management Console admin action — someone created them. Undeclared ones "
        "mean the rulebook is behind reality or something nobody approved is authenticating.",
        "`voltage_identity_new` and `voltage_identity_undeclared`.",
    ),
    "Audit export age": (
        "Seconds since the newest event in the audit export.",
        "If the export stops flowing, every tile in this row is blind while staying green. Orange at "
        "one window, red at two.",
        "`voltage_identity_audit_age_seconds`.",
    ),
    "Key requests per window, by identity": (
        "Key-issuance events per identity in each window, over time.",
        "The shape of normal for each identity. A batch job is a daily pulse; a service is a flat "
        "line; a spike is a spike.",
        '`voltage_identity_events{event="key_request"}`.',
    ),
    "Current window vs baseline": (
        "Ratio of this window's count to the median of the previous windows, per identity and event.",
        "1.0 is normal; 40 is what the demo's batch-etl identity shows when it pulls keys for every "
        "format at once. Absent means the identity has no history yet.",
        "`voltage_identity_activity_ratio{identity,event}`.",
    ),
    # ------------------------------------------------------------------ row 9
    "Restore drills OK": (
        "Number of restore drills that are within their freshness limit and whose last attempt succeeded.",
        "A tested restore of the identity backup is the highest-value operational drill in this "
        "product: stateless keys have no vault to fall back on. Red means at least one district has "
        "not proved it can be rebuilt.",
        "`voltage_restore_drill_ok{drill,district}` — from the evidence the drill records (ops table or CSV).",
    ),
    "Drills overdue / never": (
        "Drills never tested, or whose last success is older than `max_age`.",
        "The backup may still be good; nobody has proved it recently, and the appliance version, HSM "
        "firmware or Security World may have changed since.",
        "`voltage_restore_drill_overdue`.",
    ),
    "Last drill failed": (
        "Drills whose most recent attempt failed.",
        "Until it passes, assume the district cannot be rebuilt after an HSM or appliance loss. Two "
        "public restore defects exist in the community wiki; check them before retrying.",
        "`voltage_restore_drill_last_failed`.",
    ),
    "HSMs up (luna_up)": (
        "UP if every HSM monitored by luna-exporter is reachable.",
        "The HSM holds the district master secret. Its outage does not stop cached clients, but it "
        "stops key derivation for anything new — and it is the root of trust for the whole product.",
        "`luna_up` from luna-exporter (scrape job commented in prometheus/prometheus.yml; 'No data' "
        "until it exists).",
    ),
    "HSM tamper events": (
        "Tamper events reported by the HSMs.",
        "Any non-zero value is a physical-security incident and, depending on the HSM's policy, may "
        "have zeroised the keys.",
        "`luna_hsm_tamper_events` from luna-exporter.",
    ),
    "HSM FIPS mode": (
        "UP if every HSM reports FIPS mode enabled.",
        "The compliance claim for the root of trust rests on this flag.",
        "`luna_hsm_fips_mode_enabled` from luna-exporter.",
    ),
    "Restore drills: days since last tested restore": (
        "Each drill, its district, and days since the last successful tested restore.",
        "The number an assessor asks for and nobody usually has.",
        "`voltage:restore_drill_days_since_success` — recording rule over "
        "`voltage_identity_backup_restore_tested_timestamp_seconds`.",
    ),
    "HSM inventory (luna-exporter)": (
        "Model, firmware, serial and label of each HSM.",
        "Firmware changed and no restore drill since is the combination worth a change ticket. Also "
        "the place to see an nShield XC that leaves support in 2027.",
        "`luna_hsm_info` from luna-exporter.",
    ),
}
