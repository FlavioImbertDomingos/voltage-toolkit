# What a Voltage monitor can and cannot see (roadmap R10b)

This page exists because the most natural request — "alert me when someone detokenizes a
million card numbers" — is one the appliance cannot fulfil for most workloads, and a monitor
that implies otherwise is worse than none. Here is where the line runs, why, what the toolkit
does on the visible side of it, and the question to put to a vendor SE.

## The line

Voltage SecureData is a **stateless key-management** design. A client authenticates as an
identity, the key server derives the key for that identity, format and key epoch from the
district master secret, and hands it over. From then on the **Simple API caches the derived
key and performs FPE locally**. Protect and access are pure computation on the client; the
appliance is not in the loop.

Consequences, stated plainly:

* A client with a cached key can protect or access **millions of values without contacting the
  appliance at all**. There is no appliance-side per-operation record to count. This is not a
  logging setting; it follows from the design.
* What the appliance *does* observe is the control-plane edge of every workload:
  **authentication** (every identity must authenticate to obtain keys) and **key issuance**
  (one request per identity, format and key epoch — more when caches expire, when the client
  restarts, or when the client is *asking for keys it did not have before*).
* The Common Criteria Security Target's audit scope is authentication and administrative
  actions — consistent with the above, and a useful confirmation that the vendor does not claim
  per-transaction audit either.
* The **Web Services** path (REST/SOAP, the one the exporter probes) is different: each
  protect/access is an HTTP call to the appliance, so *that* traffic is countable at the web
  tier — but Web Services is the minority path in a mature deployment, and the log is an HTTP
  access log, not a security audit trail.

The inference — "appliance-side per-operation logging is architecturally impossible for
cached workloads" — is ours, from the published design. We have not seen a vendor document
that says it in those words, which is exactly why the SE question below matters.

## What the toolkit does on the visible side (R10a)

`identity_activity:` in the exporter reads the appliance's audit export (the Management
Console's audit database, a syslog sink that landed in a table, or a CSV) through the same
read-only source adapter as the SDM checks, and for every identity and event type computes
the count in the current window and a **baseline**: the median of the same count over the
previous N windows.

| Series | Meaning |
|---|---|
| `voltage_identity_events{identity,event}` | events this window (`auth_ok`, `auth_fail`, `key_request`, …) |
| `voltage_identity_events_baseline{identity,event}` | median per window over the previous N |
| `voltage_identity_activity_ratio{identity,event}` | current / baseline (absent with no history) |
| `voltage_identity_activity_spike{identity,event}` | 1 when current ≥ `spike_ratio` × baseline and ≥ `min_events` |
| `voltage_identity_new{identity}` | active now, never seen in the baseline period |
| `voltage_identity_undeclared{identity}` | active now, absent from `declared_identities` |
| `voltage_identity_audit_age_seconds` | age of the newest audit event — the freshness of the whole feed |

Alerts: `VoltageIdentityActivitySpike` (key issuance stepped up — a new batch job, a restart
storm, a rotated secret being retried, or someone pulling keys for every format at once),
`VoltageIdentityAuthFailures`, `VoltageNewIdentityActive`, `VoltageUndeclaredIdentity`,
`VoltageIdentityAuditStale`, `VoltageIdentityAuditUnreadable`.

Why this is still worth having: bulk detokenization by a *new* actor needs keys it does not
have, so key issuance is the control-plane shadow of exfiltration by anyone who is not already
a long-running, fully-cached client. It also catches the mundane failure that precedes most
incidents — a service identity failing authentication thirty times from a host nobody
recognises.

What it will not catch: a compromised long-running application that already holds the keys
it needs. For that, the controls are elsewhere — the application's own access logging, the
database's audit of who read the token column, egress monitoring — and the toolkit says so
rather than pretending.

## The question for the vendor SE

> Is there a per-protect / per-access transaction log on the appliance or in the client
> library, and does it survive client-side key caching? If the client SDK can emit one, where
> does it go, what identity and format fields does it carry, and what is the performance cost
> at 10⁴ operations per second?

If the answer is "the SDK can log locally", that log is the input `identity_activity:` should
read instead of the appliance audit export — the module does not care which, only that rows
are (timestamp, identity, event). If the answer is "no", this page is the documentation of
record for why the monitor stops where it does.

## Where the demo gets its data

`demo/seed_nonprod.py` seeds a `voltage_audit` table with 48 hours of steady authentication
and key requests for two application identities, then in the last hour: `batch-etl@demo.bank`
requests keys at 40× its baseline, and an identity nobody declared
(`svc-reporting@demo.bank`) fails authentication thirty times from an unknown client. Both
show up as alerts within the first minute of `docker compose up`.
