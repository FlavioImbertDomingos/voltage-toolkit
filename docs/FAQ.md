# FAQ

**Is it safe to run against production Voltage?**
It does what any application does: downloads the policy, calls protect/access with a synthetic
value. Use a dedicated probe identity limited to the probed formats, agree the interval with the
Voltage owners, and keep the secret in `.env` or a secret store. Nothing writes to the appliance.

**Does the probe create tokens in the vault / token table?**
For FPE formats, no — FPE is stateless. For SST tokenization formats a token is generated per
probe; use a test sample and an identity scoped to a test format, or probe only FPE formats.

**Why not just monitor the appliance's CPU / SNMP?**
Because "the box is up" and "an application can tokenize a PAN in under 200 ms right now" are
different questions, and only the second one pages the right person.

**Which Voltage versions?**
Built against publicly documented interfaces of SecureData Enterprise 6.x/7.x (policy download,
VibeSimpleSOAP). REST paths and policy element names are configurable because the full spec is
behind a support login. Report what your appliance answers and the defaults will improve.

**Why is "configuration" a YAML file and not a real change on the appliance?**
OpenText publishes no configuration API for the Management Console. The modules manage a
desired-state document (config as code) and can push through a site adapter (`http` or
`command` backend). Drift detection against the live policy works today; enforcement needs an
adapter your site builds — the contract is one page.

**Can I run the exporter without Docker?**
`pip install ./exporter`, then `voltage-exporter -c config.yml`. `--once` runs a single cycle and
prints a human summary — handy in a pipeline or a runbook.

**Can I use the collection without the exporter?**
Yes. `voltage_policy_facts`, `voltage_probe` and the audit role are independent.

**How do I get the collection?**
`ansible-galaxy collection install git+https://github.com/FlavioImbertDomingos/voltage-toolkit.git#/ansible_collections/flavioimbertdomingos/voltage`
(Galaxy publication is on the roadmap.)

**License / trademarks?**
Apache-2.0. Voltage and SecureData are trademarks of Open Text Corporation; no affiliation.
