# Security

## Reporting
Email the maintainer (address on the GitHub profile); please don't open public issues for vulnerabilities.

## What this touches
A probe identity's shared secret (or an LDAP password) and network access to a production
tokenization service. The exporter's outputs include which formats and districts exist and
how fast tokenization is — operational data, not card data.

## What the project does
- Read-only towards the appliance: policy download, protect/access with synthetic samples. No management calls.
- Secrets from env vars / files only; `no_log` on Ansible secret parameters; the probe never logs protected values.
- TLS verification on by default; `verify_tls: false` is opt-in and documented as lab-only.
- The Ansible config modules never store secret values — only references (`secret_ref`).
- Non-root container; minimal dependencies.

## What you should do
- Use a dedicated probe identity limited to the probed formats; rotate its secret like any service credential.
- Restrict port 9743 to Prometheus.
- Use synthetic samples only. Never put real PANs / SSNs in a probe config.
- The mock appliance and demo secrets are for the demo stack only. Never expose them.
