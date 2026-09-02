# flavioimbertdomingos.voltage

Ansible collection for OpenText Voltage SecureData: facts, synthetic probes, configuration
as code with drift detection, and a role that deploys
[voltage-exporter](../../../exporter).

```bash
ansible-galaxy collection install git+https://github.com/FlavioImbertDomingos/voltage-toolkit.git#/ansible_collections/flavioimbertdomingos/voltage
```

## What's in it

| Plugin / role | Kind | Needs credentials? | What it does |
|---|---|---|---|
| `voltage_policy_facts` | module | no | Downloads and parses `clientPolicy.xml`: formats, auth methods, key servers, version, hash |
| `voltage_probe` | module | yes (probe identity) | protect → access round-trip with a synthetic sample; latency; fails on mismatch |
| `voltage_district` | module | no | Declares a district's expected formats / auth methods / key servers |
| `voltage_identity` | module | no | Declares an identity (district, auth method, formats, owner, secret *reference*) |
| `voltage_auth_method` | module | no | Declares an auth method and its settings (LDAP URL, rotation period ...) |
| `voltage_policy_audit` | role | optional | Compares the declared config with the live policy; JSON + Markdown report; can fail on drift |
| `voltage_exporter` | role | yes (env file) | Deploys voltage-exporter as a container or systemd service |

Playbooks: `configure`, `audit`, `probe`, `deploy_exporter` (run with `ansible-playbook flavioimbertdomingos.voltage.<name>`).

## The honest part: how "configuration" works

OpenText publishes **no configuration API** for the SecureData Management Console. So the
three `voltage_*` config modules manage a **desired-state document** — a YAML file you keep
in git, exactly like DNS zones or firewall rules — through a pluggable *backend*:

| backend | what happens on `state: present` | when to use |
|---|---|---|
| `file` (default) | read-modify-write `voltage-config.yml`; idempotent; check mode + `--diff` | today, everywhere |
| `http` | `GET`/`PUT`/`DELETE <url>/<kind>/<name>` on a site adapter | you built a small adapter in front of the Management Console |
| `command` | run a site executable with a JSON request on stdin | you wrap vendor CLI tooling |

The audit role then fetches the district's live `clientPolicy.xml` and diffs it against the
document: **formats, auth methods and key servers are directly observable** in the policy;
identities are not (they're checked against the formats the district offers and reported as
declared). Playbooks written against `file` work unchanged when an adapter exists. The
adapter contract is in [docs/ADAPTER.md](docs/ADAPTER.md).

## 60-second example

```yaml
- hosts: localhost
  connection: local
  tasks:
    - flavioimbertdomingos.voltage.voltage_district:
        name: prod
        policy_url: https://voltage-pp-0000.example.com/policy/clientPolicy.xml
        formats: [CC, SSN, {name: CC-ST-64O, kind: tokenization}]
        auth_methods: [SharedSecret, LDAP]
        key_servers: ["https://voltage-pp-0000.example.com/vibekeys/"]
        backend: {type: file, path: voltage-config.yml}

    - flavioimbertdomingos.voltage.voltage_identity:
        name: payments@example.com
        district: prod
        auth_method: SharedSecret
        formats: [CC, CC-ST-64O]
        secret_ref: vault:secret/voltage/prod/payments
        owner: payments-platform
        backend: {type: file, path: voltage-config.yml}

- hosts: localhost
  connection: local
  roles:
    - role: flavioimbertdomingos.voltage.voltage_policy_audit
      vars:
        voltage_audit_config_path: voltage-config.yml
        voltage_audit_fail_on_drift: true
        voltage_audit_probe: true
        voltage_audit_probe_identity: monitor-probe@example.com
        voltage_audit_probe_secret: "{{ lookup('env', 'VOLTAGE_SHARED_SECRET') }}"
```

Run it nightly and you have a PCI DSS 12.3.3-friendly record of what the district offers,
who is supposed to use it, and proof that tokenization worked at 02:00.

## Testing

```bash
python -m pytest ansible_collections/flavioimbertdomingos/voltage/tests/unit   # from the repo root
ansible-test sanity --docker                                                  # inside the collection dir
```

Unit tests run the modules as Ansible does (JSON on stdin) against the mock appliance in
`mock-voltage/`, plus an in-process HTTP adapter and a command adapter.

## Requirements

ansible-core ≥ 2.15, Python ≥ 3.8 on the controller (modules run on the controller with
`connection: local`; nothing is installed on the appliance). No extra Python packages.

## License

GPL-3.0-or-later (see `COPYING`) — Ansible requires collection modules to be GPLv3+ because they link against
`ansible.module_utils.basic`. The rest of the repository (exporter, mock, dashboards) is Apache-2.0.
Not affiliated with OpenText. "Voltage" and "SecureData" are OpenText trademarks.
