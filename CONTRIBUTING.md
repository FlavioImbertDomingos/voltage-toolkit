# Contributing

The single most valuable contribution: **a redacted `clientPolicy.xml` and one REST protect
request/response from a real SecureData appliance**, with the version. It lets the policy
parser defaults and REST paths be corrected for everyone. Open an issue.

Also welcome: adapters for the `http` / `command` backends (see the collection's
`docs/ADAPTER.md`), Galaxy publication, a Helm chart, more scenarios in the mock.

## Dev setup

```bash
git clone https://github.com/FlavioImbertDomingos/voltage-toolkit.git && cd voltage-toolkit
python -m venv .venv && source .venv/bin/activate
pip install -e "./exporter[test]" ansible-core pytest ruff
make test test-collection lint
```

Run the pieces by hand:

```bash
(cd mock-voltage && MOCK_TLS_PORT=8443 MOCK_KEY_HOST=localhost:8443 python app.py &)
VOLTAGE_SHARED_SECRET=probe-secret VOLTAGE_PASSWORD=changeme \
  voltage-exporter -c <(sed 's#https://voltage:8443#https://localhost:8443#g' config/voltage-exporter.demo.yml) --once
export ANSIBLE_COLLECTIONS_PATH=$PWD
ansible-playbook flavioimbertdomingos.voltage.probe -e voltage_policy_url=https://localhost:8443/policy/clientPolicy.xml -e voltage_validate_certs=false
```

## Rules

- `exporter/voltage_exporter/policy.py` and the collection's `module_utils/policy.py` must stay identical (CI checks).
- Every new metric: mock scenario + test + `docs/METRICS.md`. Every alert: promtool test + `docs/ALERTS.md`.
- Modules: `ansible-test sanity` clean; unit test through `run_module()`; docs fragments for shared options.
- Never log or return secrets; `no_log: true` on secret params.
- ruff, line length 120.
