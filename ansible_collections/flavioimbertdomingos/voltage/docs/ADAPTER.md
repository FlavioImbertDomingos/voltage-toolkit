# Site adapter contract

The `voltage_district`, `voltage_identity` and `voltage_auth_method` modules can push desired
state to a **site adapter** instead of (or as well as) the YAML document. An adapter is
whatever your site can build to actually change the Management Console: a small service
that drives the MC's web UI, wraps a vendor CLI, calls an internal API, or files a change
ticket. This page is the whole contract.

Objects are addressed as `<kind>/<name>` where `kind` ∈ `districts`, `identities`, `auth_methods`.
The `spec` is the module's parameters minus `name`, `state`, `backend`, with `null`s removed.

## `http` backend

```yaml
backend:
  type: http
  url: https://voltage-adapter.internal/api     # base
  token: "{{ vault_adapter_token }}"            # sent as  Authorization: Bearer <token>
  validate_certs: true
  ca_path: /etc/pki/tls/certs/corp-ca.pem
```

| Call | Meaning | Expected response |
|---|---|---|
| `GET <url>/<kind>/<name>` | current state | `200` + JSON object, or `404` if absent |
| `PUT <url>/<kind>/<name>` (JSON body = merged spec) | create or update | `2xx` |
| `DELETE <url>/<kind>/<name>` | remove | `2xx` (including `204`) |

The module computes `changed` by comparing the `GET` result with the desired object, so the
adapter must return what it stores. In check mode only `GET` is called.

Minimal adapter (Flask, 25 lines) — the same shape the unit tests use:

```python
from flask import Flask, jsonify, request
app = Flask(__name__); store = {}

@app.get("/api/<kind>/<name>")
def get(kind, name):
    obj = store.get((kind, name))
    return (jsonify(obj), 200) if obj is not None else (jsonify({}), 404)

@app.put("/api/<kind>/<name>")
def put(kind, name):
    store[(kind, name)] = request.get_json()
    # ... here: drive the Management Console / vendor tooling ...
    return jsonify(store[(kind, name)])

@app.delete("/api/<kind>/<name>")
def delete(kind, name):
    store.pop((kind, name), None)
    return "", 204
```

## `command` backend

```yaml
backend:
  type: command
  command: /usr/local/bin/voltage-adapter        # anything executable; runs on the controller
```

The executable receives one JSON document on **stdin**:

```json
{"kind": "identities", "name": "payments@example.com", "state": "present",
 "spec": {"district": "prod", "auth_method": "SharedSecret", "formats": ["CC"]},
 "check_mode": false}
```

and must print one JSON document on **stdout** and exit 0:

```json
{"changed": true, "before": null, "after": {"district": "prod", "auth_method": "SharedSecret", "formats": ["CC"]},
 "message": "created via mc-cli"}
```

Non-zero exit = task failure (stderr is shown). Honour `check_mode` by reporting what *would*
change without doing it.

## Secrets

Neither backend ever receives a secret value. Identities and auth methods carry a
`secret_ref` (a vault path / secret name); resolving it is the adapter's job, using the
credentials *it* holds.
