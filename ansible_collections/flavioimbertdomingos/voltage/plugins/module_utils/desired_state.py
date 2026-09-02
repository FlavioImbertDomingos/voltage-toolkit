# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# Apache-2.0
"""Config-as-code for Voltage SecureData objects (identities, districts, auth methods).

OpenText publishes no configuration API for the SecureData Management Console. So
this collection manages a **desired-state document** -- the same way you would keep
firewall rules or DNS zones in git -- and pushes it through a *backend*:

  file      (default) read/modify/write a YAML or JSON document. Idempotent, check-mode
            and --diff aware. The audit role compares this document with the live
            clientPolicy.xml to detect drift.
  http      PUT / DELETE JSON to  <url>/<kind>/<name>  on a site adapter you run in
            front of the Management Console (contract in docs/ADAPTER.md).
  command   run a site executable with a JSON request on stdin (wrap vendor CLIs);
            it answers with JSON {"changed": bool, "before": {}, "after": {}}.

All three share one code path, so a playbook written against the `file` backend
today works unchanged when a real adapter exists.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # noqa: F821

import json
import os
import tempfile

try:
    import yaml

    HAS_YAML = True
except ImportError:  # pragma: no cover - PyYAML is an Ansible dependency
    HAS_YAML = False

from ansible.module_utils.urls import open_url

KINDS = ("identities", "districts", "auth_methods")

BACKEND_ARG_SPEC = dict(
    backend=dict(
        type="dict",
        default={"type": "file"},
        options=dict(
            type=dict(type="str", default="file", choices=["file", "http", "command"]),
            path=dict(type="path"),
            url=dict(type="str"),
            token=dict(type="str", no_log=True),
            validate_certs=dict(type="bool", default=True),
            ca_path=dict(type="path"),
            timeout=dict(type="int", default=15),
            command=dict(type="str"),
        ),
    ),
)


def _load_doc(path):
    if not os.path.exists(path):
        return {k: {} for k in KINDS}
    with open(path) as fh:
        text = fh.read()
    if not text.strip():
        return {k: {} for k in KINDS}
    doc = yaml.safe_load(text) if HAS_YAML else json.loads(text)
    doc = doc or {}
    for k in KINDS:
        doc.setdefault(k, {})
        if isinstance(doc[k], list):  # tolerate list-of-{name:...} style
            doc[k] = {e.get("name"): {kk: v for kk, v in e.items() if kk != "name"} for e in doc[k]}
    return doc


def _dump_doc(path, doc):
    if path.endswith(".json"):
        text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    else:
        text = "# Voltage SecureData desired state -- managed by flavioimbertdomingos.voltage\n" + yaml.safe_dump(doc, sort_keys=True, default_flow_style=False)
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".voltage-", dir=d)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _clean(spec):
    """Drop None values so 'unset' parameters don't create diffs."""
    return {k: v for k, v in spec.items() if v is not None}


def apply(module, kind, name, state, spec):
    """Reconcile one object. Returns a result dict for module.exit_json()."""
    backend = module.params.get("backend") or {"type": "file"}
    btype = backend.get("type", "file")
    spec = _clean(spec)
    if btype == "file":
        return _apply_file(module, backend, kind, name, state, spec)
    if btype == "http":
        return _apply_http(module, backend, kind, name, state, spec)
    if btype == "command":
        return _apply_command(module, backend, kind, name, state, spec)
    module.fail_json(msg="unknown backend type %r" % btype)


# ---------------------------------------------------------------- file
def _apply_file(module, backend, kind, name, state, spec):
    path = backend.get("path")
    if not path:
        module.fail_json(msg="backend.path is required for the file backend")
    doc = _load_doc(path)
    before = doc[kind].get(name)
    if state == "absent":
        after = None
    else:
        after = dict(before or {})
        after.update(spec)
    changed = before != after
    result = dict(changed=changed, kind=kind, name=name, before=before, after=after, backend="file", path=path)
    if module._diff:
        result["diff"] = {"before": {name: before} if before is not None else {}, "after": {name: after} if after is not None else {}}
    if changed and not module.check_mode:
        if after is None:
            doc[kind].pop(name, None)
        else:
            doc[kind][name] = after
        _dump_doc(path, doc)
    return result


# ---------------------------------------------------------------- http adapter
def _apply_http(module, backend, kind, name, state, spec):
    url = backend.get("url")
    if not url:
        module.fail_json(msg="backend.url is required for the http backend")
    endpoint = "%s/%s/%s" % (url.rstrip("/"), kind, name)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if backend.get("token"):
        headers["Authorization"] = "Bearer " + backend["token"]
    kw = dict(headers=headers, validate_certs=backend.get("validate_certs", True), ca_path=backend.get("ca_path"),
              timeout=backend.get("timeout", 15), http_agent="ansible-voltage")
    # current state
    before = None
    try:
        resp = open_url(endpoint, method="GET", **kw)
        before = json.loads(resp.read().decode() or "null")
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) != 404:
            module.fail_json(msg="adapter GET %s failed: %s" % (endpoint, exc))
    after = None if state == "absent" else dict(before or {}, **spec)
    changed = before != after
    result = dict(changed=changed, kind=kind, name=name, before=before, after=after, backend="http", endpoint=endpoint)
    if module._diff:
        result["diff"] = {"before": before or {}, "after": after or {}}
    if changed and not module.check_mode:
        try:
            if after is None:
                open_url(endpoint, method="DELETE", **kw)
            else:
                open_url(endpoint, method="PUT", data=json.dumps(after).encode(), **kw)
        except Exception as exc:  # noqa: BLE001
            module.fail_json(msg="adapter write %s failed: %s" % (endpoint, exc))
    return result


# ---------------------------------------------------------------- command adapter
def _apply_command(module, backend, kind, name, state, spec):
    cmd = backend.get("command")
    if not cmd:
        module.fail_json(msg="backend.command is required for the command backend")
    request = {"kind": kind, "name": name, "state": state, "spec": spec, "check_mode": module.check_mode}
    rc, out, err = module.run_command(cmd, data=json.dumps(request), use_unsafe_shell=True)
    if rc != 0:
        module.fail_json(msg="adapter command failed (rc=%d): %s" % (rc, err or out), stdout=out, stderr=err)
    try:
        reply = json.loads(out or "{}")
    except ValueError:
        module.fail_json(msg="adapter command returned non-JSON", stdout=out, stderr=err)
    result = dict(changed=bool(reply.get("changed")), kind=kind, name=name, before=reply.get("before"),
                  after=reply.get("after"), backend="command", adapter_message=reply.get("message"))
    if module._diff:
        result["diff"] = {"before": reply.get("before") or {}, "after": reply.get("after") or {}}
    return result


def read_all(backend):
    """Load the whole desired-state document (file backend), for the audit role."""
    if backend.get("type", "file") != "file":
        raise ValueError("read_all only supports the file backend")
    return _load_doc(backend["path"])
