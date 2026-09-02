#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: voltage_probe
short_description: Synthetic protect/access round-trip against Voltage SecureData Web Services
version_added: "0.1.0"
description:
  - Tokenizes a synthetic sample with the Web Services API, detokenizes the result, and checks
    that the original comes back. Reports latency for both calls.
  - Use it as a post-change smoke test, a pre-flight check before a batch job, or from a
    monitoring playbook. Use synthetic samples (test PANs) only -- never real data.
extends_documentation_fragment:
  - flavioimbertdomingos.voltage.voltage.connection
  - flavioimbertdomingos.voltage.voltage.webservice
options:
  format:
    description: SecureData format name, e.g. C(CC), C(SSN), C(CC-ST-64O).
    type: str
    required: true
  sample:
    description: Synthetic value to protect.
    type: str
    required: true
  tokenization:
    description: Set for SST (tokenization) formats, which are not expected to preserve the sample's shape.
    type: bool
    default: false
  fail_on_error:
    description: Fail the task when the round-trip does not succeed.
    type: bool
    default: true
  max_latency:
    description: Fail if either call takes longer than this many seconds (with I(fail_on_error)).
    type: float
author:
  - Flavio Domingos (@FlavioImbertDomingos)
"""

EXAMPLES = r"""
- name: Smoke-test tokenization after the change window
  flavioimbertdomingos.voltage.voltage_probe:
    policy_url: https://voltage-pp-0000.example.com/policy/clientPolicy.xml
    identity: monitor-probe@example.com
    secret: "{{ lookup('env', 'VOLTAGE_SHARED_SECRET') }}"
    format: CC
    sample: "4111111111111111"
    max_latency: 0.5
    ca_path: /etc/pki/tls/certs/corp-ca.pem

- name: Same over SOAP with an LDAP user
  flavioimbertdomingos.voltage.voltage_probe:
    policy_url: https://voltage-pp-0000.example.com/policy/clientPolicy.xml
    api: soap
    identity: monitor
    auth_method: password
    username: monitor
    secret: "{{ vault_voltage_password }}"
    format: SSN
    sample: "123-45-6789"
"""

RETURN = r"""
ok:
  description: Whether protect, access and the equality check all succeeded.
  type: bool
  returned: always
protected:
  description: The protected value (safe to show for a synthetic sample).
  type: str
  returned: when protect succeeded
protect_seconds:
  description: Latency of the protect call.
  type: float
  returned: when protect succeeded
access_seconds:
  description: Latency of the access call.
  type: float
  returned: when access succeeded
format_preserved:
  description: Whether the protected value kept the sample's length and character classes (FPE formats).
  type: bool
  returned: when protect succeeded
error:
  description: What went wrong.
  type: str
  returned: on failure
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.flavioimbertdomingos.voltage.plugins.module_utils.client import VoltageClientError, ws_call


def _same_shape(a, b):
    if len(a) != len(b):
        return False

    def cls(ch):
        return "d" if ch.isdigit() else "a" if ch.isalpha() else ch

    return all(cls(x) == cls(y) for x, y in zip(a, b))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            policy_url=dict(type="str", required=True),
            ws_url=dict(type="str"),
            api=dict(type="str", default="rest", choices=["rest", "soap"]),
            identity=dict(type="str", required=True),
            auth_method=dict(type="str", default="shared_secret", choices=["shared_secret", "password"]),
            username=dict(type="str"),
            secret=dict(type="str", required=True, no_log=True),
            auth_in_body=dict(type="bool", default=False),
            validate_certs=dict(type="bool", default=True),
            ca_path=dict(type="path"),
            timeout=dict(type="int", default=10),
            format=dict(type="str", required=True),
            sample=dict(type="str", required=True),
            tokenization=dict(type="bool", default=False),
            fail_on_error=dict(type="bool", default=True),
            max_latency=dict(type="float"),
        ),
        supports_check_mode=True,
    )
    p = module.params
    ws_url = p["ws_url"] or p["policy_url"].split("/policy/")[0]
    common = dict(api=p["api"], auth_method=p["auth_method"], username=p["username"], auth_in_body=p["auth_in_body"],
                  validate_certs=p["validate_certs"], ca_path=p["ca_path"], timeout=p["timeout"])
    result = dict(changed=False, ok=False)
    try:
        token, ps = ws_call("protect", ws_url, p["identity"], p["secret"], p["format"], p["sample"], **common)
        result.update(protected=token, protect_seconds=round(ps, 4))
        if token == p["sample"]:
            raise VoltageClientError("protect returned the input unchanged")
        result["format_preserved"] = _same_shape(p["sample"], token) if not p["tokenization"] else True
        back, as_ = ws_call("access", ws_url, p["identity"], p["secret"], p["format"], token, **common)
        result["access_seconds"] = round(as_, 4)
        if back != p["sample"]:
            raise VoltageClientError("access did not return the original value (data integrity!)")
        if p["max_latency"] and max(ps, as_) > p["max_latency"]:
            raise VoltageClientError("latency %.3fs exceeds max_latency %.3fs" % (max(ps, as_), p["max_latency"]))
        result["ok"] = True
    except VoltageClientError as exc:
        result["error"] = str(exc)
        if p["fail_on_error"]:
            module.fail_json(msg=str(exc), **result)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
