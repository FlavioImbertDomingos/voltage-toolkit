#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: voltage_district
short_description: Declare a Voltage SecureData district (config-as-code)
version_added: "0.1.0"
description:
  - Manages the desired state of a district -- a SecureData key domain with its own policy, formats and
    key servers (one per environment or business unit is typical).
  - What you declare here (formats, key servers, auth methods) is exactly what the live C(clientPolicy.xml)
    exposes, so the C(voltage_policy_audit) role can detect drift between git and the appliance.
extends_documentation_fragment:
  - flavioimbertdomingos.voltage.voltage.backend
options:
  name:
    description: District name.
    type: str
    required: true
  state:
    description: Whether the district should exist.
    type: str
    choices: [present, absent]
    default: present
  policy_url:
    description: The district's C(clientPolicy.xml) URL (used by the audit role to fetch the live policy).
    type: str
  formats:
    description: Formats the district must offer. Each item is a name or a dict with C(name), C(kind) (fpe|tokenization) and vendor attributes.
    type: list
    elements: raw
  auth_methods:
    description: Authentication methods the district must offer.
    type: list
    elements: str
  key_servers:
    description: Key server URLs the policy must list.
    type: list
    elements: str
  owner:
    description: Accountable team.
    type: str
  description:
    description: Free text.
    type: str
  tags:
    description: Arbitrary labels.
    type: dict
author:
  - Flavio Domingos (@FlavioImbertDomingos)
"""

EXAMPLES = r"""
- name: Production district as we expect it
  flavioimbertdomingos.voltage.voltage_district:
    name: prod
    policy_url: https://voltage-pp-0000.example.com/policy/clientPolicy.xml
    formats:
      - CC
      - SSN
      - {name: CC-ST-64O, kind: tokenization}
    auth_methods: [SharedSecret, LDAP]
    key_servers: ["https://voltage-pp-0000.example.com/vibekeys/"]
    owner: crypto-services
    backend: {type: file, path: voltage-config.yml}
"""

RETURN = r"""
before:
  description: The object before the change.
  type: dict
  returned: always
after:
  description: The object after the change.
  type: dict
  returned: always
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.flavioimbertdomingos.voltage.plugins.module_utils.desired_state import BACKEND_ARG_SPEC, apply


def _normalise_formats(items):
    if items is None:
        return None
    out = []
    for it in items:
        if isinstance(it, dict):
            d = dict(it)
            d.setdefault("kind", "fpe")
            out.append(d)
        else:
            out.append({"name": str(it), "kind": "fpe"})
    return out


def main():
    spec = dict(
        name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        policy_url=dict(type="str"),
        formats=dict(type="list", elements="raw"),
        auth_methods=dict(type="list", elements="str"),
        key_servers=dict(type="list", elements="str"),
        owner=dict(type="str"),
        description=dict(type="str"),
        tags=dict(type="dict"),
    )
    spec.update(BACKEND_ARG_SPEC)
    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    p = module.params
    desired = dict(policy_url=p["policy_url"], formats=_normalise_formats(p["formats"]), auth_methods=p["auth_methods"],
                   key_servers=p["key_servers"], owner=p["owner"], description=p["description"], tags=p["tags"])
    module.exit_json(**apply(module, "districts", p["name"], p["state"], desired))


if __name__ == "__main__":
    main()
