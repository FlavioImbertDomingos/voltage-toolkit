#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: voltage_identity
short_description: Declare a Voltage SecureData identity (config-as-code)
version_added: "0.1.0"
description:
  - Manages the desired state of a SecureData identity -- the principal an application authenticates as
    (usually e-mail-like, e.g. C(payments@example.com)) -- in a district.
  - Writes through a backend (see I(backend)); the default keeps a git-friendly desired-state file that
    the C(voltage_policy_audit) role compares with the live policy.
  - Never stores secrets. The shared secret is referenced by name (I(secret_ref)), not by value.
extends_documentation_fragment:
  - flavioimbertdomingos.voltage.voltage.backend
options:
  name:
    description: The identity string.
    type: str
    required: true
  state:
    description: Whether the identity should exist.
    type: str
    choices: [present, absent]
    default: present
  district:
    description: District the identity belongs to.
    type: str
  auth_method:
    description: How this identity authenticates.
    type: str
    choices: [SharedSecret, UsernamePassword, LDAP, Certificate]
  formats:
    description: Formats the identity is allowed to use.
    type: list
    elements: str
  secret_ref:
    description: Where the shared secret lives (vault path / secret name). A reference, never the value.
    type: str
  owner:
    description: Team or person accountable for the identity (PCI DSS 3.6.1.1 / key custodian record).
    type: str
  description:
    description: Free text.
    type: str
  tags:
    description: Arbitrary labels (application, environment, ticket ...).
    type: dict
author:
  - Flavio Domingos (@FlavioImbertDomingos)
"""

EXAMPLES = r"""
- name: Payments app identity, declared in git
  flavioimbertdomingos.voltage.voltage_identity:
    name: payments@example.com
    district: prod
    auth_method: SharedSecret
    formats: [CC, CC-ST-64O]
    secret_ref: vault:secret/voltage/prod/payments
    owner: payments-platform
    tags: {app: payments, pci: "true"}
    backend:
      type: file
      path: "{{ playbook_dir }}/voltage-config.yml"

- name: Same, pushed to a site adapter in front of the Management Console
  flavioimbertdomingos.voltage.voltage_identity:
    name: payments@example.com
    district: prod
    auth_method: SharedSecret
    formats: [CC]
    backend:
      type: http
      url: https://voltage-adapter.internal/api
      token: "{{ vault_adapter_token }}"

- name: Retire an identity
  flavioimbertdomingos.voltage.voltage_identity:
    name: legacy-batch@example.com
    state: absent
    backend: {type: file, path: voltage-config.yml}
"""

RETURN = r"""
before:
  description: The object before the change (C(null) if it did not exist).
  type: dict
  returned: always
after:
  description: The object after the change (C(null) if removed).
  type: dict
  returned: always
kind:
  description: Always C(identities).
  type: str
  returned: always
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.flavioimbertdomingos.voltage.plugins.module_utils.desired_state import BACKEND_ARG_SPEC, apply


def main():
    spec = dict(
        name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        district=dict(type="str"),
        auth_method=dict(type="str", choices=["SharedSecret", "UsernamePassword", "LDAP", "Certificate"]),
        formats=dict(type="list", elements="str"),
        secret_ref=dict(type="str", no_log=False),
        owner=dict(type="str"),
        description=dict(type="str"),
        tags=dict(type="dict"),
    )
    spec.update(BACKEND_ARG_SPEC)
    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    p = module.params
    desired = dict(district=p["district"], auth_method=p["auth_method"], formats=p["formats"], secret_ref=p["secret_ref"],
                   owner=p["owner"], description=p["description"], tags=p["tags"])
    module.exit_json(**apply(module, "identities", p["name"], p["state"], desired))


if __name__ == "__main__":
    main()
