#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# Apache-2.0
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: voltage_auth_method
short_description: Declare a Voltage SecureData authentication method (config-as-code)
version_added: "0.1.0"
description:
  - Manages the desired state of an authentication method a district offers to clients --
    shared secret, username/password, LDAP, or certificate -- and its settings (LDAP server,
    base DN, lockout policy, secret rotation period ...).
  - Secrets (LDAP bind passwords etc.) are referenced, never stored.
extends_documentation_fragment:
  - flavioimbertdomingos.voltage.voltage.backend
options:
  name:
    description: Method name as it appears in the policy, e.g. C(SharedSecret), C(LDAP).
    type: str
    required: true
  state:
    description: Whether the method should be configured.
    type: str
    choices: [present, absent]
    default: present
  district:
    description: District the method applies to.
    type: str
  type:
    description: Method family.
    type: str
    choices: [shared_secret, username_password, ldap, certificate]
  settings:
    description: Method-specific settings (e.g. C(ldap_url), C(base_dn), C(bind_dn), C(rotation_days), C(lockout_threshold)).
    type: dict
  secret_ref:
    description: Reference to any credential the method needs (LDAP bind password). Never the value.
    type: str
  description:
    description: Free text.
    type: str
author:
  - Flavio Domingos (@FlavioImbertDomingos)
"""

EXAMPLES = r"""
- name: LDAP auth for the prod district
  flavioimbertdomingos.voltage.voltage_auth_method:
    name: LDAP
    district: prod
    type: ldap
    settings:
      ldap_url: ldaps://ldap.example.com:636
      base_dn: ou=apps,dc=example,dc=com
      bind_dn: cn=voltage,ou=svc,dc=example,dc=com
    secret_ref: vault:secret/voltage/prod/ldap-bind
    backend: {type: file, path: voltage-config.yml}

- name: Shared secrets rotate every 90 days
  flavioimbertdomingos.voltage.voltage_auth_method:
    name: SharedSecret
    district: prod
    type: shared_secret
    settings: {rotation_days: 90, min_length: 32}
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


def main():
    spec = dict(
        name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        district=dict(type="str"),
        type=dict(type="str", choices=["shared_secret", "username_password", "ldap", "certificate"]),
        settings=dict(type="dict"),
        secret_ref=dict(type="str"),
        description=dict(type="str"),
    )
    spec.update(BACKEND_ARG_SPEC)
    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    p = module.params
    desired = dict(district=p["district"], type=p["type"], settings=p["settings"], secret_ref=p["secret_ref"],
                   description=p["description"])
    module.exit_json(**apply(module, "auth_methods", p["name"], p["state"], desired))


if __name__ == "__main__":
    main()
