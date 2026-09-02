#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: voltage_policy_facts
short_description: Gather facts from a Voltage SecureData district's clientPolicy.xml
version_added: "0.1.0"
description:
  - Downloads C(clientPolicy.xml) -- the one public touch-point of every SecureData deployment --
    and returns the formats, authentication methods, key servers, version and a content hash.
  - Read-only. Needs no credentials.
extends_documentation_fragment:
  - flavioimbertdomingos.voltage.voltage.connection
author:
  - Flavio Domingos (@FlavioImbertDomingos)
"""

EXAMPLES = r"""
- name: What does the prod district offer?
  flavioimbertdomingos.voltage.voltage_policy_facts:
    policy_url: https://voltage-pp-0000.example.com/policy/clientPolicy.xml
    ca_path: /etc/pki/tls/certs/corp-ca.pem

- name: Fail the play if the CC format disappeared
  ansible.builtin.assert:
    that: "'CC' in voltage_policy.format_names"
"""

RETURN = r"""
ansible_facts:
  description: Facts set for the host.
  returned: always
  type: dict
  contains:
    voltage_policy:
      description: Parsed policy.
      type: dict
      returned: always
      sample:
        version: "7.0.2"
        district: prod
        policy_id: prod-2026-09
        format_names: [CC, SSN, CC-ST-64O]
        formats:
          - {name: CC, kind: fpe, type: FPE}
        auth_methods: [SharedSecret, LDAP]
        key_servers: ["https://voltage-pp-0000.example.com/vibekeys/"]
        sha256: "04315d33..."
        fetch_seconds: 0.041
policy:
  description: Same as C(ansible_facts.voltage_policy).
  returned: always
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.flavioimbertdomingos.voltage.plugins.module_utils.client import VoltageClientError, fetch_policy
from ansible_collections.flavioimbertdomingos.voltage.plugins.module_utils.policy import parse_policy


def main():
    module = AnsibleModule(
        argument_spec=dict(
            policy_url=dict(type="str", required=True),
            validate_certs=dict(type="bool", default=True),
            ca_path=dict(type="path"),
            timeout=dict(type="int", default=10),
        ),
        supports_check_mode=True,
    )
    p = module.params
    try:
        xml, secs = fetch_policy(p["policy_url"], p["validate_certs"], p["ca_path"], p["timeout"])
        info = parse_policy(xml)
    except VoltageClientError as exc:
        module.fail_json(msg=str(exc))
    except Exception as exc:  # noqa: BLE001 - XML parse errors
        module.fail_json(msg="cannot parse policy: %s" % exc)
    facts = info.to_dict()
    facts["format_names"] = info.format_names
    facts["fetch_seconds"] = round(secs, 3)
    module.exit_json(changed=False, ansible_facts={"voltage_policy": facts}, policy=facts)


if __name__ == "__main__":
    main()
