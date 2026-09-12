#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: voltage_coverage
short_description: Is every classified sensitive column actually protected?
version_added: "0.2.0"
description:
  - Joins a classification feed (CSV from Structured Data Manager, Core Data Discovery, or a
    spreadsheet) with the data map (C(voltage-data-map.yml)) and the formats each district's live
    policy offers, and reports every column as protected, unmapped, broken or unknown.
  - Also reports dead formats (offered by a district, used by no column and no identity) and data-map
    entries the feed never mentioned.
  - Pure file/data processing; contacts nothing. Feed live policies in from M(flavioimbertdomingos.voltage.voltage_policy_facts).
options:
  classification_csv:
    description: Path to the classification feed. Header C(system,schema,table,column,classification,confidence); schema and confidence optional.
    type: path
    required: true
  data_map:
    description: Path to the data map YAML (C(version), C(columns[])).
    type: path
    required: true
  desired_state:
    description: Optional path to the desired-state document (C(voltage-config.yml)); enables identity checks.
    type: path
  policy_formats:
    description: Mapping of district name to the list of format names its live policy offers.
    type: dict
    required: true
  min_confidence:
    description: Rows with a confidence below this are reported as unknown, not unmapped.
    type: float
    default: 0.0
  sensitive_classes:
    description: Only these classifications are evaluated. Default all rows.
    type: list
    elements: str
    default: []
author:
  - Flavio Domingos (@FlavioImbertDomingos)
"""

EXAMPLES = r"""
- name: Coverage against the live prod policy
  flavioimbertdomingos.voltage.voltage_coverage:
    classification_csv: /var/lib/discovery/classification.csv
    data_map: "{{ playbook_dir }}/voltage-data-map.yml"
    desired_state: "{{ playbook_dir }}/voltage-config.yml"
    policy_formats: {prod: "{{ voltage_policy.format_names }}"}
    min_confidence: 0.8
  register: cov

- ansible.builtin.fail:
    msg: "Unprotected sensitive columns: {{ cov.report.columns | selectattr('state', 'equalto', 'unmapped') | map(attribute='column') | list }}"
  when: cov.report.totals.unmapped | int > 0
"""

RETURN = r"""
report:
  description: The coverage report.
  returned: always
  type: dict
  sample:
    totals: {protected: 3, unmapped: 1, broken: 0, unknown: 1}
    feed_rows: 5
    map_entries: 3
    columns:
      - {column: warehouse.dw.fact_orders.card_no, classification: PAN, confidence: 0.97, state: unmapped, reason: no data-map entry, district: "", format: ""}
    dead_formats: {prod: [ORA-DATE]}
    unclassified_mappings: []
    errors: []
"""

import os

import yaml

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.flavioimbertdomingos.voltage.plugins.module_utils import coverage as cov


def _read(path):
    with open(path, "r") as fh:
        return fh.read()


def main():
    module = AnsibleModule(
        argument_spec=dict(
            classification_csv=dict(type="path", required=True),
            data_map=dict(type="path", required=True),
            desired_state=dict(type="path"),
            policy_formats=dict(type="dict", required=True),
            min_confidence=dict(type="float", default=0.0),
            sensitive_classes=dict(type="list", elements="str", default=[]),
        ),
        supports_check_mode=True,
    )
    p = module.params
    for key in ("classification_csv", "data_map", "desired_state"):
        if p.get(key) and not os.path.exists(p[key]):
            module.fail_json(msg="%s does not exist: %s" % (key, p[key]))
    try:
        feed, ferr = cov.parse_feed(_read(p["classification_csv"]))
        entries, merr = cov.parse_data_map(yaml.safe_load(_read(p["data_map"])) or {})
        desired = yaml.safe_load(_read(p["desired_state"])) if p.get("desired_state") else None
    except (OSError, yaml.YAMLError) as exc:
        module.fail_json(msg="cannot read coverage inputs: %s" % exc)
    identities = cov.identities_from_desired_state(desired) if desired is not None else None
    policy_formats = {str(d): [str(f) for f in (fs or [])] for d, fs in (p["policy_formats"] or {}).items()}
    rep = cov.evaluate(
        feed,
        entries,
        policy_formats,
        identities,
        min_confidence=float(p["min_confidence"]),
        sensitive_classes=p["sensitive_classes"] or None,
    )
    rep.errors = ferr + merr + rep.errors
    module.exit_json(changed=False, report=rep.to_dict())


if __name__ == "__main__":
    main()
