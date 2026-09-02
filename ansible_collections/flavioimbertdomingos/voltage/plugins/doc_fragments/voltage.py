# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# Apache-2.0
from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    CONNECTION = r"""
options:
  policy_url:
    description: URL of the district's C(clientPolicy.xml), e.g. C(https://voltage-pp-0000.example.com/policy/clientPolicy.xml).
    type: str
    required: true
  validate_certs:
    description: Verify the appliance TLS certificate.
    type: bool
    default: true
  ca_path:
    description: CA bundle to verify the appliance certificate against.
    type: path
  timeout:
    description: Per-request timeout in seconds.
    type: int
    default: 10
"""

    WEBSERVICE = r"""
options:
  ws_url:
    description: Base URL of the Web Services host (the part before C(/vibesimple)). Defaults to the policy host.
    type: str
  api:
    description: Which Web Services API to use.
    type: str
    choices: [rest, soap]
    default: rest
  identity:
    description: SecureData identity used for the call (usually an e-mail-like string).
    type: str
    required: true
  auth_method:
    description: C(shared_secret) sends identity + shared secret; C(password) sends username + password (LDAP / appliance user).
    type: str
    choices: [shared_secret, password]
    default: shared_secret
  username:
    description: Username for I(auth_method=password). Defaults to I(identity).
    type: str
  secret:
    description: The shared secret or password. Pass it from a vault or C(lookup('env', ...)); never literal.
    type: str
    required: true
  auth_in_body:
    description: Send credentials inside the JSON body (C(sharedSecret) / C(username)+C(password)) instead of HTTP Basic.
    type: bool
    default: false
"""

    BACKEND = r"""
options:
  backend:
    description:
      - Where the desired state is written. OpenText publishes no configuration API for the Management Console,
        so the default C(file) backend keeps a config-as-code document that the audit role compares with the live policy.
      - C(http) and C(command) let you plug in a site adapter. See docs/ADAPTER.md in the repository.
    type: dict
    default: {type: file}
    suboptions:
      type:
        description: Backend type.
        type: str
        choices: [file, http, command]
        default: file
      path:
        description: Desired-state document (YAML or JSON) for the C(file) backend.
        type: path
      url:
        description: Base URL of the adapter for the C(http) backend; objects live at C(<url>/<kind>/<name>).
        type: str
      token:
        description: Bearer token for the C(http) backend.
        type: str
      validate_certs:
        description: Verify the adapter's TLS certificate.
        type: bool
        default: true
      ca_path:
        description: CA bundle for the adapter.
        type: path
      timeout:
        description: Adapter request timeout.
        type: int
        default: 15
      command:
        description: Executable for the C(command) backend; receives a JSON request on stdin.
        type: str
"""
