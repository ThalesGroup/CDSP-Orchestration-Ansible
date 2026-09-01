#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: license_create
short_description: Add a license to CipherTrust Manager
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with trials management API
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    license:
        description: License string
        required: true
        type: str
    bind_type:
        description:
          - Binding type for this license
          - Can be either instance or cluster
          - If omitted, then CM attempts to bind the license to the cluster
          - If this step fails with a lock code error, it will attempt to bind to the instance.
        required: false
        choices: ['instance', 'cluster']
        type: str

"""

EXAMPLES = """
- name: "Add License"
  thalesgroup.ciphertrust.license_create:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    license: license_string
"""

RETURN = r"""
changed:
    description: Always C(true) when the action is performed; C(false) in check mode.
    returned: always
    type: bool
    sample: true
response:
    description: Raw response payload from the CipherTrust Manager API.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.licensing import (
    addLicense,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)

argument_spec = dict(
    license=dict(type="str", required=True),
    bind_type=dict(type="str", choices=['instance', 'cluster']),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=[],
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    with ciphertrust_operation(module):
        check_mode_action(module)
        response = addLicense(
            node=module.params.get("localNode"),
            license=module.params.get("license"),
            bind_type=module.params.get("bind_type"),
        )
        result["response"] = response
        result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
