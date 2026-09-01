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
module: licensing_lockdata_get
short_description: Get license lockdata used to get license code
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with create group API
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
"""

EXAMPLES = """
- name: "Get Licensing Lockdata"
  thalesgroup.ciphertrust.licensing_lockdata_get:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
"""

RETURN = r"""
response:
    description: Data retrieved from the CipherTrust Manager API.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.licensing import (
    getLockdata,
)


argument_spec = dict()


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
        response = getLockdata(
            node=module.params.get("localNode"),
        )
        result["response"] = response

    module.exit_json(**result)


if __name__ == "__main__":
    main()
