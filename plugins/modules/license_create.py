#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
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
options:
    localNode:
      description:
        - this holds the connection parameters required to communicate with an instance of CipherTrust Manager (CM)
        - holds IP/FQDN of the server, username, password, and port
      required: true
      type: dict
      suboptions:
        server_ip:
          description: CM Server IP or FQDN
          type: str
          required: true
        server_private_ip:
          description: internal or private IP of the CM Server, if different from the server_ip
          type: str
          required: true
        server_port:
          description: Port on which CM server is listening
          type: int
          required: true
        user:
          description: admin username of CM
          type: str
          required: true
        password:
          description: admin password of CM
          type: str
          required: true
        verify:
          description: if SSL verification is required
          type: bool
          required: true
        auth_domain_path:
          description: user's domain path
          type: str
          required: true
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
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    license: license_string
"""

RETURN = """

"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.licensing import (
    addLicense,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

argument_spec = dict(
    license=dict(type="str", required=True),
    bind_type=dict(type="str", choices=['instance', 'cluster']),
)


def validate_parameters(user_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=[],
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        user_module=module,
    )

    result = dict(
        changed=False,
    )

    try:
        response = addLicense(
            node=module.params.get("localNode"),
            license=module.params.get("license"),
            bind_type=module.params.get("bind_type"),
        )
        result["response"] = response
    except CMApiException as api_e:
        if api_e.api_error_code:
            module.fail_json(
                msg="status code: "
                + str(api_e.api_error_code)
                + " message: "
                + api_e.message
            )
    except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
