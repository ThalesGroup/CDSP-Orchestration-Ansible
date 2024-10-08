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
module: group_save
short_description: Create or update groups on CipherTrust Manager
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with groups management API
version_added: "1.0.0"
author: Anurag Jain (@anugram)
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
    op_type:
        description: Operation to be performed
        choices: [create, patch]
        required: true
        type: str
    old_name:
        description:
          - Group's original name that needs to be patched.
          - Only required if the op_type is patch
        type: str
        default: null
    name:
        description: name of the group
        type: str
        required: true
        default: null
    app_metadata:
        description:
          - A schema-less object, which can be used by applications to store information about the resource
        type: dict
        default: null
    client_metadata:
        description:
          - A schema-less object, which can be used by applications to store information about the resource such as client preferences
        type: dict
        default: null
    user_metadata:
        description:
          - A schema-less object, which can be used by applications to store information about the resource such as end-user preferences
        type: dict
        default: null

"""

EXAMPLES = """
- name: "Create Group"
  thalesgroup.ciphertrust.group_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: create
    name: "group_name"

- name: "Patch Group"
  thalesgroup.ciphertrust.group_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: patch
    old_name: "group_name"
    name: "new_name"
"""

RETURN = """

"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.groups import (
    create,
    patch,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

_schema_less = dict()

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    old_name=dict(type="str"),
    name=dict(type="str", required=True),
    app_metadata=dict(type="dict", options=_schema_less, required=False),
    client_metadata=dict(type="dict", options=_schema_less, required=False),
    user_metadata=dict(type="dict", options=_schema_less, required=False),
)


def validate_parameters(user_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(["op_type", "patch", ["old_name"]],),
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

    if module.params.get("op_type") == "create":
        try:
            response = create(
                node=module.params.get("localNode"),
                name=module.params.get("name"),
                app_metadata=module.params.get("app_metadata"),
                client_metadata=module.params.get("client_metadata"),
                user_metadata=module.params.get("user_metadata"),
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

    elif module.params.get("op_type") == "patch":
        try:
            response = patch(
                node=module.params.get("localNode"),
                old_name=module.params.get("old_name"),
                name=module.params.get("name"),
                app_metadata=module.params.get("app_metadata"),
                client_metadata=module.params.get("client_metadata"),
                user_metadata=module.params.get("user_metadata"),
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

    else:
        module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
