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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import (
    createUserSet,
    updateUserSet,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

DOCUMENTATION = """
---
module: dpg_user_set_save
short_description: Create and manage DPG user sets
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with user sets management API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
version_added: "1.0.0"
author: Anurag Jain, Developer Advocate Thales Group
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
          default: 5432
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
          default: false
        auth_domain_path:
          description: user's domain path
          type: str
          required: true
    op_type:
      description: Operation to be performed
      choices: [create, patch]
      required: true
      type: str
    user_set_id:
      description:
        - Identifier of the user set to be patched
      type: str
    name:
      description: Unique name for the user set
      type: str
    description:
      description: The description of user set
      type: str
    users:
      description: List of users to be added in user set
      type: list
      elements: str
      default: []
      required: false
"""

EXAMPLES = """
- name: "Create User Set"
  thalesgroup.ciphertrust.dpg_user_set_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: create
    name: AnsibleIntegrationTest_UserSet
    description: "Created via Ansible"
    users:
    - "AnsibleIntegrationTest_User1"
    - "AnsibleIntegrationTest_User2"

- name: "Patch User Set"
  thalesgroup.ciphertrust.dpg_user_set_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: patch
    user_set_id: <UserSetID>
    users:
    - "AnsibleIntegrationTest_User1"
    - "AnsibleIntegrationTest_User2"
    - "AnsibleIntegrationTest_User3"

- name: "Delete UserSet ID"
  thalesgroup.ciphertrust.cm_resource_delete:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    key: <UserSetID>
    resource_type: "user-sets"
"""

RETURN = """

"""

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    user_set_id=dict(type="str"),
    name=dict(type="str"),
    description=dict(type="str"),
    users=dict(type="list", element="str"),
)


def validate_parameters(dpg_user_set_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["user_set_id"]],
            ["op_type", "create", ["name"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        dpg_user_set_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get("op_type") == "create":
        try:
            response = createUserSet(
                node=module.params.get("localNode"),
                name=module.params.get("name"),
                description=module.params.get("description"),
                users=module.params.get("users"),
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
            response = updateUserSet(
                node=module.params.get("localNode"),
                user_set_id=module.params.get("user_set_id"),
                name=module.params.get("name"),
                description=module.params.get("description"),
                users=module.params.get("users"),
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
