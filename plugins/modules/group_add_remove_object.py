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

DOCUMENTATION = '''
---
module: group_add_remove_object
short_description: Add or remove user or client from group
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with groups operation API
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
        description:
          - Operation to be performed
          - add to add a user or client to a group
          - remove to remove a user or client from a group
        choices: [add, remove]
        required: true
        type: str
    object_type:
        description:
          - Type of object to be added to or removed from a group
        choices: [user, client]
        required: true
        type: str
    name:
        description: name of the group to be updated
        type: str
        required: true
        default: null
    object_id:
        description: CM ID of the object (user or client) to be added to the group
        type: str
        required: true
        default: null
'''

EXAMPLES = '''
- name: "Add User to a Group"
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: add
    object_type: user
    object_id: user_id_on_CM
    name: "group_name"

- name: "Add Client to a Group"
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: add
    object_type: client
    object_id: client_id_on_CM
    name: "group_name"

- name: "Remove User from a Group"
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: remove
    object_type: user
    object_id: user_id_on_CM
    name: "group_name"

- name: "Remove Client from a Group"
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: remove
    object_type: client
    object_id: client_id_on_CM
    name: "group_name"
'''

RETURN = '''

'''

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.groups import (
    addUserToGroup,
    addClientToGroup,
    deleteUserFromGroup,
    deleteClientFromGroup,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["add", "remove"], required=True),
    object_type=dict(type="str", choices=["user", "client"], required=True),
    object_id=dict(type="str", required=True),
    name=dict(type="str", required=True),
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

    if module.params.get("op_type") == "add":
        if module.params.get("object_type") == "user":
            try:
                response = addUserToGroup(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    object_id=module.params.get("object_id"),
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
            try:
                response = addClientToGroup(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    object_id=module.params.get("object_id"),
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
        if module.params.get("object_type") == "user":
            try:
                response = deleteUserFromGroup(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    object_id=module.params.get("object_id"),
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
            try:
                response = deleteClientFromGroup(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    object_id=module.params.get("object_id"),
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
