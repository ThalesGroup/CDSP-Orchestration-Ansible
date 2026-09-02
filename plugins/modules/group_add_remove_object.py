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
module: group_add_remove_object
short_description: Add or remove user or client from group
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with groups operation API
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    The operation is idempotent where CipherTrust Manager can say whether the
    resource is already in the requested state. When it can, repeating the task
    reports C(changed=false) and sends no request; when it cannot, the
    operation is performed as before.
options:
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
"""

EXAMPLES = """
- name: "Add User to a Group"
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
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
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: remove
    object_type: client
    object_id: client_id_on_CM
    name: "group_name"
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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    quote_segment,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.groups import (
    addUserToGroup,
    addClientToGroup,
    deleteUserFromGroup,
    deleteClientFromGroup,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_add,
    idempotent_remove,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["add", "remove"], required=True),
    object_type=dict(type="str", choices=["user", "client"], required=True),
    object_id=dict(type="str", required=True),
    name=dict(type="str", required=True),
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

    client = CipherTrustClient(module.params.get("localNode"))

    with ciphertrust_operation(module):
        object_type = module.params.get("object_type")
        name = module.params.get("name")
        object_id = module.params.get("object_id")

        # Membership is addressable: the URL the write targets is also the URL
        # that says whether the member is already there, so add and remove can
        # report changed honestly. If CM will not answer, the operation is
        # performed as before.
        if object_type == "user":
            membership = (
                "usermgmt/groups/" + quote_segment(name)
                + "/users/" + quote_segment(object_id)
            )
            add_fn, remove_fn = addUserToGroup, deleteUserFromGroup
        else:
            membership = (
                "client-management/groups/" + quote_segment(name)
                + "/clients/" + quote_segment(object_id)
            )
            add_fn, remove_fn = addClientToGroup, deleteClientFromGroup

        action_kwargs = dict(
            node=module.params.get("localNode"),
            name=name,
            object_id=object_id,
        )

        if module.params.get("op_type") == "add":
            changed, response = idempotent_add(
                module, client, membership, add_fn, action_kwargs
            )
        else:
            changed, response = idempotent_remove(
                module, client, membership, remove_fn, action_kwargs
            )

        result["changed"] = changed
        result["response"] = response

    module.exit_json(**result)


if __name__ == "__main__":
    main()
