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
module: cte_user_set
short_description: Create and manage CTE user-sets
description:
    - Create and edit CTE User set or add, edit, or remove a user to or from the user set
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch, add_user, patch_user, delete_user]
      required: true
      type: str
    id:
      description: Identifier of the CTE CSI Storage Group to be patched
      type: str
    user_index:
      aliases: [userIndex]
      description:
        - Identifier of the CTE User within UserSet to be patched or deleted
      type: int
    name:
      description: Name of the user set
      type: str
    description:
      description: Description of the user set
      type: str
    users:
      description: List of users to be added to the user set
      type: list
      elements: dict
      suboptions:
        gid:
          description: Group id of the user which shall be added in user-set
          type: int
        gname:
          description: Group name of the user which shall be added in user-set
          type: str
        os_domain:
          description: OS domain name in case of windows environment
          type: str
        uid:
          description: User id of the user which shall be added in user-set
          type: int
        uname:
          description: Name of the user which shall be added in user-set
          type: str
    gid:
      description: Group id of the user which shall be added in user-set
      type: int
    gname:
      description: Group name of the user which shall be added in user-set
      type: str
    os_domain:
      description: OS domain name in case of windows environment
      type: str
    uid:
      description: User id of the user which shall be added in user-set
      type: int
    uname:
      description: Name of the user which shall be added in user-set
      type: str
"""

EXAMPLES = """
- name: "Create CTE Userset"
  thalesgroup.ciphertrust.cte_user_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: UserSet1
    description: "Using Ansible"
    users:
      - uname: root1234
        uid: 1000
        gname: rootGroup
        gid: 1000
      - uname: test1234
        uid: 1234
        gname: testGroup
        gid: 1234
  register: userset

- name: "Add user to UserSet"
  thalesgroup.ciphertrust.cte_user_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_user
    id: "usersetID"
    users:
      - uname: root0001
        uid: 1001
        gname: rootGroup
        gid: 1000
"""

RETURN = r"""
changed:
    description: Whether any change was made to CipherTrust Manager state.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing resource when one was found during the GET-before-write
        idempotency check.
    returned: when a write was attempted or an existing resource matched
    type: dict
    contains:
        id:
            description: Unique identifier of the resource on CipherTrust Manager.
            type: str
            returned: when applicable
            sample: "4ae2649a705e479589ef65759d3287f6"
        name:
            description: Name of the resource.
            type: str
            returned: when applicable
        uri:
            description: Canonical resource URI.
            type: str
            returned: when applicable
        createdAt:
            description: RFC3339 timestamp of resource creation.
            type: str
            returned: when applicable
        updatedAt:
            description: RFC3339 timestamp of last modification.
            type: str
            returned: when applicable
diff:
    description: Present only in C(--diff) mode when a change occurred.
    returned: when diff mode is enabled and the module made a change
    type: dict
    contains:
        before:
            description: Prior state of the resource (empty for create operations).
            type: dict
        after:
            description: Target state after the change.
            type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_create,
    idempotent_patch,
    check_mode_action,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import (
    createUserSet,
    updateUserSet,
    addUserToSet,
    updateUserInSetByIndex,
    deleteUserInSetByIndex,
)

_user = dict(
    gid=dict(type="int"),
    gname=dict(type="str"),
    os_domain=dict(type="str"),
    uid=dict(type="int"),
    uname=dict(type="str"),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "add_user",
            "patch_user",
            "delete_user",
        ],
        required=True,
    ),
    id=dict(type="str"),
    userIndex=dict(type="int"),
    name=dict(type="str"),
    description=dict(type="str"),
    users=dict(type="list", elements="dict", options=_user),
    gid=dict(type="int"),
    gname=dict(type="str"),
    os_domain=dict(type="str"),
    uid=dict(type="int"),
    uname=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name"]],
            ["op_type", "patch", ["id"]],
            ["op_type", "add_user", ["id"]],
            ["op_type", "patch_user", ["id", "userIndex"]],
            ["op_type", "delete_user", ["id", "userIndex"]],
        ),
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
        if module.params.get("op_type") == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint="transparent-encryption/usersets",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createUserSet,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    description=module.params.get("description"),
                    users=module.params.get("users"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="transparent-encryption/usersets",
                resource_id=module.params.get("id"),
                ignore_fields=("id",),
                patch_fn=updateUserSet,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    id=module.params.get("id"),
                    description=module.params.get("description"),
                    users=module.params.get("users"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "add_user":
            check_mode_action(module)
            response = addUserToSet(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                users=module.params.get("users"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "patch_user":
            check_mode_action(module)
            response = updateUserInSetByIndex(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                userIndex=str(module.params.get("userIndex")),
                gid=module.params.get("gid"),
                gname=module.params.get("gname"),
                os_domain=module.params.get("os_domain"),
                uid=module.params.get("uid"),
                uname=module.params.get("uname"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "delete_user":
            check_mode_action(module)
            response = deleteUserInSetByIndex(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                userIndex=str(module.params.get("userIndex")),
            )
            result["response"] = response
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
