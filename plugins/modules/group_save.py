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
module: group_save
short_description: Create or update groups on CipherTrust Manager
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with groups management API
version_added: "1.0.0"
author: Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
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
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.groups import (
    create,
    patch,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_create,
    idempotent_patch,
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


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(["op_type", "patch", ["old_name"]],),
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
                endpoint="usermgmt/groups",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=create,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    app_metadata=module.params.get("app_metadata"),
                    client_metadata=module.params.get("client_metadata"),
                    user_metadata=module.params.get("user_metadata"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="usermgmt/groups",
                resource_id=module.params.get("old_name"),
                ignore_fields=("old_name",),
                patch_fn=patch,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    old_name=module.params.get("old_name"),
                    name=module.params.get("name"),
                    app_metadata=module.params.get("app_metadata"),
                    client_metadata=module.params.get("client_metadata"),
                    user_metadata=module.params.get("user_metadata"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
