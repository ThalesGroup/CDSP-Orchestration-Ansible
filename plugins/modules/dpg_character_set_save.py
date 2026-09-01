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
module: dpg_character_set_save
short_description: Create and manage DPG character-sets
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with Character Set management API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch]
      required: true
      type: str
    char_set_id:
      description:
        - Identifier of the Character Set to be patched
      type: str
    name:
      description: Unique name for the Character Set
      type: str
    encoding:
      description: The description of Character Set
      type: str
    range:
      description: Allowed range of characters in HEX format
      type: list
      elements: str
"""

EXAMPLES = """
- name: "Create Character Set"
  thalesgroup.ciphertrust.dpg_character_set_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: DPGAlphaNum
    range:
      - "0030-0039"
      - "0041-005A"
    encoding: "UTF-8"

- name: "Patch Character Set"
  thalesgroup.ciphertrust.dpg_character_set_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: patch
    char_set_id: <CharSetID>
    range:
      - "0030-0039"
      - "0041-005A"
      - "0061-007A"

- name: "Delete charset by ID"
  thalesgroup.ciphertrust.cm_resource_delete:
    key: <CharSetID>
    resource_type: "character-sets"
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
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
            sample: "myResource"
        uri:
            description: Canonical resource URI.
            type: str
            returned: when applicable
            sample: "kylo:kylo:data-protection:dpg-policies:4ae2649a705e"
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
            description: Target state after the change (or empty-body create target in check mode).
            type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import (
    createCharacterSet,
    updateCharacterSet,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_create,
    idempotent_patch,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    char_set_id=dict(type="str"),
    name=dict(type="str"),
    encoding=dict(type="str"),
    range=dict(type="list", elements="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["char_set_id"]],
            ["op_type", "create", ["name", "range"]],
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
                endpoint="data-protection/character-sets",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createCharacterSet,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    range=module.params.get("range"),
                    encoding=module.params.get("encoding"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="data-protection/character-sets",
                resource_id=module.params.get("char_set_id"),
                ignore_fields=("char_set_id",),
                patch_fn=updateCharacterSet,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    char_set_id=module.params.get("char_set_id"),
                    name=module.params.get("name"),
                    range=module.params.get("range"),
                    encoding=module.params.get("encoding"),
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
