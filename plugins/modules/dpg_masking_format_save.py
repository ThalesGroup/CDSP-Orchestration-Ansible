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
module: dpg_masking_format_save
short_description: Manage masking formats for DPG
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG Masking Format API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch]
      required: true
      type: str
    masking_format_id:
      description:
        - Identifier of the Masking Format to be patched
      type: str
    name:
      description: Unique name for the masking format
      type: str
    ending_characters:
      description: Number of ending characters to be masked
      type: int
      required: false
    mask_char:
      description: Character used for masking
      type: str
      required: false
    show:
      description: Flag to show/hide the starting/ending characters while revealing the data
      type: bool
      required: false
    starting_characters:
      description: Number of starting characters to be masked
      type: int
"""

EXAMPLES = """
- name: "Create Masking Format"
  thalesgroup.ciphertrust.dpg_masking_format_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: AnsibleIntegrationTest_MaskingFormat
    ending_characters: 2
    mask_char: X
    show: true
    starting_characters: 4

- name: "Patch Masking Format"
  thalesgroup.ciphertrust.dpg_masking_format_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: patch
    masking_format_id: <MaskingFormatID>
    ending_characters: 4
    mask_char: O
    starting_characters: 2

- name: "Delete Masking Format ID"
  thalesgroup.ciphertrust.cm_resource_delete:
    key: <MaskingFormatID>
    resource_type: "masking-formats"
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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_create,
    idempotent_patch,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import (
    createMaskingFormat,
    updateMaskingFormat,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    masking_format_id=dict(type="str"),
    name=dict(type="str"),
    starting_characters=dict(type="int"),
    ending_characters=dict(type="int"),
    mask_char=dict(type="str"),
    show=dict(type="bool"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["masking_format_id"]],
            ["op_type", "create", ["name"]],
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
                endpoint="data-protection/masking-formats",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createMaskingFormat,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    ending_characters=module.params.get("ending_characters"),
                    mask_char=module.params.get("mask_char"),
                    show=module.params.get("show"),
                    starting_characters=module.params.get("starting_characters"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="data-protection/masking-formats",
                resource_id=module.params.get("masking_format_id"),
                ignore_fields=("masking_format_id",),
                patch_fn=updateMaskingFormat,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    masking_format_id=module.params.get("masking_format_id"),
                    name=module.params.get("name"),
                    ending_characters=module.params.get("ending_characters"),
                    mask_char=module.params.get("mask_char"),
                    show=module.params.get("show"),
                    starting_characters=module.params.get("starting_characters"),
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
