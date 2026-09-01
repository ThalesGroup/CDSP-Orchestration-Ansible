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
module: dpg_access_policy_save
short_description: Manage DPG access policies governing data access
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG Access Policy API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch, add-user-set, update-user-set, delete-user-set]
      required: true
      type: str
    policy_id:
      description:
        - Identifier of the access policy to be patched
      type: str
    default_error_replacement_value:
      description: Value to be revealed if the type is 'Error Replacement Value'
      type: str
    default_masking_format_id:
      description: Masking format used to reveal if the type is 'Masked Value'
      type: str
    default_reveal_type:
      description: Value using which data should be revealed
      choices: [Error Replacement Value, Masked Value, Ciphertext, Plaintext]
      type: str
    description:
      description: Description of the Access Policy
      required: false
      type: str
    name:
      description: Access Policy Name
      required: false
      type: str
    user_set_policy:
      description: List of policies to be added to the access policy
      required: false
      type: list
      elements: dict
      suboptions:
        error_replacement_value:
          description: Value to be revealed if the type is 'Error Replacement Value'
          type: str
        masking_format_id:
          description: Masking format used to reveal if the type is 'Masked Value'
          type: str
        reveal_type:
          description: Value using which data should be revealed
          choices: [Error Replacement Value, Masked Value, Ciphertext, Plaintext]
          type: str
        user_set_id:
          description: User set to which the policy is applied.
          type: str
    error_replacement_value:
      description: Value to be revealed if the type is 'Error Replacement Value'
      type: str
    masking_format_id:
      description: Masking format used to reveal if the type is 'Masked Value'
      type: str
    reveal_type:
      description: Value using which data should be revealed
      choices: [Error Replacement Value, Masked Value, Ciphertext, Plaintext]
      type: str
    user_set_id:
      description: User set to which the policy is applied.
      type: str
    policy_user_set_id:
      description: Update or delete the user set in an Access Policy
      type: str
"""

EXAMPLES = """
- name: "Create Access Policy"
  thalesgroup.ciphertrust.dpg_access_policy_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path: domain
    op_type: create
    name: DemoAccessPolicy
    default_reveal_type: "Ciphertext"
    user_set_policy:
      - reveal_type: Plaintext
        user_set_id: <UserSetID>
      - reveal_type: Ciphertext
        user_set_id: <UserSetID>

- name: "Patch Access Policy"
  thalesgroup.ciphertrust.dpg_access_policy_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path: domain
    op_type: patch
    policy_id: <accessPolicyID>
    name: DemoAccessPolicyUPD
    description: "Updated via Ansible"
    default_reveal_type: Plaintext

- name: "Add UserSet to Access Policy"
  thalesgroup.ciphertrust.dpg_access_policy_save:
    op_type: add-user-set
    policy_id: <accessPolicyID>
    reveal_type: Plaintext
    user_set_id: <UserSetID>
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path: domain

- name: "Update UserSet in Access Policy"
  thalesgroup.ciphertrust.dpg_access_policy_save:
    op_type: update-user-set
    policy_id: <accessPolicyID>
    policy_user_set_id: <UserSetID>
    reveal_type: Plaintext
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path: domain

- name: "Delete Access Policy"
  thalesgroup.ciphertrust.cm_resource_delete:
    key: <accessPolicyID>
    resource_type: "access-policies"
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path: domain
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
    createAccessPolicy,
    updateAccessPolicy,
    accessPolicyAddUserSet,
    accessPolicyUpdateUserSet,
    accessPolicyDeleteUserSet,
)

_user_set_policy = dict(
    error_replacement_value=dict(type="str"),
    masking_format_id=dict(type="str"),
    reveal_type=dict(
        type="str",
        choices=["Error Replacement Value", "Masked Value", "Ciphertext", "Plaintext"],
    ),
    user_set_id=dict(type="str"),
)
argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "add-user-set",
            "update-user-set",
            "delete-user-set",
        ],
        required=True,
    ),
    policy_id=dict(type="str"),
    default_error_replacement_value=dict(type="str"),
    default_masking_format_id=dict(type="str"),
    default_reveal_type=dict(
        type="str",
        choices=["Error Replacement Value", "Masked Value", "Ciphertext", "Plaintext"],
    ),
    description=dict(type="str"),
    name=dict(type="str"),
    user_set_policy=dict(type="list", elements="dict", options=_user_set_policy),
    # op_type = add-user-set
    error_replacement_value=dict(type="str"),
    masking_format_id=dict(type="str"),
    reveal_type=dict(
        type="str",
        choices=["Error Replacement Value", "Masked Value", "Ciphertext", "Plaintext"],
    ),
    user_set_id=dict(type="str"),
    # op_type = update-user-set or delete-user-set
    policy_user_set_id=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["policy_id"]],
            ["op_type", "update-user-set", ["policy_user_set_id"]],
            ["op_type", "delete-user-set", ["policy_user_set_id"]],
            [
                "default_reveal_type",
                "Error Replacement Value",
                ["default_error_replacement_value"],
            ],
            ["default_reveal_type", "Masked Value", ["default_masking_format_id"]],
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
                endpoint="data-protection/access-policies",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createAccessPolicy,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    default_error_replacement_value=module.params.get(
                        "default_error_replacement_value"
                    ),
                    default_masking_format_id=module.params.get(
                        "default_masking_format_id"
                    ),
                    default_reveal_type=module.params.get("default_reveal_type"),
                    description=module.params.get("description"),
                    name=module.params.get("name"),
                    user_set_policy=module.params.get("user_set_policy"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="data-protection/access-policies",
                resource_id=module.params.get("policy_id"),
                ignore_fields=("policy_id",),
                patch_fn=updateAccessPolicy,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    policy_id=module.params.get("policy_id"),
                    default_error_replacement_value=module.params.get(
                        "default_error_replacement_value"
                    ),
                    default_masking_format_id=module.params.get(
                        "default_masking_format_id"
                    ),
                    default_reveal_type=module.params.get("default_reveal_type"),
                    description=module.params.get("description"),
                    name=module.params.get("name"),
                    user_set_policy=module.params.get("user_set_policy"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "add-user-set":
            if module.check_mode:
                module.exit_json(changed=True)
            response = accessPolicyAddUserSet(
                node=module.params.get("localNode"),
                policy_id=module.params.get("policy_id"),
                error_replacement_value=module.params.get("error_replacement_value"),
                masking_format_id=module.params.get("masking_format_id"),
                reveal_type=module.params.get("reveal_type"),
                user_set_id=module.params.get("user_set_id"),
            )
            result["changed"] = True
            result["response"] = response

        elif module.params.get("op_type") == "update-user-set":
            if module.check_mode:
                module.exit_json(changed=True)
            response = accessPolicyUpdateUserSet(
                node=module.params.get("localNode"),
                policy_id=module.params.get("policy_id"),
                policy_user_set_id=module.params.get("policy_user_set_id"),
                error_replacement_value=module.params.get("error_replacement_value"),
                masking_format_id=module.params.get("masking_format_id"),
                reveal_type=module.params.get("reveal_type"),
            )
            result["changed"] = True
            result["response"] = response

        elif module.params.get("op_type") == "delete-user-set":
            if module.check_mode:
                module.exit_json(changed=True)
            response = accessPolicyDeleteUserSet(
                node=module.params.get("localNode"),
                policy_id=module.params.get("policy_id"),
                policy_user_set_id=module.params.get("policy_user_set_id"),
            )
            result["changed"] = True
            result["response"] = response

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
