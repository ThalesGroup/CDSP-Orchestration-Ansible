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
module: dpg_protection_policy_save
short_description: Manage DPG protection policies governing crypto operations
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with domains management API
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
    policy_name:
      description:
        - Identifier of the protection policy to be patched
      type: str
    access_policy_name:
      description:
        - Name of access policy to be associated with the protection policy.
      type: str
    masking_format_id:
      description:
        - ID of the Static Masking Format
      type: str
    algorithm:
      description: Algorithm to be used during crypto operations
      type: str
    key:
      description: Name of the key
      type: str
    name:
      description: Unique name for the protection policy
      type: str
    allow_single_char_input:
      description:
      - If true, null or single-character inputs are passed untransformed. If false, row transformation fails
      - Obsolete post CM v2.12
      type: bool
    character_set_id:
      description: ID of the Character Set
      required: false
      type: str
    iv:
      description: IV to be used during crypto operations
      required: false
      type: str
    tweak:
      description: Tweak data to be used during crypto operations
      required: false
      type: str
    tweak_algorithm:
      description: Tweak algorithm to be used during crypto operations
      choices: [SHA1, SHA256, None]
      required: false
      type: str
    disable_versioning:
      description:
      - If set to true, versioning is not maintained for the protection policies. The default value is false.
      - Added in CM v2.12
      required: false
      type: bool
    use_external_versioning:
      description:
      - If set to true, external versioning is enabled for the protection policy
      - The version details are stored in a separate external parameter
      - The default value is false
      - Added in CM v2.12
      required: false
      type: bool
"""

EXAMPLES = """
- name: "Create Protection Policy"
  thalesgroup.ciphertrust.dpg_protection_policy_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    algorithm: "AES/CBC/PKCS5Padding"
    key: <CM_KEY_ID>
    name: DemoProtectionPolicy
    character_set_id: <CHAR_SET_ID>
    iv: 16
    tweak: 1628462495815733
    tweak_algorithm: SHA1

- name: "Patch Protection Policy"
  thalesgroup.ciphertrust.dpg_protection_policy_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: patch
    policy_name: DemoProtectionPolicy
    tweak: 1628462495815733
    tweak_algorithm: SHA256

- name: "Delete Protection Policy by name"
  thalesgroup.ciphertrust.cm_resource_delete:
    key: DemoProtectionPolicy
    resource_type: "protection-policies"
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
    createProtectionPolicy,
    updateProtectionPolicy,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    policy_name=dict(type="str"),
    algorithm=dict(type="str"),
    key=dict(type="str", no_log=False),
    name=dict(type="str"),
    allow_single_char_input=dict(type="bool"),
    character_set_id=dict(type="str"),
    iv=dict(type="str"),
    tweak=dict(type="str"),
    tweak_algorithm=dict(type="str", choices=["SHA1", "SHA256", "None"]),
    disable_versioning=dict(type="bool"),
    use_external_versioning=dict(type="bool"),
    masking_format_id=dict(type="str"),
    access_policy_name=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["policy_name"]],
            ["op_type", "create", ["access_policy_name", "algorithm", "key", "name"]],
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
                endpoint="data-protection/protection-policies",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createProtectionPolicy,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    access_policy_name=module.params.get("access_policy_name"),
                    masking_format_id=module.params.get("masking_format_id"),
                    algorithm=module.params.get("algorithm"),
                    key=module.params.get("key"),
                    name=module.params.get("name"),
                    allow_single_char_input=module.params.get(
                        "allow_single_char_input"
                    ),  # Parameter not applicable with CM v2.12
                    character_set_id=module.params.get("character_set_id"),
                    iv=module.params.get("iv"),
                    tweak=module.params.get("tweak"),
                    tweak_algorithm=module.params.get("tweak_algorithm"),
                    disable_versioning=module.params.get(
                        "disable_versioning"
                    ),  # Parameter added in CM v2.12
                    use_external_versioning=module.params.get(
                        "use_external_versioning"
                    ),  # Parameter added in CM v2.12
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="data-protection/protection-policies",
                resource_id=module.params.get("policy_name"),
                ignore_fields=("policy_name",),
                patch_fn=updateProtectionPolicy,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    policy_name=module.params.get("policy_name"),
                    access_policy_name=module.params.get("access_policy_name"),
                    masking_format_id=module.params.get("masking_format_id"),
                    algorithm=module.params.get("algorithm"),
                    key=module.params.get("key"),
                    allow_single_char_input=module.params.get(
                        "allow_single_char_input"
                    ),  # Parameter not applicable with CM v2.12
                    character_set_id=module.params.get("character_set_id"),
                    iv=module.params.get("iv"),
                    tweak=module.params.get("tweak"),
                    tweak_algorithm=module.params.get("tweak_algorithm"),
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
