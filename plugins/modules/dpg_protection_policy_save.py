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
  - thalesgroup.ciphertrust.attributes
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
        - Name of an existing access policy to associate with the protection
          policy.
        - Required when I(op_type=create); CipherTrust Manager rejects a
          create without it.
      type: str
    masking_format_id:
      description:
        - ID of the Static Masking Format
      type: str
    algorithm:
      description:
        - Algorithm to be used during crypto operations.
        - CipherTrust Manager enforces requirements that depend on this value.
          C(AES/CBC/NoPadding) and C(AES/CBC/PKCS5Padding) require a 16-byte
          I(iv) unless I(random_nonce) is set; C(AES/GCM) requires a 1-16 byte
          I(iv) and a I(tag_length); the C(FPE/*) algorithms and C(Random2)
          require a I(character_set_id).
      choices:
        - AES/CBC/NoPadding
        - AES/CBC/PKCS5Padding
        - AES/ECB/NoPadding
        - AES/ECB/PKCS5Padding
        - AES/GCM
        - Random2
        - FPE/AES/UNICODE
        - FPE/FF1v2/UNICODE
        - FPE/FF3/UNICODE
        - FPE/FF3-1/UNICODE
      type: str
    key:
      description: Name of the key
      type: str
    name:
      description: Unique name for the protection policy
      type: str
    allow_small_input:
      description:
        - If true, input shorter than the algorithm's minimum is passed through
          untransformed instead of failing the row.
        - Only supported for the FPE and Random2 algorithms.
        - Named C(allow_single_char_input) before 1.1.0. That spelling is
          accepted as an alias but is not the name CipherTrust Manager uses.
      type: bool
      aliases: [allow_single_char_input]
    description:
      description: Description of the protection policy.
      type: str
    tag_length:
      description:
        - Tag length for the C(AES/GCM) algorithm, which requires it.
        - Valid values are 32 to 128 in multiples of 8.
      type: int
    aad:
      description: Additional authenticated data for the C(AES/GCM) algorithm.
      type: str
    random_nonce:
      description:
        - Enables a randomly generated nonce, so no I(iv) need be supplied for
          C(AES/CBC/PKCS5Padding), C(AES/CBC/NoPadding) or C(AES/GCM).
      type: str
    prefix:
      description: Static string prepended to tokens. Maximum length 7.
      type: str
    data_format:
      description: Format in which the data to be protected is supplied.
      choices: [luhn]
      type: str
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
    name: DemoProtectionPolicy
    # CipherTrust Manager requires all four of these for a create.
    algorithm: "AES/CBC/PKCS5Padding"
    key: "aes_key"
    access_policy_name: "DemoAccessPolicy"
    # AES/CBC needs a 16-byte IV, unless random_nonce is set instead.
    iv: "0123456789abcdef"

- name: "Create a tokenizing Protection Policy"
  thalesgroup.ciphertrust.dpg_protection_policy_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: DemoTokenPolicy
    algorithm: "FPE/FF3-1/UNICODE"
    key: "fpe_key"
    access_policy_name: "DemoAccessPolicy"
    # The FPE algorithms and Random2 require a character set instead of an IV.
    character_set_id: "<CHAR_SET_ID>"
    tweak: "1628462495815733"
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
    algorithm=dict(
        type="str",
        choices=[
            "AES/CBC/NoPadding",
            "AES/CBC/PKCS5Padding",
            "AES/ECB/NoPadding",
            "AES/ECB/PKCS5Padding",
            "AES/GCM",
            "Random2",
            "FPE/AES/UNICODE",
            "FPE/FF1v2/UNICODE",
            "FPE/FF3/UNICODE",
            "FPE/FF3-1/UNICODE",
        ],
    ),
    key=dict(type="str", no_log=False),
    name=dict(type="str"),
    allow_small_input=dict(
        type="bool", aliases=["allow_single_char_input"]
    ),
    description=dict(type="str"),
    tag_length=dict(type="int"),
    aad=dict(type="str"),
    random_nonce=dict(type="str"),
    prefix=dict(type="str"),
    data_format=dict(type="str", choices=["luhn"]),
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
                    allow_small_input=module.params.get("allow_small_input"),
                    description=module.params.get("description"),
                    tag_length=module.params.get("tag_length"),
                    aad=module.params.get("aad"),
                    random_nonce=module.params.get("random_nonce"),
                    prefix=module.params.get("prefix"),
                    data_format=module.params.get("data_format"),
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
                    allow_small_input=module.params.get("allow_small_input"),
                    description=module.params.get("description"),
                    tag_length=module.params.get("tag_length"),
                    aad=module.params.get("aad"),
                    random_nonce=module.params.get("random_nonce"),
                    prefix=module.params.get("prefix"),
                    data_format=module.params.get("data_format"),
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
