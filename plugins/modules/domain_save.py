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
module: domain_save
short_description: Create or manage domains
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with domains management API
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
    domain_id:
        description: ID of the domain to be updated
        type: str
    name:
        description: The name of the domain
        type: str
    admins:
        description: List of administrators for the domain
        type: list
        elements: str
    allow_user_management:
        description: To allow user creation and management in the domain, set it to true
        required: false
        default: false
        type: bool
    hsm_connection_id:
        description: The ID of the HSM connection. Required for HSM-anchored domains.
        required: false
        type: str
    hsm_kek_label:
        description:
          - Optional name field for the domain KEK for an HSM-anchored domain.
          - If not provided, a random UUID is assigned for KEK label.
        required: false
        type: str
    meta:
        description: Optional end-user or service data stored with the domain.
        required: false
        default: null
        type: dict
    parent_ca_id:
        description:
          - This optional parameter is the ID or URI of the parent domain's CA.
          - This CA is used for signing the default CA of a newly created sub-domain.
          - The oldest CA in the parent domain is used if this value is not supplied.
        required: false
        type: str
    connection_id:
        description: HSM connection ID pertaining to the domain KEK
        required: false
        type: str
    domain_kek_label:
        description: Label of the target domain KEK
        required: false
        type: str
"""

EXAMPLES = """
- name: "Create Domain"
  thalesgroup.ciphertrust.domain_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: create
    admins:
      - local|4d1c26ab-8730-4d44-af5c-9a8641d0266d
      - local|c7cf4efc-df81-4446-a30e-2dd5badf44b4
    name: AnsibleDomain
    parent_ca_id: a5e0fa8a-a7f7-434c-ade8-f84de040269a

- name: "Patch Domain"
  thalesgroup.ciphertrust.domain_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: patch
    domain_id: "ID_STRING"
    connection_id: "ID_STRING"
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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.domains import (
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
    domain_id=dict(type="str"),
    admins=dict(type="list", elements="str"),
    name=dict(type="str"),
    allow_user_management=dict(type="bool", required=False, default=False),
    hsm_connection_id=dict(type="str", required=False),
    hsm_kek_label=dict(type="str", required=False),
    meta=dict(type="dict", options=_schema_less, required=False),
    parent_ca_id=dict(type="str", required=False),
    connection_id=dict(type="str", required=False),
    domain_kek_label=dict(type="str", required=False),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["domain_id"]],
            ["op_type", "create", ["admins"]],
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
                endpoint="domains",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=create,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    admins=module.params.get("admins"),
                    name=module.params.get("name"),
                    allow_user_management=module.params.get("allow_user_management"),
                    hsm_connection_id=module.params.get("hsm_connection_id"),
                    hsm_kek_label=module.params.get("hsm_kek_label"),
                    meta=module.params.get("meta"),
                    parent_ca_id=module.params.get("parent_ca_id"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="domains",
                resource_id=module.params.get("domain_id"),
                ignore_fields=("domain_id",),
                patch_fn=patch,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    domain_id=module.params.get("domain_id"),
                    connection_id=module.params.get("connection_id"),
                    domain_kek_label=module.params.get("domain_kek_label"),
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
