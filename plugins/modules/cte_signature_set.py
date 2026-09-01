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
module: cte_signature_set
short_description: Create and manage CTE Signature Sets
description:
    - Create and edit CTE signature set or add, edit, or remove a signature to or from the signature set
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch, add_signature, get_signature, delete_signature, sign_app, query_sign_app, cancel_sign_app]
      required: true
      type: str
    id:
      description:
        - Identifier of the CTE SignatureSet to be patched
      type: str
    signature_id:
      description:
        - Identifier of the Signature within the CTE SignatureSet to be patched
      type: str
    name:
      description:
        - Name of the signature set
      type: str
    description:
      description:
        - Description of the signature set
      type: str
    source_list:
      description:
        - Path of the directory or file to be signed. If a directory is specified, all files in the directory and its subdirectories are signed.
      type: list
      elements: str
    signatures:
      description:
        - Name of the signature set
      type: list
      elements: dict
      suboptions:
        file_name:
          description: file name
          type: str
        hash_value:
          description: hash value
          type: str
    client_id:
      description:
        - ID of the client where the signing request is to be sent
      type: str
    file_name:
        description: file name
        type: str
    hash_value:
        description: hash value
        type: str
"""

EXAMPLES = """
- name: "Create CTE Signature Set"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: TestSignSet
    source_list:
      - "/usr/bin"
      - "/usr/sbin"
  register: signature_set

- name: "Add signature to a Signature Set"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_signature
    id: "signatureSetID"
    source_list:
      - "/usr/bin"
  register: signature

- name: "Remove a signature from a Signature Set"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: delete_signature
    id: "signatureSetID"
    signature_id: "signatureSetID"

- name: "Sends a signature signing request to the client"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: sign_app
    id: "signatureSetID"
    client_id: Client1
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
    createSignatureSet,
    updateSignatureSet,
    addSignatureToSet,
    deleteSignatureInSetById,
    sendSignAppRequest,
    querySignAppRequest,
    cancelSignAppRequest,
    getSignatureFromSetByFilter,
)

_signature = dict(
    file_name=dict(type="str"),
    hash_value=dict(type="str"),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "add_signature",
            "get_signature",
            "delete_signature",
            "sign_app",
            "query_sign_app",
            "cancel_sign_app",
        ],
        required=True,
    ),
    id=dict(type="str"),
    signature_id=dict(type="str"),
    name=dict(type="str"),
    description=dict(type="str"),
    source_list=dict(type="list", elements="str"),
    signatures=dict(type="list", elements="dict", options=_signature),
    client_id=dict(type="str"),
    hash_value=dict(type="str"),
    file_name=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name"]],
            ["op_type", "patch", ["id"]],
            ["op_type", "add_signature", ["id", "signatures"]],
            ["op_type", "get_signature", ["id"]],
            ["op_type", "delete_signature", ["id", "signature_id"]],
            ["op_type", "sign_app", ["id", "client_id"]],
            ["op_type", "query_sign_app", ["id", "client_id"]],
            ["op_type", "cancel_sign_app", ["id", "client_id"]],
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
                endpoint="transparent-encryption/signaturesets",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createSignatureSet,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    description=module.params.get("description"),
                    source_list=module.params.get("source_list"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="transparent-encryption/signaturesets",
                resource_id=module.params.get("id"),
                ignore_fields=("id",),
                patch_fn=updateSignatureSet,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    id=module.params.get("id"),
                    description=module.params.get("description"),
                    source_list=module.params.get("source_list"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "add_signature":
            check_mode_action(module)
            response = addSignatureToSet(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                signatures=module.params.get("signatures"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "get_signature":
            response = getSignatureFromSetByFilter(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                hash_value=module.params.get("hash_value"),
                file_name=module.params.get("file_name"),
            )
            result["response"] = response

        elif module.params.get("op_type") == "delete_signature":
            check_mode_action(module)
            response = deleteSignatureInSetById(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                signature_id=module.params.get("signature_id"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "sign_app":
            check_mode_action(module)
            response = sendSignAppRequest(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_id=module.params.get("client_id"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "query_sign_app":
            response = querySignAppRequest(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_id=module.params.get("client_id"),
            )
            result["response"] = response

        elif module.params.get("op_type") == "cancel_sign_app":
            check_mode_action(module)
            response = cancelSignAppRequest(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_id=module.params.get("client_id"),
            )
            result["response"] = response
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
