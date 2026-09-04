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
module: cckm_azure_secret
short_description: Manage Azure Key Vault secrets through CCKM
description:
    - Creates a secret in an Azure key vault, updates one, and drives the Azure soft-
      delete lifecycle.
    - Read secrets with M(thalesgroup.ciphertrust.cckm_azure_secret_info).
    - Azure deletion is two-stage -- C(soft_delete) moves the secret to the recycle bin,
      C(recover) restores it, and C(hard_delete) purges it.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) creates a secret; C(patch) updates its attributes, tags or content
          type.
        - C(delete) removes the CCKM record; C(soft_delete), C(recover), C(hard_delete)
          and C(restore) drive the Azure lifecycle.
      choices:
        - create
        - patch
        - delete
        - soft_delete
        - hard_delete
        - recover
        - restore
      required: true
      type: str
    secret_id:
      description:
        - Identifier of the secret in CCKM.
        - Required for every operation except C(create).
      type: str
    secret_name:
      description:
        - Name for the secret in Azure.
        - Azure secret names accept alphanumerics and hyphens only.
        - Required for C(create).
      type: str
    key_vault:
      description:
        - Name or id of the Azure vault.
        - Required for C(create).
      type: str
    azure_param:
      description:
        - Azure secret parameters.
        - Required for C(create).
      type: dict
      suboptions:
        value:
          description:
            - The secret's value.
            - CipherTrust Manager never returns this value.
          type: str
        content_type:
          description:
            - Content type recorded with the secret.
            - Sent to Azure as C(contentType).
          type: str
        tags:
          description:
            - Azure tags to set on the secret.
          type: dict
        attributes:
          description:
            - Azure secret attributes.
          type: dict
          suboptions:
            enabled:
              description:
                - Whether the object is enabled.
              type: bool
            nbf:
              description:
                - Not-before time, as an Azure timestamp.
              type: str
            exp:
              description:
                - Expiry time, as an Azure timestamp.
              type: str
    attributes:
      description:
        - Azure secret attributes to update. Used by C(patch).
      type: dict
      suboptions:
        enabled:
          description:
            - Whether the object is enabled.
          type: bool
        nbf:
          description:
            - Not-before time, as an Azure timestamp.
          type: str
        exp:
          description:
            - Expiry time, as an Azure timestamp.
          type: str
    tags:
      description:
        - Azure tags to set. Used by C(patch).
      type: dict
    content_type:
      description:
        - Content type to set. Used by C(patch).
      type: str
"""

EXAMPLES = """
- name: "Create a secret in an Azure vault"
  thalesgroup.ciphertrust.cckm_azure_secret:
    localNode: "{{ cm_connection }}"
    op_type: create
    secret_name: api-token
    key_vault: production-vault
    azure_param:
      value: "{{ vault_api_token }}"
      contentType: text/plain

- name: "Soft-delete the secret"
  thalesgroup.ciphertrust.cckm_azure_secret:
    localNode: "{{ cm_connection }}"
    op_type: soft_delete
    secret_id: "{{ _secret.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(create) and C(patch) report accurately; the lifecycle operations report
        C(true) whenever they run.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing resource when one was found during a GET-before-write
        idempotency check.
    returned: when the operation returns a body
    type: dict
diff:
    description: Present only in C(--diff) mode when a change occurred.
    returned: when diff mode is enabled and the module made a change
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_azure,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
    create_if_absent,
    find_resource_by_filters,
    idempotent_patch,
)
_attributes = dict(
    enabled=dict(type="bool"),
    nbf=dict(type="str"),
    exp=dict(type="str"),
)

_azure_param = dict(
    value=dict(type="str", no_log=True),
    content_type=dict(type="str"),
    tags=dict(type="dict"),
    attributes=dict(type="dict", options=_attributes),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "delete",
            "soft_delete",
            "hard_delete",
            "recover",
            "restore",
        ],
        required=True,
    ),
    secret_id=dict(type="str"),
    secret_name=dict(type="str"),
    key_vault=dict(type="str", no_log=False),
    azure_param=dict(type="dict", options=_azure_param),
    attributes=dict(type="dict", options=_attributes),
    tags=dict(type="dict"),
    content_type=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["secret_name", "key_vault", "azure_param"]],
            ["op_type", "patch", ["secret_id"]],
            ["op_type", "delete", ["secret_id"]],
            ["op_type", "soft_delete", ["secret_id"]],
            ["op_type", "hard_delete", ["secret_id"]],
            ["op_type", "recover", ["secret_id"]],
            ["op_type", "restore", ["secret_id"]],
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

    node = module.params.get("localNode")
    params = module.params
    op_type = params.get("op_type")
    client = CipherTrustClient(node)

    with ciphertrust_operation(module):
        if op_type == "create":
            existing = None
            if params.get("secret_name"):
                existing = find_resource_by_filters(
                    client, cckm_azure.SECRETS,
                    filters={"secret_name": params.get("secret_name"),
                             "key_vault": params.get("key_vault")},
                    confirm_fields=("key_vault",),
                )
            changed, response, diff = create_if_absent(
                module, existing,
                create_fn=cckm_azure.secret_create,
                create_kwargs=dict(
                    node=node,
                    secret_name=params.get("secret_name"),
                    key_vault=params.get("key_vault"),
                    azure_param=params.get("azure_param"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_azure.SECRETS,
                resource_id=params.get("secret_id"),
                ignore_fields=("secret_id",),
                patch_fn=cckm_azure.secret_patch,
                patch_kwargs=dict(
                    node=node,
                    secret_id=params.get("secret_id"),
                    attributes=params.get("attributes"),
                    tags=params.get("tags"),
                    content_type=params.get("content_type"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_azure.secret_delete(
                node=node,
                secret_id=params.get("secret_id"),
            )
            result["changed"] = True
        elif op_type in (
                "soft_delete", "hard_delete", "recover", "restore"):
            check_mode_action(module)
            result["response"] = cckm_azure.secret_action(
                node=node,
                secret_id=params.get("secret_id"),
                action=op_type.replace("_", "-"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
