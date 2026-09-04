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
module: cckm_azure_secret_info
short_description: Read Azure Key Vault secrets known to CCKM
description:
    - Lists or reads the Azure Key Vault secrets CCKM manages.
    - Create or act on a secret with M(thalesgroup.ciphertrust.cckm_azure_secret).
    - Secret values are held in Azure; CCKM returns metadata.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description:
        - Which read to perform.
        - C(list) returns a filtered collection; C(get) reads one secret.
      choices: [list, get]
      default: list
      type: str
    secret_id:
      description:
        - Identifier of the secret.
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    key_vault:
      description:
        - Filter by vault name.
      type: str
    key_vault_id:
      description:
        - Filter by vault id.
      type: str
    secret_name:
      description:
        - Filter by secret name.
      type: str
    region:
      description:
        - Filter by Azure region.
      type: str
    status:
      description:
        - Filter by secret status.
      type: str
    version:
      description:
        - Filter by secret version.
      type: str
    enabled:
      description:
        - Filter by whether the secret is enabled.
      type: bool
    backup:
      description:
        - Filter by whether a backup exists.
      type: bool
    deleted_in_azure:
      description:
        - Filter by secrets deleted in Azure.
      type: bool
    gone:
      description:
        - Filter by secrets no longer present in Azure.
      type: bool
    managed:
      description:
        - Filter by Azure-managed secrets.
      type: bool
    tags:
      description:
        - Filter by tag.
      type: list
      elements: str
    skip:
      description:
        - Number of records to skip.
      type: int
    limit:
      description:
        - Maximum number of records to return.
      type: int
    sort:
      description:
        - Comma-separated fields to sort by.
      type: str
"""

EXAMPLES = """
- name: "List the secrets in one vault"
  thalesgroup.ciphertrust.cckm_azure_secret_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    key_vault: production-vault

- name: "Read one secret"
  thalesgroup.ciphertrust.cckm_azure_secret_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    secret_id: "{{ _secret.response.id }}"
"""

RETURN = r"""
changed:
    description: Always C(false). These operations only read.
    returned: always
    type: bool
    sample: false
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API.
      - A list operation returns a C(resources) array with C(skip), C(limit)
        and C(total); a get returns the resource itself.
    returned: always
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_azure,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get"], default="list"),
    secret_id=dict(type="str"),
    id=dict(type="str"),
    key_vault=dict(type="str", no_log=False),
    key_vault_id=dict(type="str", no_log=False),
    secret_name=dict(type="str"),
    region=dict(type="str"),
    status=dict(type="str"),
    version=dict(type="str"),
    enabled=dict(type="bool"),
    backup=dict(type="bool"),
    deleted_in_azure=dict(type="bool"),
    gone=dict(type="bool"),
    managed=dict(type="bool"),
    tags=dict(type="list", elements="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "key_vault": "key_vault",
    "key_vault_id": "key_vault_id",
    "secret_name": "secret_name",
    "region": "region",
    "status": "status",
    "backup": "backup",
    "enabled": "enabled",
    "deleted_in_azure": "deleted_in_azure",
    "gone": "gone",
    "version": "version",
    "tags": "tags",
    "managed": "managed",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["secret_id"]],
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
    op_type = module.params.get("op_type")

    # Reading changes nothing, so every operation runs unchanged under --check.
    with ciphertrust_operation(module):
        if op_type == "list":
            result["response"] = cckm_azure.secret_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_azure.secret_get(
                node=node,
                secret_id=module.params.get("secret_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
