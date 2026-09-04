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
module: cckm_azure_key_info
short_description: Read Azure keys, their backups and public key material from CCKM
description:
    - Lists or reads the Azure Key Vault keys CCKM manages, lists and reads the cloud
      key backups taken of them, and downloads a key's public half.
    - Create or act on a key with M(thalesgroup.ciphertrust.cckm_azure_key).
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
        - C(list) and C(get) read keys.
        - C(list_backups) and C(get_backup) read the backups of one key.
        - C(download_public_key) returns the public half of an asymmetric key.
      choices: [list, get, list_backups, get_backup, download_public_key]
      default: list
      type: str
    key_id:
      description:
        - Identifier of the key.
      type: str
    backup_id:
      description:
        - Identifier of the backup.
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
    key_name:
      description:
        - Filter by key name.
      type: str
    cloud_name:
      description:
        - Filter by Azure cloud.
      type: str
    region:
      description:
        - Filter by Azure region.
      type: str
    kid:
      description:
        - Filter by Azure key identifier.
      type: str
    version:
      description:
        - Filter by key version.
      type: str
    algorithm:
      description:
        - Filter by key algorithm.
      type: str
    crv:
      description:
        - Filter by elliptic curve name.
      type: str
    key_size:
      description:
        - Filter by key size.
      type: int
    status:
      description:
        - Filter by key status.
      type: str
    enabled:
      description:
        - Filter by whether the key is enabled.
      type: bool
    backup:
      description:
        - Filter by whether a backup exists.
      type: bool
    deleted_in_azure:
      description:
        - Filter by keys deleted in Azure.
      type: bool
    gone:
      description:
        - Filter by keys no longer present in Azure.
      type: bool
    managed:
      description:
        - Filter by Azure-managed keys.
      type: bool
    rotation_job_enabled:
      description:
        - Filter by rotation job state.
      type: bool
    job_config_id:
      description:
        - Filter by rotation job configuration id.
      type: str
    backup_job_config_id:
      description:
        - Filter by backup job configuration id.
      type: str
    key_material_origin:
      description:
        - Filter by where the key material came from.
      type: str
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
- name: "List the keys in one vault"
  thalesgroup.ciphertrust.cckm_azure_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    key_vault: production-vault

- name: "List the backups taken of a key"
  thalesgroup.ciphertrust.cckm_azure_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list_backups
    key_id: "{{ _key.response.id }}"

- name: "Download a key's public half"
  thalesgroup.ciphertrust.cckm_azure_key_info:
    localNode: "{{ cm_connection }}"
    op_type: download_public_key
    key_id: "{{ _key.response.id }}"
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
    op_type=dict(type="str", choices=["list", "get", "list_backups", "get_backup", "download_public_key"], default="list"),
    key_id=dict(type="str"),
    backup_id=dict(type="str"),
    id=dict(type="str"),
    key_vault=dict(type="str", no_log=False),
    key_vault_id=dict(type="str", no_log=False),
    key_name=dict(type="str", no_log=False),
    cloud_name=dict(type="str"),
    region=dict(type="str"),
    kid=dict(type="str"),
    version=dict(type="str"),
    algorithm=dict(type="str"),
    crv=dict(type="str"),
    key_size=dict(type="int", no_log=False),
    status=dict(type="str"),
    enabled=dict(type="bool"),
    backup=dict(type="bool"),
    deleted_in_azure=dict(type="bool"),
    gone=dict(type="bool"),
    managed=dict(type="bool"),
    rotation_job_enabled=dict(type="bool"),
    job_config_id=dict(type="str"),
    backup_job_config_id=dict(type="str"),
    key_material_origin=dict(type="str", no_log=False),
    tags=dict(type="list", elements="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "key_vault": "key_vault",
    "key_vault_id": "key_vault_id",
    "key_name": "key_name",
    "cloud_name": "cloud_name",
    "region": "region",
    "crv": "crv",
    "status": "status",
    "backup": "backup",
    "enabled": "enabled",
    "key_size": "key_size",
    "job_config_id": "job_config_id",
    "backup_job_config_id": "backup_job_config_id",
    "deleted_in_azure": "deleted_in_azure",
    "algorithm": "algorithm",
    "kid": "kid",
    "gone": "gone",
    "version": "version",
    "rotation_job_enabled": "rotation_job_enabled",
    "tags": "tags",
    "key_material_origin": "key_material_origin",
    "managed": "managed",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["key_id"]],
            ["op_type", "list_backups", ["key_id"]],
            ["op_type", "get_backup", ["key_id", "backup_id"]],
            ["op_type", "download_public_key", ["key_id"]],
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
            result["response"] = cckm_azure.key_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_azure.key_get(
                node=node,
                key_id=module.params.get("key_id"),
            )
        elif op_type == "list_backups":
            result["response"] = cckm_azure.key_backup_list(
                node=node,
                key_id=module.params.get("key_id"),
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get_backup":
            result["response"] = cckm_azure.key_backup_get(
                node=node,
                key_id=module.params.get("key_id"),
                backup_id=module.params.get("backup_id"),
            )
        elif op_type == "download_public_key":
            result["response"] = cckm_azure.key_download_public_key(
                node=node,
                key_id=module.params.get("key_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
