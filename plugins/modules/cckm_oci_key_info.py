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
module: cckm_oci_key_info
short_description: Read OCI Vault keys and their versions from CCKM
description:
    - Lists or reads the OCI Vault keys CCKM manages, and lists or reads their versions.
    - Create or act on a key with M(thalesgroup.ciphertrust.cckm_oci_key).
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
        - C(list_versions) and C(get_version) read the versions of one key.
      choices: [list, get, list_versions, get_version]
      default: list
      type: str
    key_id:
      description:
        - Identifier of the key in CCKM.
      type: str
    version_id:
      description:
        - Identifier of the key version.
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    key_name:
      description:
        - Filter by key name.
      type: str
    algorithm:
      description:
        - Filter by key algorithm.
      type: str
    length:
      description:
        - Filter by key length.
      type: int
    curve_id:
      description:
        - Filter by elliptic curve.
      type: str
    vault_name:
      description:
        - Filter by vault name.
      type: str
    vault_id:
      description:
        - Filter by the vault's OCID.
      type: str
    cckm_vault_id:
      description:
        - Filter by the vault's CCKM id.
      type: str
    protection_mode:
      description:
        - Filter by protection mode.
      type: str
    job_config_id:
      description:
        - Filter by rotation job configuration id.
      type: str
    lifecycle_state:
      description:
        - Filter by OCI lifecycle state.
      type: str
    state:
      description:
        - Filter by CCKM state.
      type: str
    tenancy:
      description:
        - Filter by tenancy.
      type: str
    compartment_name:
      description:
        - Filter by compartment name.
      type: str
    region:
      description:
        - Filter by OCI region.
      type: str
    gone:
      description:
        - Filter by keys no longer present in OCI.
      type: bool
    blocked:
      description:
        - Filter by whether the key is blocked.
      type: bool
    linked_state:
      description:
        - Filter by whether the key is linked.
      type: bool
    key_material_origin:
      description:
        - Filter by where the key material came from.
      type: str
    local_hyok_key_id:
      description:
        - Filter by the backing CipherTrust Manager key.
      type: str
    local_hyok_key_version_id:
      description:
        - Filter by the backing CipherTrust Manager key version.
      type: str
    local_key_store_id:
      description:
        - Filter by the backing local key store.
      type: str
    origin:
      description:
        - Filter versions by origin.
      type: str
    is_primary:
      description:
        - Filter versions by whether they are primary.
      type: bool
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
  thalesgroup.ciphertrust.cckm_oci_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    vault_name: production-vault

- name: "List the versions of a key"
  thalesgroup.ciphertrust.cckm_oci_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list_versions
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
    cckm_oci,
)

_VERSION_FILTERS = {
    "version_id": "version_id",
    "id": "id",
    "origin": "origin",
    "is_primary": "is_primary",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get", "list_versions", "get_version"], default="list"),
    key_id=dict(type="str", no_log=False),
    version_id=dict(type="str"),
    id=dict(type="str"),
    key_name=dict(type="str", no_log=False),
    algorithm=dict(type="str"),
    length=dict(type="int"),
    curve_id=dict(type="str"),
    vault_name=dict(type="str"),
    vault_id=dict(type="str"),
    cckm_vault_id=dict(type="str"),
    protection_mode=dict(type="str"),
    job_config_id=dict(type="str"),
    lifecycle_state=dict(type="str"),
    state=dict(type="str"),
    tenancy=dict(type="str"),
    compartment_name=dict(type="str"),
    region=dict(type="str"),
    gone=dict(type="bool"),
    blocked=dict(type="bool"),
    linked_state=dict(type="bool"),
    key_material_origin=dict(type="str", no_log=False),
    local_hyok_key_id=dict(type="str", no_log=False),
    local_hyok_key_version_id=dict(type="str", no_log=False),
    local_key_store_id=dict(type="str", no_log=False),
    origin=dict(type="str"),
    is_primary=dict(type="bool"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "key_name": "key_name",
    "algorithm": "algorithm",
    "length": "length",
    "key_id": "key_id",
    "vault_name": "vault_name",
    "protection_mode": "protection_mode",
    "job_config_id": "job_config_id",
    "lifecycle_state": "lifecycle_state",
    "tenancy": "tenancy",
    "compartment_name": "compartment_name",
    "vault_id": "vault_id",
    "cckm_vault_id": "cckm_vault_id",
    "curve_id": "curve_id",
    "gone": "gone",
    "region": "region",
    "local_hyok_key_id": "local_hyok_key_id",
    "local_hyok_key_version_id": "local_hyok_key_version_id",
    "local_key_store_id": "local_key_store_id",
    "linked_state": "linked_state",
    "key_material_origin": "key_material_origin",
    "blocked": "blocked",
    "state": "state",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["key_id"]],
            ["op_type", "list_versions", ["key_id"]],
            ["op_type", "get_version", ["key_id", "version_id"]],
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
            result["response"] = cckm_oci.key_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_oci.key_get(
                node=node,
                key_id=module.params.get("key_id"),
            )
        elif op_type == "list_versions":
            result["response"] = cckm_oci.key_version_list(
                node=node,
                key_id=module.params.get("key_id"),
                filters={api: module.params.get(name)
                         for name, api in _VERSION_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get_version":
            result["response"] = cckm_oci.key_version_get(
                node=node,
                key_id=module.params.get("key_id"),
                version_id=module.params.get("version_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
