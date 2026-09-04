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
module: cckm_oci_vault_info
short_description: Read OCI vaults known to CCKM, and discover new ones
description:
    - Lists or reads the OCI Vaults CCKM manages, and discovers the vaults that exist in
      a compartment and region but have not been added yet.
    - Add or create a vault with M(thalesgroup.ciphertrust.cckm_oci_vault).
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
        - C(list) and C(get) read the vaults CCKM already manages.
        - C(available) asks OCI what exists in a compartment and region, and stores
          nothing. It needs I(connection), I(compartment_id) and I(region).
      choices: [list, get, available]
      default: list
      type: str
    vault_id:
      description:
        - Identifier of the vault.
      type: str
    connection:
      description:
        - Name or id of the OCI connection to look through.
        - Required for I(op_type=available).
      type: str
    compartment_id:
      description:
        - Compartment to look in.
        - Required for I(op_type=available).
      type: str
    oci_next_page:
      description:
        - Continuation token from a previous discovery response.
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    display_name:
      description:
        - Filter by display name.
      type: str
    vault_name:
      description:
        - Filter by vault name.
      type: str
    vault_type:
      description:
        - Filter by vault type.
      type: str
    external_vault_type:
      description:
        - Filter by external vault type.
      type: str
    linked_state:
      description:
        - Filter by whether the vault is linked.
      type: bool
    issuer_id:
      description:
        - Filter by issuer.
      type: str
    state:
      description:
        - Filter by CCKM state.
      type: str
    lifecycle_state:
      description:
        - Filter by OCI lifecycle state.
      type: str
    cloud_name:
      description:
        - Filter by cloud name.
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
        - Required for I(op_type=available).
      type: str
    source_key_tier:
      description:
        - Filter by where key material is held.
      type: str
    blocked:
      description:
        - Filter by whether the vault is blocked.
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
- name: "Discover vaults that could be added"
  thalesgroup.ciphertrust.cckm_oci_vault_info:
    localNode: "{{ cm_connection }}"
    op_type: available
    connection: oci-production
    compartment_id: "ocid1.compartment.oc1..aaaa"
    region: us-ashburn-1

- name: "List the external vaults CCKM manages"
  thalesgroup.ciphertrust.cckm_oci_vault_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    vault_type: external
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

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get", "available"], default="list"),
    vault_id=dict(type="str"),
    connection=dict(type="str"),
    compartment_id=dict(type="str"),
    oci_next_page=dict(type="str"),
    id=dict(type="str"),
    display_name=dict(type="str"),
    vault_name=dict(type="str"),
    vault_type=dict(type="str"),
    external_vault_type=dict(type="str"),
    linked_state=dict(type="bool"),
    issuer_id=dict(type="str"),
    state=dict(type="str"),
    lifecycle_state=dict(type="str"),
    cloud_name=dict(type="str"),
    tenancy=dict(type="str"),
    compartment_name=dict(type="str"),
    region=dict(type="str"),
    source_key_tier=dict(type="str", no_log=False),
    blocked=dict(type="bool"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "display_name": "display_name",
    "vault_name": "vault_name",
    "linked_state": "linked_state",
    "issuer_id": "issuer_id",
    "state": "state",
    "external_vault_type": "external_vault_type",
    "cloud_name": "cloud_name",
    "vault_id": "vault_id",
    "vault_type": "vault_type",
    "tenancy": "tenancy",
    "compartment_name": "compartment_name",
    "lifecycle_state": "lifecycle_state",
    "region": "region",
    "source_key_tier": "source_key_tier",
    "blocked": "blocked",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["vault_id"]],
            ["op_type", "available", ["connection", "compartment_id", "region"]],
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
            result["response"] = cckm_oci.vault_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_oci.vault_get(
                node=node,
                vault_id=module.params.get("vault_id"),
            )
        elif op_type == "available":
            result["response"] = cckm_oci.vaults_available(
                node=node,
                connection=module.params.get("connection"),
                compartment_id=module.params.get("compartment_id"),
                region=module.params.get("region"),
                limit=module.params.get("limit"),
                oci_next_page=module.params.get("oci_next_page"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
