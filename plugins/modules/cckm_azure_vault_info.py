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
module: cckm_azure_vault_info
short_description: Read Azure key vaults known to CCKM, and discover new ones
description:
    - Lists or reads the Azure key vaults CCKM manages, and discovers the vaults and
      managed HSMs a connection can see in Azure but that have not been added yet.
    - Add a discovered vault with M(thalesgroup.ciphertrust.cckm_azure_vault).
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
        - C(available) and C(managed_hsms) ask Azure through a connection what exists
          there, and store nothing. Both need I(connection) and I(subscription_id).
      choices: [list, get, available, managed_hsms]
      default: list
      type: str
    vault_id:
      description:
        - Identifier of the vault to read.
      type: str
    connection:
      description:
        - Name or id of the Azure connection to look through.
        - Required for I(op_type=available) and I(op_type=managed_hsms).
      type: str
    subscription_id:
      description:
        - Azure subscription to look in.
        - Required for I(op_type=available) and I(op_type=managed_hsms).
      type: str
    next_link:
      description:
        - Continuation token from a previous discovery response.
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    name:
      description:
        - Filter by vault name.
      type: str
    location:
      description:
        - Filter by Azure location.
      type: str
    cloud_name:
      description:
        - Filter by Azure cloud.
      type: str
    subscription_name:
      description:
        - Filter by subscription name.
      type: str
    job_config_id:
      description:
        - Filter by rotation job configuration id.
      type: str
    type:
      description:
        - Filter by vault type.
      type: str
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
- name: "List the vaults CCKM manages"
  thalesgroup.ciphertrust.cckm_azure_vault_info:
    localNode: "{{ cm_connection }}"
    op_type: list

- name: "Discover vaults that could be added"
  thalesgroup.ciphertrust.cckm_azure_vault_info:
    localNode: "{{ cm_connection }}"
    op_type: available
    connection: azure-production
    subscription_id: "00000000-0000-0000-0000-000000000000"
  register: _available

- name: "Read one vault"
  thalesgroup.ciphertrust.cckm_azure_vault_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    vault_id: "{{ _vault.response.id }}"
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
    op_type=dict(type="str", choices=["list", "get", "available", "managed_hsms"], default="list"),
    vault_id=dict(type="str"),
    connection=dict(type="str"),
    subscription_id=dict(type="str"),
    next_link=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="str"),
    location=dict(type="str"),
    cloud_name=dict(type="str"),
    subscription_name=dict(type="str"),
    job_config_id=dict(type="str"),
    type=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "name": "name",
    "location": "location",
    "cloud_name": "cloud_name",
    "subscription_id": "subscription_id",
    "subscription_name": "subscription_name",
    "job_config_id": "job_config_id",
    "type": "type",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["vault_id"]],
            ["op_type", "available", ["connection", "subscription_id"]],
            ["op_type", "managed_hsms", ["connection", "subscription_id"]],
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
            result["response"] = cckm_azure.vault_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_azure.vault_get(
                node=node,
                vault_id=module.params.get("vault_id"),
            )
        elif op_type == "available":
            result["response"] = cckm_azure.vaults_available(
                node=node,
                connection=module.params.get("connection"),
                subscription_id=module.params.get("subscription_id"),
                limit=module.params.get("limit"),
                next_link=module.params.get("next_link"),
            )
        elif op_type == "managed_hsms":
            result["response"] = cckm_azure.managed_hsms_available(
                node=node,
                connection=module.params.get("connection"),
                subscription_id=module.params.get("subscription_id"),
                limit=module.params.get("limit"),
                next_link=module.params.get("next_link"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
