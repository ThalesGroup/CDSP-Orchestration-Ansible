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
module: cckm_azure_subscription_info
short_description: Read Azure subscriptions known to CCKM, and discover new ones
description:
    - Lists or reads the Azure subscriptions CCKM knows about, and discovers the
      subscriptions a connection can reach.
    - A subscription is the container a vault is added from, so C(available) is usually
      the first CCKM Azure call a playbook makes.
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
        - C(list) and C(get) read what CCKM already knows.
        - C(available) asks Azure through I(connection) and stores nothing.
      choices: [list, get, available]
      default: list
      type: str
    subscription_id:
      description:
        - Identifier of the subscription.
      type: str
    connection:
      description:
        - Name or id of the Azure connection to look through.
        - Required for I(op_type=available).
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    display_name:
      description:
        - Filter by subscription display name.
      type: str
    azure_subscription_id:
      description:
        - Filter by the Azure subscription GUID.
        - Distinct from I(subscription_id), which is the identifier of the record inside
          CCKM.
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
- name: "Discover the subscriptions a connection can reach"
  thalesgroup.ciphertrust.cckm_azure_subscription_info:
    localNode: "{{ cm_connection }}"
    op_type: available
    connection: azure-production

- name: "List the subscriptions CCKM knows about"
  thalesgroup.ciphertrust.cckm_azure_subscription_info:
    localNode: "{{ cm_connection }}"
    op_type: list
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
    op_type=dict(type="str", choices=["list", "get", "available"], default="list"),
    subscription_id=dict(type="str"),
    connection=dict(type="str"),
    id=dict(type="str"),
    display_name=dict(type="str"),
    azure_subscription_id=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "display_name": "displayName",
    "azure_subscription_id": "subscriptionId",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["subscription_id"]],
            ["op_type", "available", ["connection"]],
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
            result["response"] = cckm_azure.subscription_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_azure.subscription_get(
                node=node,
                subscription_id=module.params.get("subscription_id"),
            )
        elif op_type == "available":
            result["response"] = cckm_azure.subscriptions_available(
                node=node,
                connection=module.params.get("connection"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
