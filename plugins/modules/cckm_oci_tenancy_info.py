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
module: cckm_oci_tenancy_info
short_description: Read OCI tenancies known to CCKM and the regions they subscribe to
description:
    - Lists or reads the Oracle Cloud Infrastructure tenancies CCKM knows about, and
      reads the regions a tenancy is subscribed to.
    - A tenancy is the root container in OCI; compartments, vaults and keys all sit
      inside one. Add a tenancy with M(thalesgroup.ciphertrust.cckm_oci_tenancy).
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
        - C(list) and C(get) read the tenancies CCKM knows about.
        - C(regions) asks OCI through I(connection) which regions the tenancy is
          subscribed to, and stores nothing.
      choices: [list, get, regions]
      default: list
      type: str
    tenancy_id:
      description:
        - Identifier of the tenancy record in CCKM.
      type: str
    connection:
      description:
        - Name or id of the OCI connection to look through.
        - Required for I(op_type=regions).
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    tenancy_ocid:
      description:
        - Filter by the tenancy's OCID.
      type: str
    tenancy:
      description:
        - Filter by tenancy name.
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
- name: "List the tenancies CCKM knows about"
  thalesgroup.ciphertrust.cckm_oci_tenancy_info:
    localNode: "{{ cm_connection }}"
    op_type: list

- name: "Read the regions a tenancy subscribes to"
  thalesgroup.ciphertrust.cckm_oci_tenancy_info:
    localNode: "{{ cm_connection }}"
    op_type: regions
    connection: oci-production
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
    op_type=dict(type="str", choices=["list", "get", "regions"], default="list"),
    tenancy_id=dict(type="str"),
    connection=dict(type="str"),
    id=dict(type="str"),
    tenancy_ocid=dict(type="str"),
    tenancy=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "tenancy_ocid": "tenancy_ocid",
    "tenancy": "tenancy",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["tenancy_id"]],
            ["op_type", "regions", ["connection"]],
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
            result["response"] = cckm_oci.tenancy_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_oci.tenancy_get(
                node=node,
                tenancy_id=module.params.get("tenancy_id"),
            )
        elif op_type == "regions":
            result["response"] = cckm_oci.subscribed_regions(
                node=node,
                connection=module.params.get("connection"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
