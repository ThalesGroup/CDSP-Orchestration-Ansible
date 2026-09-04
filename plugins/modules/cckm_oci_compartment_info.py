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
module: cckm_oci_compartment_info
short_description: Read OCI compartments known to CCKM, and discover compartments, tags and buckets
description:
    - Lists or reads the OCI compartments CCKM manages, and discovers the compartments,
      defined tags and Object Storage buckets a connection can reach.
    - Add a compartment with M(thalesgroup.ciphertrust.cckm_oci_compartment).
    - A bucket is where an added vault's backups are written, so C(buckets) is usually
      read before adding a vault.
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
        - C(list) and C(get) read the compartments CCKM already manages.
        - C(available) asks OCI which compartments exist, C(defined_tags) which defined
          tags the tenancy offers, and C(buckets) which Object Storage buckets a
          compartment holds. None of them store anything.
      choices: [list, get, available, defined_tags, buckets]
      default: list
      type: str
    compartment_id:
      description:
        - Identifier of the compartment.
      type: str
    connection:
      description:
        - Name or id of the OCI connection to look through.
        - Required for the discovery operations.
      type: str
    oci_next_page:
      description:
        - Continuation token from a previous discovery response.
        - Sent to OCI as C(ociNextPage).
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    name:
      description:
        - Filter by compartment name.
      type: str
    tenancy:
      description:
        - Filter by tenancy.
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
- name: "Discover the compartments a connection can reach"
  thalesgroup.ciphertrust.cckm_oci_compartment_info:
    localNode: "{{ cm_connection }}"
    op_type: available
    connection: oci-production

- name: "List the buckets a compartment holds"
  thalesgroup.ciphertrust.cckm_oci_compartment_info:
    localNode: "{{ cm_connection }}"
    op_type: buckets
    connection: oci-production
    compartment_id: "ocid1.compartment.oc1..aaaa"
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
    op_type=dict(type="str", choices=["list", "get", "available", "defined_tags", "buckets"], default="list"),
    compartment_id=dict(type="str"),
    connection=dict(type="str"),
    oci_next_page=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="str"),
    tenancy=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "name": "name",
    "compartment_id": "compartment_id",
    "tenancy": "tenancy",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["compartment_id"]],
            ["op_type", "available", ["connection"]],
            ["op_type", "defined_tags", ["connection"]],
            ["op_type", "buckets", ["connection", "compartment_id"]],
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
            result["response"] = cckm_oci.compartment_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_oci.compartment_get(
                node=node,
                compartment_id=module.params.get("compartment_id"),
            )
        elif op_type == "available":
            result["response"] = cckm_oci.compartments_available(
                node=node,
                connection=module.params.get("connection"),
                limit=module.params.get("limit"),
                oci_next_page=module.params.get("oci_next_page"),
            )
        elif op_type == "defined_tags":
            result["response"] = cckm_oci.defined_tags_available(
                node=node,
                connection=module.params.get("connection"),
                limit=module.params.get("limit"),
                oci_next_page=module.params.get("oci_next_page"),
            )
        elif op_type == "buckets":
            result["response"] = cckm_oci.buckets_available(
                node=node,
                connection=module.params.get("connection"),
                compartment_id=module.params.get("compartment_id"),
                limit=module.params.get("limit"),
                oci_next_page=module.params.get("oci_next_page"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
