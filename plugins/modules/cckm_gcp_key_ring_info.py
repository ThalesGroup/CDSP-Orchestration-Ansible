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
module: cckm_gcp_key_ring_info
short_description: Read Cloud KMS key rings known to CCKM, and discover new ones
description:
    - Lists or reads the Cloud KMS key rings CCKM manages, and discovers the key rings
      that exist in a project's location but have not been added yet.
    - Add a discovered key ring with M(thalesgroup.ciphertrust.cckm_gcp_key_ring).
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
        - C(list) and C(get) read the key rings CCKM already manages.
        - C(available) asks Google Cloud what exists in a project's location and stores
          nothing. It needs I(connection), I(project_id) and I(location).
      choices: [list, get, available]
      default: list
      type: str
    key_ring_id:
      description:
        - Identifier of the key ring.
      type: str
    connection:
      description:
        - Name or id of the Google Cloud connection to look through.
        - Required for I(op_type=available).
      type: str
    page_size:
      description:
        - Maximum number of results per discovery page.
      type: int
    page_token:
      description:
        - Continuation token from a previous discovery response.
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    name:
      description:
        - Filter by key ring name.
      type: str
    cloud_name:
      description:
        - Filter by cloud name.
      type: str
    organization_name:
      description:
        - Filter by organisation name.
      type: str
    organization_display_name:
      description:
        - Filter by organisation display name.
      type: str
    location:
      description:
        - Filter by Cloud KMS location.
        - Required for I(op_type=available).
      type: str
    project_id:
      description:
        - Filter by Google Cloud project id.
        - Required for I(op_type=available).
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
- name: "Discover key rings that could be added"
  thalesgroup.ciphertrust.cckm_gcp_key_ring_info:
    localNode: "{{ cm_connection }}"
    op_type: available
    connection: gcp-production
    project_id: my-gcp-project
    location: us-east1

- name: "List the key rings CCKM manages"
  thalesgroup.ciphertrust.cckm_gcp_key_ring_info:
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
    cckm_gcp,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get", "available"], default="list"),
    key_ring_id=dict(type="str"),
    connection=dict(type="str"),
    page_size=dict(type="int"),
    page_token=dict(type="str", no_log=False),
    id=dict(type="str"),
    name=dict(type="str"),
    cloud_name=dict(type="str"),
    organization_name=dict(type="str"),
    organization_display_name=dict(type="str"),
    location=dict(type="str"),
    project_id=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "name": "name",
    "connection": "connection",
    "cloud_name": "cloud_name",
    "organization_name": "organization_name",
    "organization_display_name": "organization_display_name",
    "location": "location",
    "project_id": "project_id",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["key_ring_id"]],
            ["op_type", "available", ["connection", "project_id", "location"]],
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
            result["response"] = cckm_gcp.key_ring_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_gcp.key_ring_get(
                node=node,
                key_ring_id=module.params.get("key_ring_id"),
            )
        elif op_type == "available":
            result["response"] = cckm_gcp.key_rings_available(
                node=node,
                connection=module.params.get("connection"),
                project_id=module.params.get("project_id"),
                location=module.params.get("location"),
                page_size=module.params.get("page_size"),
                page_token=module.params.get("page_token"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
