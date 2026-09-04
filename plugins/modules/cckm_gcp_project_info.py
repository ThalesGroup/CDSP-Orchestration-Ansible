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
module: cckm_gcp_project_info
short_description: Read Google Cloud projects known to CCKM, and discover new ones
description:
    - Lists or reads the Google Cloud projects CCKM manages, and discovers the projects,
      Cloud KMS locations and IAM roles reachable through a connection.
    - Add a project with M(thalesgroup.ciphertrust.cckm_gcp_project).
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
        - C(list) and C(get) read the projects CCKM already manages.
        - C(available) asks Google Cloud through I(connection) which projects exist,
          C(locations) which Cloud KMS locations a project offers, and C(iam_roles)
          which roles can be granted. None of them store anything.
      choices: [list, get, available, locations, iam_roles]
      default: list
      type: str
    gcp_project_id:
      description:
        - Identifier of the project record in CCKM.
      type: str
    connection:
      description:
        - Name or id of the Google Cloud connection to look through.
        - Required for I(op_type=available).
      type: str
    project_id:
      description:
        - Google Cloud project id.
        - Required for I(op_type=locations).
      type: str
    key_ring_id:
      description:
        - Key ring to list grantable IAM roles for.
      type: str
    key_id:
      description:
        - Key to list grantable IAM roles for.
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
        - Filter by project name.
      type: str
    cloud_name:
      description:
        - Filter by cloud name.
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
- name: "Discover the projects a connection can reach"
  thalesgroup.ciphertrust.cckm_gcp_project_info:
    localNode: "{{ cm_connection }}"
    op_type: available
    connection: gcp-production

- name: "List the Cloud KMS locations in a project"
  thalesgroup.ciphertrust.cckm_gcp_project_info:
    localNode: "{{ cm_connection }}"
    op_type: locations
    project_id: my-gcp-project

- name: "List the projects CCKM manages"
  thalesgroup.ciphertrust.cckm_gcp_project_info:
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
    op_type=dict(type="str", choices=["list", "get", "available", "locations", "iam_roles"], default="list"),
    gcp_project_id=dict(type="str"),
    connection=dict(type="str"),
    project_id=dict(type="str"),
    key_ring_id=dict(type="str"),
    key_id=dict(type="str", no_log=False),
    page_size=dict(type="int"),
    page_token=dict(type="str", no_log=False),
    id=dict(type="str"),
    name=dict(type="str"),
    cloud_name=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "name": "name",
    "connection": "connection",
    "cloud_name": "cloud_name",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["gcp_project_id"]],
            ["op_type", "available", ["connection"]],
            ["op_type", "locations", ["project_id"]],
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
            result["response"] = cckm_gcp.project_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_gcp.project_get(
                node=node,
                gcp_project_id=module.params.get("gcp_project_id"),
            )
        elif op_type == "available":
            result["response"] = cckm_gcp.projects_available(
                node=node,
                connection=module.params.get("connection"),
                page_size=module.params.get("page_size"),
                page_token=module.params.get("page_token"),
            )
        elif op_type == "locations":
            result["response"] = cckm_gcp.locations_available(
                node=node,
                project_id=module.params.get("project_id"),
                connection=module.params.get("connection"),
                page_size=module.params.get("page_size"),
                page_token=module.params.get("page_token"),
            )
        elif op_type == "iam_roles":
            result["response"] = cckm_gcp.iam_roles_available(
                node=node,
                id=module.params.get("key_ring_id"),
                key_id=module.params.get("key_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
