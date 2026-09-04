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
module: cckm_oci_synchronization_job_info
short_description: Read CCKM OCI synchronisation jobs
description:
    - Lists or reads the jobs that synchronise OCI Vault keys into CCKM.
    - Start or cancel a job with
      M(thalesgroup.ciphertrust.cckm_oci_synchronization_job).
    - The job runs asynchronously. Poll C(get) until C(overall_status) leaves
      C(in_progress).
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
        - C(list) returns a filtered collection; C(get) reads one job.
      choices: [list, get]
      default: list
      type: str
    job_id:
      description:
        - Identifier of the synchronisation job.
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    overall_status:
      description:
        - Filter by job status.
      type: str
    vaults:
      description:
        - Filter by vault.
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
"""

EXAMPLES = """
- name: "Wait for a synchronisation job to finish"
  thalesgroup.ciphertrust.cckm_oci_synchronization_job_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    job_id: "{{ _sync.response.id }}"
  register: _status
  until: _status.response.overall_status != "in_progress"
  retries: 30
  delay: 10
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
    op_type=dict(type="str", choices=["list", "get"], default="list"),
    job_id=dict(type="str"),
    id=dict(type="str"),
    overall_status=dict(type="str"),
    vaults=dict(type="list", elements="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
)

_LIST_FILTERS = {
    "id": "id",
    "overall_status": "overall_status",
    "vaults": "vaults",
    "skip": "skip",
    "limit": "limit",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["job_id"]],
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
            result["response"] = cckm_oci.sync_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_oci.sync_get(
                node=node,
                job_id=module.params.get("job_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
