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
module: cckm_gcp_update_all_versions_job_info
short_description: Read a CCKM Google Cloud update-all-versions job
description:
    - Reads a job that enables, disables or destroys every version of a Cloud KMS key.
    - Start one with M(thalesgroup.ciphertrust.cckm_gcp_update_all_versions_job).
    - The API offers no listing for these jobs, so only C(get) exists.
    - The job runs asynchronously. Poll it until C(overall_status) leaves
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
        - C(get) reads one job by id.
      choices: [get]
      default: get
      type: str
    job_id:
      description:
        - Identifier of the update-all-versions job.
      type: str
"""

EXAMPLES = """
- name: "Wait for an update-all-versions job to finish"
  thalesgroup.ciphertrust.cckm_gcp_update_all_versions_job_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    job_id: "{{ _job.response.id }}"
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
    cckm_gcp,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["get"], default="get"),
    job_id=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
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
        if op_type == "get":
            result["response"] = cckm_gcp.update_all_versions_get(
                node=node,
                job_id=module.params.get("job_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
