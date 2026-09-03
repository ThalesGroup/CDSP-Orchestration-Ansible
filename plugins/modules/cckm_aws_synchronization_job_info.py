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
module: cckm_aws_synchronization_job_info
short_description: Read the status of CCKM AWS synchronization jobs
description:
    - Read the status of the jobs that bring CipherTrust Cloud Key Manager (CCKM) up to
      date with AWS.
    - This module only reads. Use
      M(thalesgroup.ciphertrust.cckm_aws_synchronization_job) to start or cancel a job.
    - Poll C(overall_status) with C(until) to wait for a job to finish.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
options:
    op_type:
      description:
        - What to read. C(list) returns jobs matching the filters; C(get) returns one job
          by id.
      choices: [list, get]
      default: list
      type: str
    scope:
      description:
        - Which synchronization service to read. Defaults to C(keys).
      choices: [keys, custom-key-stores]
      default: keys
      type: str
    job_id:
      description:
        - Id of the job to read.
        - Required when I(op_type=get).
      type: str
    id:
      description:
        - Filter by job id.
      type: str
    overall_status:
      description:
        - Filter by job status, such as C(in_progress), C(completed) or C(error).
      type: str
    kms:
      description:
        - Filter by the account containers a job covers.
      type: list
      elements: str
    skip:
      description:
        - Number of results to skip, for paging through a long list.
      type: int
    limit:
      description:
        - Maximum number of results to return.
      type: int
"""

EXAMPLES = """
- name: "Start a synchronization job"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job:
    localNode: "{{ cm_connection }}"
    op_type: create
    kms:
      - aws-production
  register: _sync

- name: "Wait for it to finish"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: get
    job_id: "{{ _sync.response.id }}"
  register: _status
  until: _status.response.overall_status != "in_progress"
  retries: 30
  delay: 10

- name: "Find synchronization jobs that failed"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    overall_status: error

- name: "Read custom key store synchronization jobs"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    scope: custom-key-stores
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
response:
    description:
      - For I(op_type=get), the job. For I(op_type=list), a page of results
        under C(resources).
    returned: on success
    type: dict
    contains:
        total:
            description: Number of records matching the filters.
            type: int
            returned: for I(op_type=list)
        resources:
            description: The matching jobs.
            type: list
            elements: dict
            returned: for I(op_type=list)
        overall_status:
            description:
              - Progress of the job, such as C(in_progress), C(completed) or
                C(error).
            type: str
            returned: for I(op_type=get)
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get"], default="list"),
    scope=dict(type="str", choices=["keys", "custom-key-stores"], default="keys"),
    job_id=dict(type="str"),
    id=dict(type="str"),
    overall_status=dict(type="str"),
    kms=dict(type="list", elements="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
)

_LIST_FILTERS = ("id", "overall_status", "kms", "skip", "limit")


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
    scope = module.params.get("scope")

    # Reading changes nothing, so both operations run unchanged under --check.
    with ciphertrust_operation(module):
        if module.params.get("op_type") == "get":
            result["response"] = cckm_aws.sync_get(
                node=node, scope=scope, job_id=module.params.get("job_id"))

        elif module.params.get("op_type") == "list":
            result["response"] = cckm_aws.sync_list(
                node=node,
                scope=scope,
                filters={name: module.params.get(name)
                         for name in _LIST_FILTERS
                         if module.params.get(name) is not None},
            )

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
