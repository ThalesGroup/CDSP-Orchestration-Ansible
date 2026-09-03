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
module: cckm_aws_bulkjob
short_description: Run an operation over many AWS keys at once
description:
    - Start and cancel CCKM bulk jobs, which apply one operation to a list of AWS keys.
    - A bulk job does in one request what M(thalesgroup.ciphertrust.cckm_aws_key) does one
      key at a time. Prefer it where the list is long, because it is a single request and
      CipherTrust Manager tracks the outcome per key.
    - Read job status and the per-key results with
      M(thalesgroup.ciphertrust.cckm_aws_bulkjob_info).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    A bulk job runs asynchronously. A successful C(create) means CipherTrust
    Manager accepted the job, not that every key succeeded; poll it with
    M(thalesgroup.ciphertrust.cckm_aws_bulkjob_info) and check the per-key
    results, because a job can complete with some keys having failed.
  - >-
    C(schedulekeydeletion) starts AWS's waiting period before the keys -- and
    everything encrypted under them -- are destroyed, for every key in the
    list. Once the period elapses they cannot be recovered.
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) starts a bulk job; C(cancel) stops one that is running.
      choices: [create, cancel]
      required: true
      type: str
    job_id:
      description:
        - Id of the bulk job to cancel.
        - Required when I(op_type=cancel).
      type: str
    keys:
      description:
        - CCKM ids of the keys to operate on.
        - Required when I(op_type=create).
      type: list
      elements: str
    operation:
      description:
        - Operation to apply to every key in the list.
        - Required when I(op_type=create).
      choices:
        - enablekey
        - disablekey
        - schedulekeydeletion
        - cancelkeydeletion
        - applypolicytemplate
      type: str
    days:
      description:
        - Number of days AWS waits before destroying the keys.
        - Required when I(operation=schedulekeydeletion). AWS accepts 7 to 30.
      type: int
    policy_template_id:
      description:
        - Id of the policy template to apply.
        - Required when I(operation=applypolicytemplate). Every key in the list must
          belong to the same account container as the template.
      type: str
"""

EXAMPLES = """
- name: "Disable several keys at once"
  thalesgroup.ciphertrust.cckm_aws_bulkjob:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    operation: disablekey
    keys: "{{ _stale_keys.response.resources | map(attribute='id') | list }}"
  register: _bulk

- name: "Wait for the job to finish"
  thalesgroup.ciphertrust.cckm_aws_bulkjob_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    job_id: "{{ _bulk.response.id }}"
  register: _status
  until: _status.response.overall_status != "in_progress"
  retries: 30
  delay: 10

- name: "Apply one policy template across a set of keys"
  thalesgroup.ciphertrust.cckm_aws_bulkjob:
    localNode: "{{ cm_connection }}"
    op_type: create
    operation: applypolicytemplate
    policy_template_id: "{{ _template.response.id }}"
    keys:
      - "{{ key_one }}"
      - "{{ key_two }}"

- name: "Schedule a set of keys for deletion in 30 days"
  thalesgroup.ciphertrust.cckm_aws_bulkjob:
    localNode: "{{ cm_connection }}"
    op_type: create
    operation: schedulekeydeletion
    days: 30
    keys:
      - "{{ key_one }}"
      - "{{ key_two }}"

- name: "Cancel a running job"
  thalesgroup.ciphertrust.cckm_aws_bulkjob:
    localNode: "{{ cm_connection }}"
    op_type: cancel
    job_id: "{{ _bulk.response.id }}"
"""

RETURN = r"""
changed:
    description: Always C(true) when the action is performed; C(false) in check mode.
    returned: always
    type: bool
    sample: true
response:
    description: Raw response payload from the CipherTrust Manager API.
    returned: on success
    type: dict
    contains:
        id:
            description: Id of the bulk job, used to poll or cancel it.
            type: str
            returned: when applicable
        overall_status:
            description:
              - Progress of the job, such as C(in_progress), C(completed) or
                C(error).
            type: str
            returned: when applicable
        operation:
            description: Operation the job applies to each key.
            type: str
            returned: when applicable
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)

_OPERATIONS = [
    "enablekey",
    "disablekey",
    "schedulekeydeletion",
    "cancelkeydeletion",
    "applypolicytemplate",
]

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "cancel"], required=True),
    job_id=dict(type="str"),
    keys=dict(type="list", elements="str", no_log=False),
    operation=dict(type="str", choices=_OPERATIONS),
    days=dict(type="int"),
    policy_template_id=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["keys", "operation"]],
            ["op_type", "cancel", ["job_id"]],
            ["operation", "schedulekeydeletion", ["days"]],
            ["operation", "applypolicytemplate", ["policy_template_id"]],
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

    with ciphertrust_operation(module):
        check_mode_action(module)

        if module.params.get("op_type") == "create":
            result["response"] = cckm_aws.bulkjob_create(
                node=node,
                keys=module.params.get("keys"),
                operation=module.params.get("operation"),
                days=module.params.get("days"),
                policy_template_id=module.params.get("policy_template_id"),
            )
            result["changed"] = True

        elif module.params.get("op_type") == "cancel":
            result["response"] = cckm_aws.bulkjob_cancel(
                node=node,
                job_id=module.params.get("job_id"),
            )
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
