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
module: cckm_aws_synchronization_job
short_description: Synchronize AWS keys and custom key stores into CCKM
description:
    - Start and cancel the jobs that bring CipherTrust Cloud Key Manager (CCKM) up to date
      with what actually exists in AWS.
    - CCKM only knows about AWS keys it created or has been told about. A key created in
      the AWS console, or a change made to a key outside CCKM, is invisible until a
      synchronization job runs. Run one after adding an account container, and on a
      schedule where keys are also managed outside CCKM.
    - Two independent scopes exist, selected with I(scope) -- one for keys and one for
      custom key stores.
    - Read job status with M(thalesgroup.ciphertrust.cckm_aws_synchronization_job_info).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    Synchronization runs asynchronously. A successful C(create) means
    CipherTrust Manager accepted the job, not that it has finished; poll it
    with M(thalesgroup.ciphertrust.cckm_aws_synchronization_job_info) until
    C(overall_status) leaves C(in_progress).
  - >-
    Starting a job is an action, not a state to converge on, so C(create)
    reports C(changed) on every run and starting one while another is running
    is refused by CipherTrust Manager.
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) starts a synchronization job; C(cancel) stops one that is running.
      choices: [create, cancel]
      required: true
      type: str
    scope:
      description:
        - What to synchronize. Defaults to C(keys).
      choices: [keys, custom-key-stores]
      default: keys
      type: str
    job_id:
      description:
        - Id of the job to cancel.
        - Required when I(op_type=cancel).
      type: str
    kms:
      description:
        - Names or ids of the AWS account containers to synchronize.
        - Mutually exclusive with I(synchronize_all).
      type: list
      elements: str
    regions:
      description:
        - Regions to synchronize within the named containers. Defaults to every region the
          container manages.
        - Mutually exclusive with I(synchronize_all).
      type: list
      elements: str
    synchronize_all:
      description:
        - Synchronize every region of every account container.
        - Mutually exclusive with I(kms) and I(regions).
      type: bool
"""

EXAMPLES = """
- name: "Synchronize the keys of one account container"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    scope: keys
    kms:
      - aws-production
    regions:
      - us-east-1
  register: _sync

- name: "Wait for the job to finish"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    scope: keys
    job_id: "{{ _sync.response.id }}"
  register: _status
  until: _status.response.overall_status != "in_progress"
  retries: 30
  delay: 10

- name: "Synchronize every key CCKM can see"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job:
    localNode: "{{ cm_connection }}"
    op_type: create
    synchronize_all: true

- name: "Synchronize custom key stores"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job:
    localNode: "{{ cm_connection }}"
    op_type: create
    scope: custom-key-stores
    kms:
      - aws-production

- name: "Cancel a running job"
  thalesgroup.ciphertrust.cckm_aws_synchronization_job:
    localNode: "{{ cm_connection }}"
    op_type: cancel
    scope: keys
    job_id: "{{ _sync.response.id }}"
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
            description: Id of the synchronization job, used to poll or cancel it.
            type: str
            returned: when applicable
        overall_status:
            description:
              - Progress of the job, such as C(in_progress), C(completed) or
                C(error).
            type: str
            returned: when applicable
        kms:
            description: Account containers the job covers.
            type: list
            elements: str
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

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "cancel"], required=True),
    scope=dict(type="str", choices=["keys", "custom-key-stores"], default="keys"),
    job_id=dict(type="str"),
    kms=dict(type="list", elements="str"),
    regions=dict(type="list", elements="str"),
    synchronize_all=dict(type="bool"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "cancel", ["job_id"]],
        ),
        mutually_exclusive=[
            ["synchronize_all", "kms"],
            ["synchronize_all", "regions"],
        ],
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

    with ciphertrust_operation(module):
        check_mode_action(module)

        if module.params.get("op_type") == "create":
            result["response"] = cckm_aws.sync_start(
                node=node,
                scope=scope,
                kms=module.params.get("kms"),
                regions=module.params.get("regions"),
                synchronize_all=module.params.get("synchronize_all"),
            )
            result["changed"] = True

        elif module.params.get("op_type") == "cancel":
            result["response"] = cckm_aws.sync_cancel(
                node=node,
                scope=scope,
                job_id=module.params.get("job_id"),
            )
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
