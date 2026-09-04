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
module: cckm_gcp_update_all_versions_job
short_description: Enable, disable or destroy every version of a Cloud KMS key
description:
    - Starts a job that applies one operation to every version of a Cloud KMS key.
    - Google Cloud's key lifecycle acts on versions, so this is how a whole key is
      disabled or destroyed. To act on a single version use
      M(thalesgroup.ciphertrust.cckm_gcp_key).
    - The job runs asynchronously. Poll it with
      M(thalesgroup.ciphertrust.cckm_gcp_update_all_versions_job_info).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description:
        - Operation to perform.
        - C(start) begins the job.
      choices:
        - start
      required: true
      type: str
    key_id:
      description:
        - Identifier of the key in CCKM.
        - Required.
      type: str
    operation:
      description:
        - What to do to every version of the key.
        - Required.
      choices: [enable, disable, schedule_destroy, cancel_destroy]
      type: str
"""

EXAMPLES = """
- name: "Disable every version of a key"
  thalesgroup.ciphertrust.cckm_gcp_update_all_versions_job:
    localNode: "{{ cm_connection }}"
    op_type: start
    key_id: "{{ _key.response.id }}"
    operation: disable
  register: _job

- name: "Schedule every version for destruction"
  thalesgroup.ciphertrust.cckm_gcp_update_all_versions_job:
    localNode: "{{ cm_connection }}"
    op_type: start
    key_id: "{{ _key.response.id }}"
    operation: schedule_destroy
"""

RETURN = r"""
changed:
    description:
      - C(true) when the job was started.
      - Each run creates a new job rather than converging on a state, so this always
        reports C(true).
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing resource when one was found during a GET-before-write
        idempotency check.
    returned: when the operation returns a body
    type: dict
diff:
    description: Present only in C(--diff) mode when a change occurred.
    returned: when diff mode is enabled and the module made a change
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_gcp,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)
argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "start",
        ],
        required=True,
    ),
    key_id=dict(type="str", no_log=False),
    operation=dict(type="str", choices=["enable", "disable", "schedule_destroy", "cancel_destroy"]),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "start", ["key_id", "operation"]],
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
    params = module.params
    op_type = params.get("op_type")

    with ciphertrust_operation(module):
        if op_type == "start":
            check_mode_action(module)
            result["response"] = cckm_gcp.update_all_versions_start(
                node=node,
                key_id=params.get("key_id"),
                operation=params.get("operation"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
