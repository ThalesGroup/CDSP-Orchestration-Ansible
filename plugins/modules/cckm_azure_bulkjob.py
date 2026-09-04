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
module: cckm_azure_bulkjob
short_description: Start, cancel and delete CCKM Azure bulk jobs
description:
    - Starts a CCKM Azure bulk job, cancels a running one, or deletes a finished one.
    - A bulk job runs asynchronously. Poll it with
      M(thalesgroup.ciphertrust.cckm_azure_bulkjob_info) until C(overall_status) leaves
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
        - Operation to perform.
        - C(create) starts a job; C(cancel) stops a running one; C(delete) removes a
          finished one.
      choices:
        - create
        - cancel
        - delete
      required: true
      type: str
    job_id:
      description:
        - Identifier of the bulk job.
        - Required for C(cancel) and C(delete).
      type: str
    operation:
      description:
        - Bulk operation to run.
        - Required for C(create).
      choices: [delete-key-backups]
      type: str
    delete_key_backups_param:
      description:
        - Parameters for the C(delete-key-backups) operation.
      type: dict
"""

EXAMPLES = """
- name: "Delete key backups in bulk"
  thalesgroup.ciphertrust.cckm_azure_bulkjob:
    localNode: "{{ cm_connection }}"
    op_type: create
    operation: delete-key-backups
    delete_key_backups_param:
      key_vaults:
        - production-vault
  register: _job
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - Starting a job always reports C(true) -- each run creates a new job.
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
    cckm_azure,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)
argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "cancel",
            "delete",
        ],
        required=True,
    ),
    job_id=dict(type="str"),
    operation=dict(type="str", choices=["delete-key-backups"]),
    delete_key_backups_param=dict(type="dict", no_log=False),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["operation"]],
            ["op_type", "cancel", ["job_id"]],
            ["op_type", "delete", ["job_id"]],
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
        if op_type == "create":
            check_mode_action(module)
            result["response"] = cckm_azure.bulkjob_create(
                node=node,
                operation=params.get("operation"),
                delete_key_backups_param=params.get("delete_key_backups_param"),
            )
            result["changed"] = True
        elif op_type == "cancel":
            check_mode_action(module)
            result["response"] = cckm_azure.bulkjob_cancel(
                node=node,
                job_id=params.get("job_id"),
            )
            result["changed"] = True
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_azure.bulkjob_delete(
                node=node,
                job_id=params.get("job_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
