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
module: cckm_gcp_report
short_description: Start and delete CCKM Google Cloud reports
description:
    - Starts a CCKM Google Cloud report, or deletes a finished one.
    - A report runs asynchronously. Poll it with
      M(thalesgroup.ciphertrust.cckm_gcp_report_info) until C(overall_status) leaves
      C(in_progress), then read its contents.
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
        - C(create) starts a report; C(delete) removes one.
      choices:
        - create
        - delete
      required: true
      type: str
    report_id:
      description:
        - Identifier of the report.
        - Required for C(delete).
      type: str
    name:
      description:
        - Name for the report.
        - Required for C(create).
      type: str
    report_type:
      description:
        - Kind of report to run.
        - Required for C(create).
      choices: [key-report, key-aging]
      type: str
    gcp_cloud_params:
      description:
        - Which projects, key rings or keys the report covers.
        - Required for C(create).
      type: list
      elements: dict
    start_time:
      description:
        - Start of the reporting window.
      type: str
    end_time:
      description:
        - End of the reporting window.
      type: str
"""

EXAMPLES = """
- name: "Start a key report for one key ring"
  thalesgroup.ciphertrust.cckm_gcp_report:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: quarterly-keys
    report_type: key-report
    gcp_cloud_params:
      - key_rings:
          - production-ring
  register: _report
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - Starting a report always reports C(true) -- each run creates a new report job
        rather than converging on a state.
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
            "create",
            "delete",
        ],
        required=True,
    ),
    report_id=dict(type="str"),
    name=dict(type="str"),
    report_type=dict(type="str", choices=["key-report", "key-aging"]),
    gcp_cloud_params=dict(type="list", elements="dict"),
    start_time=dict(type="str"),
    end_time=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name", "report_type", "gcp_cloud_params"]],
            ["op_type", "delete", ["report_id"]],
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
            result["response"] = cckm_gcp.report_create(
                node=node,
                name=params.get("name"),
                report_type=params.get("report_type"),
                gcp_cloud_params=params.get("gcp_cloud_params"),
                start_time=params.get("start_time"),
                end_time=params.get("end_time"),
            )
            result["changed"] = True
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_gcp.report_delete(
                node=node,
                report_id=params.get("report_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
