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
module: cckm_aws_report
short_description: Generate AWS key usage reports in CCKM
description:
    - Generate the reports CipherTrust Cloud Key Manager (CCKM) builds from AWS CloudWatch
      logs, and delete them when they are no longer wanted.
    - Three kinds exist. A C(key-report) says which keys were used and by whom; a
      C(service-report) groups the same activity by AWS service; a C(key-aging) report
      lists keys by age and needs no CloudWatch log group.
    - Read a report's status, contents, or CSV with
      M(thalesgroup.ciphertrust.cckm_aws_report_info). Find the log group names to pass
      here with M(thalesgroup.ciphertrust.cckm_aws_log_group_info).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    Report generation runs asynchronously. A successful C(create) means
    CipherTrust Manager accepted the job, not that the report is ready; poll
    it with M(thalesgroup.ciphertrust.cckm_aws_report_info) until
    C(overall_status) leaves C(in_progress).
  - >-
    Generating a report is an action rather than a state to converge on, so
    C(create) reports C(changed) on every run and repeating the task generates
    another report of the same name.
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) generates a report; C(delete) removes a generated report and its
          contents from CCKM.
      choices: [create, delete]
      required: true
      type: str
    report_id:
      description:
        - Id of the report to delete.
        - Required when I(op_type=delete).
      type: str
    name:
      description:
        - Name for the report.
        - Required when I(op_type=create).
      type: str
    report_type:
      description:
        - Kind of report to generate. Defaults to C(key-report).
      choices: [key-report, service-report, key-aging]
      type: str
    start_time:
      description:
        - Start of the period the report covers, as an RFC3339 timestamp.
        - When neither I(start_time) nor I(end_time) is given, the report covers the last
          24 hours.
      type: str
    end_time:
      description:
        - End of the period the report covers, as an RFC3339 timestamp.
      type: str
    cloud_watch_params:
      description:
        - Which account containers, regions and CloudWatch log groups to read.
        - Required when I(op_type=create).
      type: list
      elements: dict
      suboptions:
        kms:
          description:
            - Name or id of the AWS account container to report on.
          type: str
        log_group_region:
          description:
            - Region the CloudWatch log group lives in.
            - Required for every report type except C(key-aging).
          type: str
        log_group_name:
          description:
            - Name of the CloudWatch log group holding the KMS activity.
            - Required for every report type except C(key-aging).
          type: str
"""

EXAMPLES = """
- name: "Report on key usage over the last 24 hours"
  thalesgroup.ciphertrust.cckm_aws_report:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: daily-key-usage
    report_type: key-report
    cloud_watch_params:
      - kms: aws-production
        log_group_region: us-east-1
        log_group_name: /aws/kms/production
  register: _report

- name: "Wait for the report to be ready"
  thalesgroup.ciphertrust.cckm_aws_report_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    report_id: "{{ _report.response.id }}"
  register: _status
  until: _status.response.overall_status != "in_progress"
  retries: 30
  delay: 10

- name: "Read what the report found"
  thalesgroup.ciphertrust.cckm_aws_report_info:
    localNode: "{{ cm_connection }}"
    op_type: contents
    report_id: "{{ _report.response.id }}"

- name: "Report on a specific week"
  thalesgroup.ciphertrust.cckm_aws_report:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: incident-window
    report_type: service-report
    start_time: "2026-08-24T00:00:00Z"
    end_time: "2026-08-31T00:00:00Z"
    cloud_watch_params:
      - kms: aws-production
        log_group_region: us-east-1
        log_group_name: /aws/kms/production

- name: "List keys by age -- no log group needed"
  thalesgroup.ciphertrust.cckm_aws_report:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: key-aging
    report_type: key-aging
    cloud_watch_params:
      - kms: aws-production

- name: "Delete a report"
  thalesgroup.ciphertrust.cckm_aws_report:
    localNode: "{{ cm_connection }}"
    op_type: delete
    report_id: "{{ _report.response.id }}"
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
            description: Id of the report, used to poll, read or delete it.
            type: str
            returned: when applicable
        name:
            description: Name of the report.
            type: str
            returned: when applicable
        overall_status:
            description:
              - Progress of the job, such as C(in_progress), C(completed) or
                C(error).
            type: str
            returned: when applicable
        report_type:
            description: Kind of report generated.
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

_cloud_watch_params = dict(
    kms=dict(type="str"),
    log_group_region=dict(type="str"),
    log_group_name=dict(type="str"),
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "delete"], required=True),
    report_id=dict(type="str"),
    name=dict(type="str"),
    report_type=dict(type="str",
                     choices=["key-report", "service-report", "key-aging"]),
    start_time=dict(type="str"),
    end_time=dict(type="str"),
    cloud_watch_params=dict(type="list", elements="dict",
                            options=_cloud_watch_params),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name", "cloud_watch_params"]],
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

    with ciphertrust_operation(module):
        check_mode_action(module)

        if module.params.get("op_type") == "create":
            result["response"] = cckm_aws.report_create(
                node=node,
                name=module.params.get("name"),
                cloud_watch_params=module.params.get("cloud_watch_params"),
                start_time=module.params.get("start_time"),
                end_time=module.params.get("end_time"),
                report_type=module.params.get("report_type"),
            )
            result["changed"] = True

        elif module.params.get("op_type") == "delete":
            result["response"] = cckm_aws.report_delete(
                node=node,
                report_id=module.params.get("report_id"),
            )
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
