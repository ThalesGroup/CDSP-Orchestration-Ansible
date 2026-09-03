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
module: cckm_aws_report_info
short_description: Read AWS key usage reports in CCKM
description:
    - Read the status and contents of the AWS reports CipherTrust Cloud Key Manager (CCKM)
      generates.
    - This module only reads. Use M(thalesgroup.ciphertrust.cckm_aws_report) to generate
      or delete a report.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    A report is only readable once it has been generated. Poll C(get) until
    C(overall_status) leaves C(in_progress) before reading its contents.
  - >-
    C(download) returns the report as CSV text rather than as a dictionary, so
    C(response) is a string for that operation. Write it to a file with the
    C(ansible.builtin.copy) module's C(content) parameter.
options:
    op_type:
      description:
        - What to read.
        - C(list) returns reports matching the filters, and C(get) one report's status.
        - C(contents) returns the report's rows, page by page; C(download) returns the
          whole report as CSV.
      choices: [list, get, contents, download]
      default: list
      type: str
    report_id:
      description:
        - Id of the report to read.
        - Required for every operation except I(op_type=list).
      type: str
    id:
      description:
        - Filter by report id.
      type: str
    name:
      description:
        - Filter by report name.
      type: list
      elements: str
    report_type:
      description:
        - Filter by kind of report.
      type: list
      elements: str
    overall_status:
      description:
        - Filter by report status, such as C(in_progress), C(completed) or C(error).
      type: str
    key_arn:
      description:
        - Filter report contents by key ARN.
        - Only used when I(op_type=contents).
      type: str
    region:
      description:
        - Filter report contents by AWS region.
        - Only used when I(op_type=contents).
      type: list
      elements: str
    aws_account_id:
      description:
        - Filter report contents by AWS account id.
        - Only used when I(op_type=contents).
      type: list
      elements: str
    cloud_name:
      description:
        - Filter report contents by AWS partition.
        - Only used when I(op_type=contents).
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
    sort:
      description:
        - Comma-separated fields to sort by. Prefix a field with C(-) to sort descending.
      type: str
"""

EXAMPLES = """
- name: "List every report"
  thalesgroup.ciphertrust.cckm_aws_report_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: list
  register: _reports

- name: "Wait for a report to be ready"
  thalesgroup.ciphertrust.cckm_aws_report_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    report_id: "{{ report_id }}"
  register: _status
  until: _status.response.overall_status != "in_progress"
  retries: 30
  delay: 10

- name: "Read what the report found in one region"
  thalesgroup.ciphertrust.cckm_aws_report_info:
    localNode: "{{ cm_connection }}"
    op_type: contents
    report_id: "{{ report_id }}"
    region:
      - us-east-1
    limit: 100

- name: "Download the report as CSV"
  thalesgroup.ciphertrust.cckm_aws_report_info:
    localNode: "{{ cm_connection }}"
    op_type: download
    report_id: "{{ report_id }}"
  register: _csv

- name: "Save it"
  ansible.builtin.copy:
    content: "{{ _csv.response }}"
    dest: "./aws-key-usage.csv"
    mode: "0640"
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
response:
    description:
      - For I(op_type=get), the report's status. For I(op_type=list) and
        I(op_type=contents), a page of results under C(resources). For
        I(op_type=download), the report as CSV text rather than a dictionary.
    returned: on success
    type: raw
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get", "contents", "download"],
                 default="list"),
    report_id=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="list", elements="str"),
    report_type=dict(type="list", elements="str"),
    overall_status=dict(type="str"),
    key_arn=dict(type="str", no_log=False),
    region=dict(type="list", elements="str"),
    aws_account_id=dict(type="list", elements="str"),
    cloud_name=dict(type="list", elements="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = ("id", "name", "report_type", "overall_status",
                 "skip", "limit", "sort")

_CONTENT_FILTERS = ("key_arn", "region", "aws_account_id", "cloud_name",
                    "skip", "limit", "sort")


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["report_id"]],
            ["op_type", "contents", ["report_id"]],
            ["op_type", "download", ["report_id"]],
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
    params = module.params

    def _filters(names):
        return {name: params.get(name) for name in names
                if params.get(name) is not None}

    # Reading changes nothing, so every operation runs unchanged under --check.
    with ciphertrust_operation(module):
        if op_type == "list":
            result["response"] = cckm_aws.report_list(
                node=node, filters=_filters(_LIST_FILTERS))

        elif op_type == "get":
            result["response"] = cckm_aws.report_get(
                node=node, report_id=params.get("report_id"))

        elif op_type == "contents":
            result["response"] = cckm_aws.report_contents(
                node=node, report_id=params.get("report_id"),
                filters=_filters(_CONTENT_FILTERS))

        elif op_type == "download":
            response = cckm_aws.report_download(
                node=node, report_id=params.get("report_id"))
            # A CSV body comes back as bytes, which Ansible cannot serialise
            # into a result. Decode it so the task returns usable text.
            if isinstance(response, bytes):
                response = response.decode("utf-8", "replace")
            result["response"] = response

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
