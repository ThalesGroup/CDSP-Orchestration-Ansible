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
module: cckm_azure_report_info
short_description: Read CCKM Azure reports and their contents
description:
    - Lists or reads CCKM Azure reports, and fetches a finished report's contents.
    - Start a report with M(thalesgroup.ciphertrust.cckm_azure_report).
    - A report runs asynchronously. Poll C(get) until C(overall_status) leaves
      C(in_progress) before reading its contents.
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
        - C(list) and C(get) read report jobs.
        - C(contents) returns the report body; C(download) returns it as a downloadable
          document.
      choices: [list, get, contents, download]
      default: list
      type: str
    report_id:
      description:
        - Identifier of the report.
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    name:
      description:
        - Filter by report name.
      type: str
    report_type:
      description:
        - Filter by report type.
      choices: [service-report, key-report, key-aging]
      type: str
    overall_status:
      description:
        - Filter by job status.
      type: str
    skip:
      description:
        - Number of records to skip.
      type: int
    limit:
      description:
        - Maximum number of records to return.
      type: int
    sort:
      description:
        - Comma-separated fields to sort by.
      type: str
"""

EXAMPLES = """
- name: "Wait for a report to finish, then read it"
  thalesgroup.ciphertrust.cckm_azure_report_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    report_id: "{{ _report.response.id }}"
  register: _status
  until: _status.response.overall_status != "in_progress"
  retries: 30
  delay: 10

- name: "Read the finished report's contents"
  thalesgroup.ciphertrust.cckm_azure_report_info:
    localNode: "{{ cm_connection }}"
    op_type: contents
    report_id: "{{ _report.response.id }}"
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
    cckm_azure,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get", "contents", "download"], default="list"),
    report_id=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="str"),
    report_type=dict(type="str", choices=["service-report", "key-report", "key-aging"]),
    overall_status=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "overall_status": "overall_status",
    "name": "name",
    "report_type": "report_type",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


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

    # Reading changes nothing, so every operation runs unchanged under --check.
    with ciphertrust_operation(module):
        if op_type == "list":
            result["response"] = cckm_azure.report_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_azure.report_get(
                node=node,
                report_id=module.params.get("report_id"),
            )
        elif op_type == "contents":
            result["response"] = cckm_azure.report_contents(
                node=node,
                report_id=module.params.get("report_id"),
            )
        elif op_type == "download":
            result["response"] = cckm_azure.report_download(
                node=node,
                report_id=module.params.get("report_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
