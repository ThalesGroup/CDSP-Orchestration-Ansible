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
module: cckm_gcp_report_info
short_description: Read CCKM Google Cloud reports and their contents
description:
    - Lists or reads CCKM Google Cloud reports, and fetches a finished report's
      contents.
    - Start a report with M(thalesgroup.ciphertrust.cckm_gcp_report).
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
        - C(contents) returns the report body, which can be filtered; C(download)
          returns it as a downloadable document.
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
      choices: [key-report, key-aging]
      type: str
    overall_status:
      description:
        - Filter by job status.
      type: str
    key_name:
      description:
        - Filter report contents by key name.
      type: str
    key_ring:
      description:
        - Filter report contents by key ring.
      type: str
    project:
      description:
        - Filter report contents by project.
      type: str
    region:
      description:
        - Filter report contents by region.
      type: str
    organization:
      description:
        - Filter report contents by organisation.
      type: str
    key_activity:
      description:
        - Filter report contents by key activity.
      type: str
    cckm_operation:
      description:
        - Filter report contents by CCKM operation.
      type: str
    user_name:
      description:
        - Filter report contents by user.
      type: str
    origin:
      description:
        - Filter report contents by origin.
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
  thalesgroup.ciphertrust.cckm_gcp_report_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    report_id: "{{ _report.response.id }}"
  register: _status
  until: _status.response.overall_status != "in_progress"
  retries: 30
  delay: 10

- name: "Read the rows for one key ring"
  thalesgroup.ciphertrust.cckm_gcp_report_info:
    localNode: "{{ cm_connection }}"
    op_type: contents
    report_id: "{{ _report.response.id }}"
    key_ring: production-ring
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

_CONTENT_FILTERS = {
    "key_name": "key_name",
    "key_ring": "key_ring",
    "project": "project",
    "region": "region",
    "organization": "organization",
    "key_activity": "key_activity",
    "cckm_operation": "cckm_operation",
    "user_name": "user_name",
    "origin": "origin",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get", "contents", "download"], default="list"),
    report_id=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="str"),
    report_type=dict(type="str", choices=["key-report", "key-aging"]),
    overall_status=dict(type="str"),
    key_name=dict(type="str", no_log=False),
    key_ring=dict(type="str", no_log=False),
    project=dict(type="str"),
    region=dict(type="str"),
    organization=dict(type="str"),
    key_activity=dict(type="str", no_log=False),
    cckm_operation=dict(type="str"),
    user_name=dict(type="str"),
    origin=dict(type="str"),
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
            result["response"] = cckm_gcp.report_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_gcp.report_get(
                node=node,
                report_id=module.params.get("report_id"),
            )
        elif op_type == "contents":
            result["response"] = cckm_gcp.report_contents(
                node=node,
                report_id=module.params.get("report_id"),
                filters={api: module.params.get(name)
                         for name, api in _CONTENT_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "download":
            result["response"] = cckm_gcp.report_download(
                node=node,
                report_id=module.params.get("report_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
