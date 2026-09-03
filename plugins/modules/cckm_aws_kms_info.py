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
module: cckm_aws_kms_info
short_description: Read AWS account containers (KMS) in CCKM
description:
    - List, filter and read the AWS account containers CipherTrust Cloud Key Manager
      (CCKM) manages keys through.
    - This module only reads. Use M(thalesgroup.ciphertrust.cckm_aws_kms) to add or change
      a container.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
options:
    op_type:
      description:
        - What to read. C(list) returns containers matching the filters; C(get) returns
          one by name or id.
      choices: [list, get]
      default: list
      type: str
    kms_id:
      description:
        - Name or id of the container to read.
        - Required when I(op_type=get).
      type: str
    id:
      description:
        - Filter by container id.
      type: str
    name:
      description:
        - Filter by container name.
      type: str
    account_id:
      description:
        - Filter by AWS account id.
      type: str
    cloud_name:
      description:
        - Filter by AWS partition, such as C(aws), C(aws-us-gov) or C(aws-cn).
      type: list
      elements: str
    status:
      description:
        - Filter by container status.
      type: str
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
- name: "List every AWS account container"
  thalesgroup.ciphertrust.cckm_aws_kms_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: list
  register: _containers

- name: "Find the container for one AWS account"
  thalesgroup.ciphertrust.cckm_aws_kms_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    account_id: "123456789012"

- name: "Read one container, including the regions it manages"
  thalesgroup.ciphertrust.cckm_aws_kms_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    kms_id: aws-production
  register: _kms

- name: "Show which regions CCKM manages"
  ansible.builtin.debug:
    var: _kms.response.regions
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
response:
    description:
      - For I(op_type=get), the container. For I(op_type=list), a page of
        results under C(resources).
    returned: on success
    type: dict
    contains:
        total:
            description: Number of records matching the filters.
            type: int
            returned: for I(op_type=list)
        resources:
            description: The matching containers.
            type: list
            elements: dict
            returned: for I(op_type=list)
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get"], default="list"),
    kms_id=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="str"),
    account_id=dict(type="str"),
    cloud_name=dict(type="list", elements="str"),
    status=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = ("id", "name", "account_id", "cloud_name", "status",
                 "skip", "limit", "sort")


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["kms_id"]],
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

    # Reading changes nothing, so both operations run unchanged under --check.
    with ciphertrust_operation(module):
        if module.params.get("op_type") == "get":
            result["response"] = cckm_aws.kms_get(
                node=node, kms_id=module.params.get("kms_id"))

        elif module.params.get("op_type") == "list":
            result["response"] = cckm_aws.kms_list(
                node=node,
                filters={name: module.params.get(name)
                         for name in _LIST_FILTERS
                         if module.params.get(name) is not None},
            )

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
