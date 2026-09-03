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
module: cckm_aws_policy_template_info
short_description: Read AWS key policy templates in CCKM
description:
    - List, filter and read the AWS key policy templates CipherTrust Cloud Key Manager
      (CCKM) holds.
    - This module only reads. Use M(thalesgroup.ciphertrust.cckm_aws_policy_template) to
      create or change a template.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
options:
    op_type:
      description:
        - What to read. C(list) returns templates matching the filters; C(get) returns one
          by name or id.
      choices: [list, get]
      default: list
      type: str
    template_id:
      description:
        - Name or id of the template to read.
        - Required when I(op_type=get).
      type: str
    id:
      description:
        - Filter by template id.
      type: str
    name:
      description:
        - Filter by template name.
      type: str
    kms_name:
      description:
        - Filter by the name of the AWS account container the template belongs to.
      type: list
      elements: str
    account_id:
      description:
        - Filter by AWS account id.
      type: str
    policy_type:
      description:
        - Filter by whether the record is a reusable template or a policy saved from a
          key.
      choices: [saved_policy, template]
      type: str
    cloud:
      description:
        - Filter by AWS partition.
      type: list
      elements: str
    is_verified:
      description:
        - Filter by whether the policy has been verified against AWS.
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
- name: "List every policy template"
  thalesgroup.ciphertrust.cckm_aws_policy_template_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: list
  register: _templates

- name: "Find a template by name"
  thalesgroup.ciphertrust.cckm_aws_policy_template_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    name: payments-key-policy
    policy_type: template
  register: _template

- name: "Read the policy a template resolves to"
  thalesgroup.ciphertrust.cckm_aws_policy_template_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    template_id: "{{ _template.response.resources[0].id }}"
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
response:
    description:
      - For I(op_type=get), the template. For I(op_type=list), a page of
        results under C(resources).
    returned: on success
    type: dict
    contains:
        total:
            description: Number of records matching the filters.
            type: int
            returned: for I(op_type=list)
        resources:
            description: The matching templates.
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
    template_id=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="str"),
    kms_name=dict(type="list", elements="str"),
    account_id=dict(type="str"),
    policy_type=dict(type="str", choices=["saved_policy", "template"]),
    cloud=dict(type="list", elements="str"),
    is_verified=dict(type="str"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = ("id", "name", "kms_name", "account_id", "policy_type",
                 "cloud", "is_verified", "skip", "limit", "sort")


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["template_id"]],
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
            result["response"] = cckm_aws.template_get(
                node=node, template_id=module.params.get("template_id"))

        elif module.params.get("op_type") == "list":
            result["response"] = cckm_aws.template_list(
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
