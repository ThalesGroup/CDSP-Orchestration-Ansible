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
module: cckm_aws_account_info
short_description: Discover AWS accounts, regions, IAM principals and log groups
description:
    - Ask CipherTrust Manager what it can see in AWS through a connection or an account
      container.
    - Use this before M(thalesgroup.ciphertrust.cckm_aws_kms) to find the account id and
      the regions a connection reaches, and before creating keys or reports to find the
      IAM users, IAM roles and CloudWatch log groups to name.
    - Everything here reads from AWS. Nothing is created or changed, in CipherTrust
      Manager or in AWS.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    These operations reach AWS from the CipherTrust Manager itself, so they
    need the manager to have network egress and the connection's credentials
    to be valid. A manager without egress makes the task hang rather than
    fail.
  - >-
    C(iam_roles) and C(iam_users) are paginated by AWS. When the response has
    C(IsTruncated) set, pass its C(Marker) back as I(marker) to fetch the next
    page.
options:
    op_type:
      description:
        - What to look up.
        - C(accounts) lists the AWS accounts a connection reaches, and C(regions) every
          region available to it. Both take I(connection).
        - C(iam_roles), C(iam_users) and C(log_groups) read through an account container
          and take I(kms).
      choices: [accounts, regions, iam_roles, iam_users, log_groups]
      required: true
      type: str
    connection:
      description:
        - Name or id of the AWS connection to look through.
        - Required when I(op_type=accounts) or I(op_type=regions).
      type: str
    kms:
      description:
        - Name or id of the AWS account container to look through.
        - Required when I(op_type=iam_roles), I(op_type=iam_users) or
          I(op_type=log_groups).
      type: str
    region:
      description:
        - AWS region to read CloudWatch log groups from.
        - Required when I(op_type=log_groups).
      type: str
    assume_role_arn:
      description:
        - ARN of an IAM role to assume for the lookup.
        - Only used when I(op_type=accounts).
      type: str
    assume_role_external_id:
      description:
        - External id required when assuming the role.
        - Only meaningful alongside I(assume_role_arn).
      type: str
    path_prefix:
      description:
        - Return only IAM principals whose path starts with this prefix, for example
          C(/division_abc/). Defaults to every principal in the account.
        - Only used when I(op_type=iam_roles) or I(op_type=iam_users).
      type: str
    max_items:
      description:
        - Maximum number of IAM principals to return in one page.
        - Only used when I(op_type=iam_roles) or I(op_type=iam_users).
      type: int
    marker:
      description:
        - Pagination marker from a previous truncated response.
        - Only used when I(op_type=iam_roles) or I(op_type=iam_users).
      type: str
    log_group_name_prefix:
      description:
        - Return only log groups whose name starts with this prefix.
        - Only used when I(op_type=log_groups).
      type: str
    limit:
      description:
        - Maximum number of log groups to return. CloudWatch's own default is 50.
        - Only used when I(op_type=log_groups).
      type: int
    next_token:
      description:
        - Pagination token from a previous log group response.
        - Only used when I(op_type=log_groups).
      type: str
"""

EXAMPLES = """
- name: "Find the AWS account a connection reaches"
  thalesgroup.ciphertrust.cckm_aws_account_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: accounts
    connection: aws-production-connection
  register: _accounts

- name: "List every region the connection can use"
  thalesgroup.ciphertrust.cckm_aws_account_info:
    localNode: "{{ cm_connection }}"
    op_type: regions
    connection: aws-production-connection
  register: _regions

- name: "Create the account container from what was discovered"
  thalesgroup.ciphertrust.cckm_aws_kms:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: aws-production
    account_id: "{{ _accounts.response.accounts[0] }}"
    connection: aws-production-connection
    regions:
      - us-east-1

- name: "List the IAM users that could be named as key users"
  thalesgroup.ciphertrust.cckm_aws_account_info:
    localNode: "{{ cm_connection }}"
    op_type: iam_users
    kms: aws-production
    path_prefix: "/service-accounts/"

- name: "List the IAM roles"
  thalesgroup.ciphertrust.cckm_aws_account_info:
    localNode: "{{ cm_connection }}"
    op_type: iam_roles
    kms: aws-production

- name: "Find the CloudWatch log group holding KMS activity"
  thalesgroup.ciphertrust.cckm_aws_account_info:
    localNode: "{{ cm_connection }}"
    op_type: log_groups
    kms: aws-production
    region: us-east-1
    log_group_name_prefix: "/aws/kms"
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API. Its
        shape follows the AWS API being read -- accounts and regions come back
        as lists, IAM and CloudWatch results in AWS's own paginated form.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=["accounts", "regions", "iam_roles", "iam_users", "log_groups"],
        required=True,
    ),
    connection=dict(type="str"),
    kms=dict(type="str"),
    region=dict(type="str"),
    assume_role_arn=dict(type="str"),
    assume_role_external_id=dict(type="str", no_log=False),
    path_prefix=dict(type="str"),
    max_items=dict(type="int"),
    marker=dict(type="str"),
    log_group_name_prefix=dict(type="str"),
    limit=dict(type="int"),
    next_token=dict(type="str", no_log=False),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "accounts", ["connection"]],
            ["op_type", "regions", ["connection"]],
            ["op_type", "iam_roles", ["kms"]],
            ["op_type", "iam_users", ["kms"]],
            ["op_type", "log_groups", ["kms", "region"]],
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

    # Every operation here reads from AWS and changes nothing, so none of them
    # is guarded by check mode.
    with ciphertrust_operation(module):
        if op_type == "accounts":
            result["response"] = cckm_aws.accounts_list(
                node=node,
                connection=params.get("connection"),
                assume_role_arn=params.get("assume_role_arn"),
                assume_role_external_id=params.get("assume_role_external_id"),
            )

        elif op_type == "regions":
            result["response"] = cckm_aws.regions_list(
                node=node, connection=params.get("connection"))

        elif op_type in ("iam_roles", "iam_users"):
            lookup = (cckm_aws.iam_roles_list if op_type == "iam_roles"
                      else cckm_aws.iam_users_list)
            result["response"] = lookup(
                node=node,
                kms=params.get("kms"),
                path_prefix=params.get("path_prefix"),
                max_items=params.get("max_items"),
                marker=params.get("marker"),
            )

        elif op_type == "log_groups":
            cloud_watch_params = {
                "limit": params.get("limit"),
                "logGroupNamePrefix": params.get("log_group_name_prefix"),
                "nextToken": params.get("next_token"),
            }
            result["response"] = cckm_aws.log_groups_list(
                node=node,
                kms=params.get("kms"),
                region=params.get("region"),
                cloud_watch_params=cloud_watch_params,
            )

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
