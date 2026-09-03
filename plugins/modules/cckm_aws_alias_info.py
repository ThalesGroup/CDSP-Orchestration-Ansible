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
module: cckm_aws_alias_info
short_description: Check whether an AWS key alias is already in use
description:
    - Ask AWS whether a key alias already exists in a region, before creating a key that
      would claim it.
    - An AWS alias is unique within one region of one account. Creating a key with an
      alias that is taken fails, so checking first turns a failed play into a decision the
      playbook can make.
    - This module only reads. Nothing is created or changed, in CipherTrust Manager or in
      AWS.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    The check reaches AWS from the CipherTrust Manager itself, so it needs the
    manager to have network egress and the account container's credentials to
    be valid.
options:
    alias:
      description:
        - Alias to check, without the C(alias/) prefix.
      required: true
      type: str
    region:
      description:
        - AWS region to check the alias in.
      required: true
      type: str
    kms:
      description:
        - Name or id of the AWS account container to check within.
      required: true
      type: str
"""

EXAMPLES = """
- name: "Check whether an alias is free"
  thalesgroup.ciphertrust.cckm_aws_alias_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    alias: payments-encryption
    region: us-east-1
    kms: aws-production
  register: _alias

- name: "Create the key only if the alias is not taken"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: create
    kms: aws-production
    region: us-east-1
    aws_param:
      alias: payments-encryption
  when: not _alias.exists
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
exists:
    description:
      - Whether the alias is already in use in the region.
      - C(none) when CipherTrust Manager's answer did not say either way, so a
        playbook branching on this can tell "not in use" from "could not
        tell".
    returned: always
    type: bool
    sample: false
response:
    description: The raw response dictionary from the CipherTrust Manager API.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws

argument_spec = dict(
    alias=dict(type="str", required=True),
    region=dict(type="str", required=True),
    kms=dict(type="str", required=True),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=[],
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def _alias_exists(response):
    """Read the verdict out of the response, without inventing one.

    CipherTrust Manager has answered this endpoint with more than one field
    name over its life. Where none of them is present the answer is ``None``
    rather than ``False``: reporting "the alias is free" when the manager did
    not say so would have a playbook create a key that then fails.
    """
    if not isinstance(response, dict):
        return None
    for field in ("exists", "alias_exists", "is_alias_exist"):
        if isinstance(response.get(field), bool):
            return response[field]
    return None


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    # Verifying an alias reads AWS and changes nothing, so it runs unchanged
    # under --check.
    with ciphertrust_operation(module):
        response = cckm_aws.verify_alias(
            node=module.params.get("localNode"),
            alias=module.params.get("alias"),
            region=module.params.get("region"),
            kms=module.params.get("kms"),
        )

    result["response"] = response
    result["exists"] = _alias_exists(response)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
