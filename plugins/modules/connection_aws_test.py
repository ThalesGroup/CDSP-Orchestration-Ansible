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
module: connection_aws_test
short_description: Test AWS credentials without storing them
description:
    - Asks CipherTrust Manager to verify a set of AWS credentials by reaching AWS with
      them, without storing a connection.
    - Use this before M(thalesgroup.ciphertrust.connection_aws_save) to fail early on
      credentials that do not work, or to check a replacement credential before rotating
      the one a connection already uses.
    - To test credentials already stored in a connection, use
      M(thalesgroup.ciphertrust.connection_test) instead.
    - A failed test fails the task. CipherTrust Manager answers a failed test with HTTP
      200 and C(connection_ok=false) rather than an error status, so a module that checked
      only the HTTP status would report success for credentials the provider refused. Set
      C(failed_when) to C(false) to check credentials without failing the play.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    access_key_id:
      description:
        - Access key id of the AWS user.
        - Required.
      required: true
      type: str
    secret_access_key:
      description:
        - Secret associated with the access key id.
        - CipherTrust Manager never returns this value, so supplying it on a patch makes
          the task report C(changed) on every run.
        - Required.
      required: true
      type: str
    cloud_name:
      description:
        - AWS partition to connect to. Defaults to C(aws).
      choices: [aws, aws-us-gov, aws-cn]
      type: str
    assume_role_arn:
      description:
        - ARN of an AWS IAM role for CipherTrust Manager to assume.
      type: str
    assume_role_external_id:
      description:
        - External id required when assuming the role.
      type: str
    aws_sts_regional_endpoints:
      description:
        - Whether AWS STS requests go to the global endpoint or the endpoint for
          I(aws_region). Defaults to C(global).
      choices: [global, regional]
      type: str
    aws_region:
      description:
        - AWS region for STS requests.
        - Only used when I(aws_sts_regional_endpoints=regional).
      type: str
    is_role_anywhere:
      description:
        - Create an IAM Roles Anywhere connection, authenticated with a certificate rather
          than an access key.
        - Cannot be changed after the connection is created.
      type: bool
    iam_role_anywhere:
      description:
        - IAM Roles Anywhere settings, used when I(is_role_anywhere=true).
      type: dict
      suboptions:
        trust_anchor_arn:
          description:
            - ARN of the IAM Roles Anywhere trust anchor.
          type: str
        profile_arn:
          description:
            - ARN of the IAM Roles Anywhere profile.
          type: str
        anywhere_role_arn:
          description:
            - ARN of the role to assume.
          type: str
        certificate:
          description:
            - Certificate to authenticate with.
          type: str
        private_key:
          description:
            - Private key for the certificate.
            - CipherTrust Manager never returns this value, so supplying it on a patch
              makes the task report C(changed) on every run.
          type: str
"""

EXAMPLES = """
- name: "Check AWS credentials before creating a connection"
  thalesgroup.ciphertrust.connection_aws_test:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    access_key_id: "AKIAIOSFODNN7EXAMPLE"
    secret_access_key: "{{ vault_aws_secret_access_key }}"
  register: _aws_check

- name: "Create the connection only once the credentials are known to work"
  thalesgroup.ciphertrust.connection_aws_save:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: aws-production
    access_key_id: "AKIAIOSFODNN7EXAMPLE"
    secret_access_key: "{{ vault_aws_secret_access_key }}"
  when: _aws_check.connection_ok
"""

RETURN = r"""
changed:
    description:
      - Always C(false). Testing credentials stores nothing and changes
        nothing in CipherTrust Manager.
    returned: always
    type: bool
    sample: false
connection_ok:
    description: Whether CipherTrust Manager reached AWS with these credentials.
    returned: always
    type: bool
    sample: true
response:
    description: The raw response dictionary from the CipherTrust Manager API.
    returned: always
    type: dict
    contains:
        connection_ok:
            description: C(true) when the test succeeded.
            type: bool
            returned: always
        connection_error:
            description: Why the test failed, as reported by the provider.
            type: str
            returned: when the test failed
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connections import (
    test_error,
    test_failed,
    test_parameters,
)

_CLOUD = "aws"

_iam_role_anywhere = dict(
    trust_anchor_arn=dict(type="str"),
    profile_arn=dict(type="str"),
    anywhere_role_arn=dict(type="str"),
    certificate=dict(type="str"),
    private_key=dict(type="str", no_log=True),
)

argument_spec = dict(
    access_key_id=dict(type="str", no_log=False, required=True),
    secret_access_key=dict(type="str", no_log=True, required=True),
    cloud_name=dict(type="str", choices=["aws", "aws-us-gov", "aws-cn"]),
    assume_role_arn=dict(type="str"),
    assume_role_external_id=dict(type="str", no_log=False),
    aws_sts_regional_endpoints=dict(type="str", choices=["global", "regional"]),
    aws_region=dict(type="str"),
    is_role_anywhere=dict(type="bool"),
    iam_role_anywhere=dict(type="dict", options=_iam_role_anywhere),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=[],
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    # Nothing is stored, so this is safe to run under --check as-is.
    with ciphertrust_operation(module):
        response = test_parameters(
            node=module.params.get("localNode"),
            cloud=_CLOUD,
            access_key_id=module.params.get("access_key_id"),
            secret_access_key=module.params.get("secret_access_key"),
            cloud_name=module.params.get("cloud_name"),
            assume_role_arn=module.params.get("assume_role_arn"),
            assume_role_external_id=module.params.get("assume_role_external_id"),
            aws_sts_regional_endpoints=module.params.get("aws_sts_regional_endpoints"),
            aws_region=module.params.get("aws_region"),
            is_role_anywhere=module.params.get("is_role_anywhere"),
            iam_role_anywhere=module.params.get("iam_role_anywhere"),
        )

    result["response"] = response
    result["connection_ok"] = (response or {}).get("connection_ok")

    # A failed test comes back as HTTP 200 with connection_ok=false, so the
    # body has to be read; the status code alone would report success.
    if test_failed(response):
        module.fail_json(
            msg="AWS credentials were rejected: {0}".format(
                test_error(response)
            ),
            **result
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
