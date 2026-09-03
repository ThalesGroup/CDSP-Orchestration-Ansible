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
module: connection_aws_save
short_description: Manage AWS connections in CipherTrust Manager's connection manager
description:
    - Create or update an AWS connection in the CipherTrust Manager connection manager.
    - An AWS connection stores the credentials CipherTrust Manager uses to reach an AWS
      account, and is referenced by products such as CCKM.
    - Authenticate with an access key pair, by assuming a role, or with IAM Roles
      Anywhere.
    - Delete a connection with M(thalesgroup.ciphertrust.cm_resource_delete) using
      I(resource_type=aws-connection), and test one with
      M(thalesgroup.ciphertrust.connection_test).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch]
      required: true
      type: str
    connection_id:
      description:
        - Name or id of the connection to update.
        - Required when I(op_type=patch).
      type: str
    name:
      description:
        - Unique name for the connection.
        - Required when I(op_type=create). CipherTrust Manager does not allow a connection
          to be renamed, so it cannot be patched.
      type: str
    access_key_id:
      description:
        - Access key id of the AWS user.
      type: str
    secret_access_key:
      description:
        - Secret associated with the access key id.
        - CipherTrust Manager never returns this value, so supplying it on a patch makes
          the task report C(changed) on every run.
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
    products:
      description:
        - CipherTrust products that may use this connection.
        - C(cckm) is the value for cloud connections; GCP connections also accept C(ddc).
      type: list
      elements: str
    description:
      description:
        - Description of the connection.
      type: str
    meta:
      description:
        - Arbitrary end-user or service data stored alongside the connection.
      type: dict
    labels:
      description:
        - Key/value pairs used to group resources, following Kubernetes label conventions.
      type: dict
"""

EXAMPLES = """
- name: "Create an AWS connection with an access key pair"
  thalesgroup.ciphertrust.connection_aws_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: aws-production
    description: "Production AWS account"
    products:
      - cckm
    access_key_id: "AKIAIOSFODNN7EXAMPLE"
    secret_access_key: "{{ vault_aws_secret_access_key }}"
    cloud_name: aws

- name: "Create an AWS connection that assumes a role"
  thalesgroup.ciphertrust.connection_aws_save:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: aws-audit
    access_key_id: "AKIAIOSFODNN7EXAMPLE"
    secret_access_key: "{{ vault_aws_secret_access_key }}"
    assume_role_arn: "arn:aws:iam::123456789012:role/CipherTrustAudit"
    assume_role_external_id: "cm-audit"

- name: "Update the description of an AWS connection"
  thalesgroup.ciphertrust.connection_aws_save:
    localNode: "{{ cm_connection }}"
    op_type: patch
    connection_id: aws-production
    description: "Production AWS account (eu-west-1)"

- name: "Delete an AWS connection"
  thalesgroup.ciphertrust.cm_resource_delete:
    localNode: "{{ cm_connection }}"
    key: aws-production
    resource_type: aws-connection
"""

RETURN = r"""
changed:
    description: Whether any change was made to CipherTrust Manager state.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing connection when one was found during the GET-before-write
        idempotency check.
      - Secrets are never returned by CipherTrust Manager, so they do not
        appear here.
    returned: when a write was attempted or an existing connection matched
    type: dict
    contains:
        id:
            description: Unique identifier of the connection.
            type: str
            returned: when applicable
        name:
            description: Name of the connection.
            type: str
            returned: when applicable
        uri:
            description: Canonical resource URI.
            type: str
            returned: when applicable
        createdAt:
            description: RFC3339 timestamp of creation.
            type: str
            returned: when applicable
        updatedAt:
            description: RFC3339 timestamp of last modification.
            type: str
            returned: when applicable
diff:
    description: Present only in C(--diff) mode when a change occurred.
    returned: when diff mode is enabled and the module made a change
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connections import (
    create,
    patch,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_create,
    idempotent_patch,
)

_CLOUD = "aws"
_ENDPOINT = "connectionmgmt/services/aws/connections"

_iam_role_anywhere = dict(
    trust_anchor_arn=dict(type="str"),
    profile_arn=dict(type="str"),
    anywhere_role_arn=dict(type="str"),
    certificate=dict(type="str"),
    private_key=dict(type="str", no_log=True),
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    connection_id=dict(type="str"),
    name=dict(type="str"),
    access_key_id=dict(type="str", no_log=False),
    secret_access_key=dict(type="str", no_log=True),
    cloud_name=dict(type="str", choices=["aws", "aws-us-gov", "aws-cn"]),
    assume_role_arn=dict(type="str"),
    assume_role_external_id=dict(type="str", no_log=False),
    aws_sts_regional_endpoints=dict(type="str", choices=["global", "regional"]),
    aws_region=dict(type="str"),
    is_role_anywhere=dict(type="bool"),
    iam_role_anywhere=dict(type="dict", options=_iam_role_anywhere),
    products=dict(type="list", elements="str"),
    description=dict(type="str"),
    meta=dict(type="dict"),
    labels=dict(type="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["connection_id"]],
            ["op_type", "create", ["name"]],
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

    client = CipherTrustClient(module.params.get("localNode"))

    with ciphertrust_operation(module):
        if module.params.get("op_type") == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint=_ENDPOINT,
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=create,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    cloud=_CLOUD,
                    name=module.params.get("name"),
                    access_key_id=module.params.get("access_key_id"),
                    secret_access_key=module.params.get("secret_access_key"),
                    cloud_name=module.params.get("cloud_name"),
                    assume_role_arn=module.params.get("assume_role_arn"),
                    assume_role_external_id=module.params.get("assume_role_external_id"),
                    aws_sts_regional_endpoints=module.params.get("aws_sts_regional_endpoints"),
                    aws_region=module.params.get("aws_region"),
                    is_role_anywhere=module.params.get("is_role_anywhere"),
                    iam_role_anywhere=module.params.get("iam_role_anywhere"),
                    products=module.params.get("products"),
                    description=module.params.get("description"),
                    meta=module.params.get("meta"),
                    labels=module.params.get("labels"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=_ENDPOINT,
                resource_id=module.params.get("connection_id"),
                ignore_fields=("cloud", "connection_id"),
                patch_fn=patch,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    cloud=_CLOUD,
                    connection_id=module.params.get("connection_id"),
                    access_key_id=module.params.get("access_key_id"),
                    secret_access_key=module.params.get("secret_access_key"),
                    cloud_name=module.params.get("cloud_name"),
                    assume_role_arn=module.params.get("assume_role_arn"),
                    assume_role_external_id=module.params.get("assume_role_external_id"),
                    aws_sts_regional_endpoints=module.params.get("aws_sts_regional_endpoints"),
                    aws_region=module.params.get("aws_region"),
                    iam_role_anywhere=module.params.get("iam_role_anywhere"),
                    products=module.params.get("products"),
                    description=module.params.get("description"),
                    meta=module.params.get("meta"),
                    labels=module.params.get("labels"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
