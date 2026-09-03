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
module: cckm_aws_kms
short_description: Manage AWS account containers (KMS) in CCKM
description:
    - Add, update, archive and recover the AWS account containers that CipherTrust Cloud
      Key Manager (CCKM) manages AWS KMS keys through.
    - A KMS container names one AWS account, the connection CipherTrust Manager reaches it
      with, and the AWS regions CCKM manages within it. Every other CCKM AWS resource --
      keys, policy templates, custom key stores, reports -- is scoped to one.
    - Create the connection first with M(thalesgroup.ciphertrust.connection_aws_save), and
      discover the account id and the available regions with
      M(thalesgroup.ciphertrust.cckm_aws_account_info).
    - Delete a container with M(thalesgroup.ciphertrust.cm_resource_delete) using
      I(resource_type=aws-kms).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.partial_diff
notes:
  - >-
    C(archive) and C(recover) perform an action rather than converging on a
    state. CipherTrust Manager does not report whether a container is archived
    in a form this module can read back, so they report C(changed) on every
    run.
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) adds an account container, C(patch) updates one.
        - C(archive) takes a container out of service, and C(recover) returns it.
        - C(update_acls) replaces the per-user and per-group permissions on a container.
      choices: [create, patch, archive, recover, update_acls]
      required: true
      type: str
    kms_id:
      description:
        - Name or id of the KMS container to act on.
        - Required for every operation except I(op_type=create).
      type: str
    name:
      description:
        - Unique name for the KMS container.
        - Required when I(op_type=create). CipherTrust Manager does not allow a container
          to be renamed, so it cannot be patched.
      type: str
    account_id:
      description:
        - The 12-digit AWS account id the container manages.
        - Required when I(op_type=create). It cannot be changed afterwards.
      type: str
    connection:
      description:
        - Name or id of the AWS connection CipherTrust Manager reaches the account with.
        - Required when I(op_type=create).
      type: str
    regions:
      description:
        - AWS regions CCKM manages within the account.
        - Required when I(op_type=create).
        - On a patch this replaces the region list rather than adding to it, so pass the
          full set you want. Removing a region CCKM holds keys in is refused by
          CipherTrust Manager.
      type: list
      elements: str
    assume_role_arn:
      description:
        - ARN of an AWS IAM role for CipherTrust Manager to assume when reaching this
          account, instead of using the connection's own identity.
      type: str
    assume_role_external_id:
      description:
        - External id required when assuming the role.
        - Only meaningful alongside I(assume_role_arn).
      type: str
    acls:
      description:
        - Per-user and per-group permissions on the container.
        - Required when I(op_type=update_acls). The list replaces whatever is currently
          set, so include every entry you want to keep.
      type: list
      elements: dict
      suboptions:
        user_id:
          description:
            - Id of the user the permissions apply to.
            - Mutually exclusive with I(group).
          type: str
        group:
          description:
            - Name of the user group the permissions apply to.
            - Mutually exclusive with I(user_id).
          type: str
        permit:
          description:
            - Whether to permit the actions (C(true)) or deny them (C(false)).
          type: bool
        actions:
          description:
            - Actions the entry permits or denies.
          type: list
          elements: str
          choices:
            - keycreate
            - keyupdate
            - keymaterialimport
            - keymaterialdelete
            - keyrotate
            - keydelete
            - keycanceldelete
            - keysynchronize
            - keyupload
            - viewnative
            - viewbyok
            - reportview
            - reportcreate
            - reportdelete
            - reportdownload
"""

EXAMPLES = """
- name: "Add an AWS account container to CCKM"
  thalesgroup.ciphertrust.cckm_aws_kms:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: aws-production
    account_id: "123456789012"
    connection: aws-production-connection
    regions:
      - us-east-1
      - eu-west-1
  register: _kms

- name: "Manage an additional region"
  thalesgroup.ciphertrust.cckm_aws_kms:
    localNode: "{{ cm_connection }}"
    op_type: patch
    kms_id: "{{ _kms.response.id }}"
    regions:
      - us-east-1
      - eu-west-1
      - ap-south-1

- name: "Add a container reached by assuming a role"
  thalesgroup.ciphertrust.cckm_aws_kms:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: aws-audit
    account_id: "210987654321"
    connection: aws-production-connection
    regions:
      - us-east-1
    assume_role_arn: "arn:aws:iam::210987654321:role/CCKMAudit"
    assume_role_external_id: cckm-audit

- name: "Let the cloud team create and rotate keys, and nothing else"
  thalesgroup.ciphertrust.cckm_aws_kms:
    localNode: "{{ cm_connection }}"
    op_type: update_acls
    kms_id: aws-production
    acls:
      - group: cloud-team
        permit: true
        actions:
          - keycreate
          - keyrotate
          - viewnative

- name: "Take a container out of service"
  thalesgroup.ciphertrust.cckm_aws_kms:
    localNode: "{{ cm_connection }}"
    op_type: archive
    kms_id: aws-audit

- name: "Remove a container from CCKM"
  thalesgroup.ciphertrust.cm_resource_delete:
    localNode: "{{ cm_connection }}"
    key: aws-audit
    resource_type: aws-kms
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
        existing container when one was found during the GET-before-write
        idempotency check.
    returned: when a write was attempted or an existing container matched
    type: dict
    contains:
        id:
            description: Unique identifier of the KMS container.
            type: str
            returned: when applicable
        name:
            description: Name of the KMS container.
            type: str
            returned: when applicable
        account_id:
            description: AWS account id the container manages.
            type: str
            returned: when applicable
        connection:
            description: Connection CipherTrust Manager reaches the account with.
            type: str
            returned: when applicable
        regions:
            description: AWS regions CCKM manages within the account.
            type: list
            elements: str
            returned: when applicable
        arn:
            description: ARN of the identity CipherTrust Manager authenticates as.
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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
    idempotent_create,
    idempotent_patch,
)

_ACL_ACTIONS = [
    "keycreate",
    "keyupdate",
    "keymaterialimport",
    "keymaterialdelete",
    "keyrotate",
    "keydelete",
    "keycanceldelete",
    "keysynchronize",
    "keyupload",
    "viewnative",
    "viewbyok",
    "reportview",
    "reportcreate",
    "reportdelete",
    "reportdownload",
]

_acl = dict(
    user_id=dict(type="str"),
    group=dict(type="str"),
    permit=dict(type="bool"),
    actions=dict(type="list", elements="str", choices=_ACL_ACTIONS),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=["create", "patch", "archive", "recover", "update_acls"],
        required=True,
    ),
    kms_id=dict(type="str"),
    name=dict(type="str"),
    account_id=dict(type="str"),
    connection=dict(type="str"),
    regions=dict(type="list", elements="str"),
    assume_role_arn=dict(type="str"),
    assume_role_external_id=dict(type="str", no_log=False),
    acls=dict(type="list", elements="dict", options=_acl),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name", "account_id", "connection", "regions"]],
            ["op_type", "patch", ["kms_id"]],
            ["op_type", "archive", ["kms_id"]],
            ["op_type", "recover", ["kms_id"]],
            ["op_type", "update_acls", ["kms_id", "acls"]],
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
    client = CipherTrustClient(node)
    op_type = module.params.get("op_type")

    with ciphertrust_operation(module):
        if op_type == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint=cckm_aws.KMS,
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=cckm_aws.kms_create,
                create_kwargs=dict(
                    node=node,
                    name=module.params.get("name"),
                    account_id=module.params.get("account_id"),
                    connection=module.params.get("connection"),
                    regions=module.params.get("regions"),
                    assume_role_arn=module.params.get("assume_role_arn"),
                    assume_role_external_id=module.params.get("assume_role_external_id"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_aws.KMS,
                resource_id=module.params.get("kms_id"),
                ignore_fields=("kms_id",),
                patch_fn=cckm_aws.kms_patch,
                patch_kwargs=dict(
                    node=node,
                    kms_id=module.params.get("kms_id"),
                    connection=module.params.get("connection"),
                    regions=module.params.get("regions"),
                    assume_role_arn=module.params.get("assume_role_arn"),
                    assume_role_external_id=module.params.get("assume_role_external_id"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif op_type in ("archive", "recover"):
            check_mode_action(module)
            result["response"] = cckm_aws.kms_action(
                node=node,
                kms_id=module.params.get("kms_id"),
                action=op_type,
            )
            result["changed"] = True

        elif op_type == "update_acls":
            check_mode_action(module)
            result["response"] = cckm_aws.kms_update_acls(
                node=node,
                kms_id=module.params.get("kms_id"),
                acls=module.params.get("acls"),
            )
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
