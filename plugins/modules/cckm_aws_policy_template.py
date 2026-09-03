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
module: cckm_aws_policy_template
short_description: Manage AWS key policy templates in CCKM
description:
    - Create and update the key policy templates CipherTrust Cloud Key Manager (CCKM)
      applies to AWS KMS keys.
    - A template holds one key policy, expressed either as a policy document or as lists
      of IAM users, roles and external accounts CCKM turns into one. Pass the template's
      id as I(policytemplate) to M(thalesgroup.ciphertrust.cckm_aws_key) instead of
      repeating the policy on every key.
    - Read templates with M(thalesgroup.ciphertrust.cckm_aws_policy_template_info), and
      delete one with M(thalesgroup.ciphertrust.cm_resource_delete) using
      I(resource_type=aws-policy-template).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
notes:
  - >-
    A template that is already applied to keys is updated in place, but the
    keys keep the policy they were given until the change is pushed to them.
    Set I(auto_push=true) to push the new policy to every key using the
    template.
options:
    op_type:
      description: Operation to perform.
      choices: [create, patch]
      required: true
      type: str
    template_id:
      description:
        - Name or id of the template to update.
        - Required when I(op_type=patch).
      type: str
    name:
      description:
        - Unique name for the template.
        - Required when I(op_type=create). CipherTrust Manager does not allow a template
          to be renamed, so it cannot be patched.
      type: str
    kms:
      description:
        - Name or id of the AWS account container the template is built for.
        - Used with the individual policy options, so CCKM can resolve IAM names into the
          ARNs of that account. Mutually exclusive with I(account_id).
      type: str
    account_id:
      description:
        - AWS account id the template is built for, as an alternative to naming a I(kms).
      type: str
    policy:
      description:
        - Key policy document.
        - Mutually exclusive with the individual policy options below; supply one or the
          other, not both.
      type: dict
    key_users:
      description:
        - IAM users allowed to use keys the template is applied to.
      type: list
      elements: str
    key_users_roles:
      description:
        - IAM roles allowed to use keys the template is applied to.
      type: list
      elements: str
    key_admins:
      description:
        - IAM users allowed to administer keys the template is applied to.
      type: list
      elements: str
    key_admins_roles:
      description:
        - IAM roles allowed to administer keys the template is applied to.
      type: list
      elements: str
    external_accounts:
      description:
        - AWS accounts, other than the key's own, allowed to use keys the template is
          applied to.
      type: list
      elements: str
    auto_push:
      description:
        - Push the updated policy to every key already using this template.
        - Only meaningful when I(op_type=patch). Required by CipherTrust Manager to
          update a template that has been verified.
      type: bool
"""

EXAMPLES = """
- name: "Create a policy template from IAM names"
  thalesgroup.ciphertrust.cckm_aws_policy_template:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: payments-key-policy
    kms: aws-production
    key_admins:
      - platform-admin
    key_users:
      - payments-service
    key_users_roles:
      - payments-task-role
  register: _template

- name: "Create a policy template from a policy document"
  thalesgroup.ciphertrust.cckm_aws_policy_template:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: explicit-key-policy
    kms: aws-production
    policy:
      Version: "2012-10-17"
      Statement:
        - Sid: "Enable IAM User Permissions"
          Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:root"
          Action: "kms:*"
          Resource: "*"

- name: "Add a key user and push the change to every key using the template"
  thalesgroup.ciphertrust.cckm_aws_policy_template:
    localNode: "{{ cm_connection }}"
    op_type: patch
    template_id: "{{ _template.response.id }}"
    key_users:
      - payments-service
      - reporting-service
    auto_push: true

- name: "Apply the template to a new key"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: create
    kms: aws-production
    region: us-east-1
    policytemplate: "{{ _template.response.id }}"
    aws_param:
      alias: payments-encryption

- name: "Delete the template"
  thalesgroup.ciphertrust.cm_resource_delete:
    localNode: "{{ cm_connection }}"
    key: payments-key-policy
    resource_type: aws-policy-template
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
        existing template when one was found during the GET-before-write
        idempotency check.
    returned: when a write was attempted or an existing template matched
    type: dict
    contains:
        id:
            description: Unique identifier of the template, used as I(policytemplate).
            type: str
            returned: when applicable
        name:
            description: Name of the template.
            type: str
            returned: when applicable
        policy:
            description: The key policy the template resolves to.
            type: dict
            returned: when applicable
        key_users:
            description: IAM users the template grants use of the key to.
            type: list
            elements: str
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
    idempotent_create,
    idempotent_patch,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    template_id=dict(type="str"),
    name=dict(type="str"),
    kms=dict(type="str"),
    account_id=dict(type="str"),
    policy=dict(type="dict"),
    key_users=dict(type="list", elements="str", no_log=False),
    key_users_roles=dict(type="list", elements="str", no_log=False),
    key_admins=dict(type="list", elements="str", no_log=False),
    key_admins_roles=dict(type="list", elements="str", no_log=False),
    external_accounts=dict(type="list", elements="str"),
    auto_push=dict(type="bool"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name"]],
            ["op_type", "patch", ["template_id"]],
        ),
        mutually_exclusive=[
            ["kms", "account_id"],
        ],
        supports_check_mode=True,
    )
    return module


# CipherTrust Manager accepts ``key_admins`` on a write and reports it as
# ``key-admins`` on a read. Without this the field looks absent from every
# GET, so a patch that only sets key admins would report changed for ever.
_RESPONSE_ALIASES = {
    "key_admins": "key-admins",
    "key_admins_roles": "key-admins-roles",
}


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    node = module.params.get("localNode")
    client = CipherTrustClient(node)

    with ciphertrust_operation(module):
        if module.params.get("op_type") == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint=cckm_aws.TEMPLATES,
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=cckm_aws.template_create,
                create_kwargs=dict(
                    node=node,
                    name=module.params.get("name"),
                    kms=module.params.get("kms"),
                    account_id=module.params.get("account_id"),
                    policy=module.params.get("policy"),
                    external_accounts=module.params.get("external_accounts"),
                    key_admins=module.params.get("key_admins"),
                    key_admins_roles=module.params.get("key_admins_roles"),
                    key_users=module.params.get("key_users"),
                    key_users_roles=module.params.get("key_users_roles"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_aws.TEMPLATES,
                resource_id=module.params.get("template_id"),
                # auto_push asks for the policy to be pushed to the keys using
                # the template; it is not part of the template's own state and
                # CM never reports it back.
                ignore_fields=("template_id", "auto_push"),
                response_aliases=_RESPONSE_ALIASES,
                patch_fn=cckm_aws.template_patch,
                patch_kwargs=dict(
                    node=node,
                    template_id=module.params.get("template_id"),
                    policy=module.params.get("policy"),
                    external_accounts=module.params.get("external_accounts"),
                    key_admins=module.params.get("key_admins"),
                    key_admins_roles=module.params.get("key_admins_roles"),
                    key_users=module.params.get("key_users"),
                    key_users_roles=module.params.get("key_users_roles"),
                    auto_push=module.params.get("auto_push"),
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
