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
module: cckm_aws_key
short_description: Manage AWS KMS keys through CCKM
description:
    - Create AWS KMS keys through CipherTrust Cloud Key Manager (CCKM), upload key
      material from a key source (BYOK), and perform the lifecycle operations AWS KMS
      offers -- enable, disable, rotate, schedule and cancel deletion, alias and tag
      maintenance, policy updates and multi-region replication.
    - A key belongs to an AWS account container, which must exist first; create one with
      M(thalesgroup.ciphertrust.cckm_aws_kms).
    - Read key state with M(thalesgroup.ciphertrust.cckm_aws_key_info).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.partial_diff
notes:
  - >-
    Only C(create) and C(upload) converge on a desired state. Every other
    operation acts on a key that already exists, and CipherTrust Manager does
    not report enough of AWS's state to tell beforehand whether the action
    would change anything, so those operations report C(changed) on every run.
  - >-
    C(schedule_deletion) starts AWS's waiting period before a key -- and
    everything encrypted under it -- is destroyed. C(cancel_deletion) stops it
    while the period is still running. Once the period elapses the key cannot
    be recovered by any means.
  - >-
    C(delete) removes CCKM's record of the key. The key itself remains in AWS.
    To destroy the AWS key, use C(schedule_deletion).
  - >-
    C(download_public_key) returns the public half of an asymmetric key, which
    is not secret. No operation in this module returns private key material.
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) creates a key in AWS KMS; C(upload) uploads key material from a key
          source; C(create_hyok) creates a hold-your-own-key backed by a local key store;
          C(create_in_custom_key_store) creates one inside a CloudHSM-backed store.
        - C(replicate) copies a multi-region primary key into another region, and
          C(update_primary_region) moves which region holds the primary.
        - C(enable) and C(disable) control whether AWS will use the key.
        - C(rotate) rotates through CCKM (creating new material from the key source);
          C(enable_auto_rotation) and C(disable_auto_rotation) control AWS's own yearly
          rotation; C(enable_rotation_job) and C(disable_rotation_job) control CCKM's
          scheduled rotation.
        - C(import_material), C(rotate_material) and C(delete_material) manage the key
          material of an C(EXTERNAL)-origin key.
        - C(block) and C(unblock) control whether a HYOK key will serve cryptographic
          operations.
        - C(delete) removes CCKM's record of the key without touching AWS.
      choices:
        - create
        - upload
        - create_hyok
        - create_in_custom_key_store
        - replicate
        - add_alias
        - delete_alias
        - add_tags
        - remove_tags
        - block
        - unblock
        - cancel_deletion
        - schedule_deletion
        - delete
        - delete_material
        - disable
        - enable
        - disable_auto_rotation
        - enable_auto_rotation
        - disable_rotation_job
        - enable_rotation_job
        - get_rotation_status
        - download_public_key
        - import_material
        - link
        - update_policy
        - refresh
        - rotate
        - rotate_material
        - update_description
        - update_primary_region
      required: true
      type: str
    key_id:
      description:
        - CCKM's id for the key, as returned by a create or by
          M(thalesgroup.ciphertrust.cckm_aws_key_info).
        - This is CCKM's own identifier, not the AWS key id or ARN.
        - Required for every operation except the create operations.
      type: str
    kms:
      description:
        - Name or id of the AWS account container the key belongs to.
        - Required when I(op_type=create) or I(op_type=upload).
      type: str
    region:
      description:
        - AWS region to create the key in.
        - Required when I(op_type=create) or I(op_type=upload).
      type: str
    custom_key_store_id:
      description:
        - Id of the CloudHSM-backed custom key store to create the key in.
        - Required when I(op_type=create_in_custom_key_store).
      type: str
    aws_param:
      description:
        - AWS key parameters. Which suboptions apply depends on the operation; those AWS
          rejects for an operation are documented below.
      type: dict
      suboptions:
        alias:
          description:
            - Alias for the key, without the C(alias/) prefix.
            - Used together with I(region) and I(kms) to decide whether the key already
              exists, so a create is idempotent only when an alias is given.
          type: str
        description:
          description:
            - Description of the key.
          type: str
        key_usage:
          description:
            - What the key may be used for. Defaults to C(ENCRYPT_DECRYPT).
            - Cannot be changed after the key is created.
          choices: [ENCRYPT_DECRYPT, SIGN_VERIFY, GENERATE_VERIFY_MAC]
          type: str
        customer_master_key_spec:
          description:
            - Whether the key is symmetric or an asymmetric pair, and which algorithm.
            - Defaults to C(SYMMETRIC_DEFAULT). Cannot be changed after creation.
          choices:
            - SYMMETRIC_DEFAULT
            - RSA_2048
            - RSA_3072
            - RSA_4096
            - ECC_NIST_P256
            - ECC_NIST_P384
            - ECC_NIST_P521
            - ECC_SECG_P256K1
            - HMAC_224
            - HMAC_256
            - HMAC_384
            - HMAC_512
          type: str
        origin:
          description:
            - Source of the key material. C(AWS_KMS) lets AWS generate it; C(EXTERNAL)
              creates a key with no material, to be supplied with
              I(op_type=import_material).
            - Cannot be changed after the key is created.
          choices: [AWS_KMS, EXTERNAL]
          type: str
        multi_region:
          description:
            - Create a multi-region primary key, which can later be replicated into other
              regions with I(op_type=replicate).
            - Cannot be changed after the key is created.
          type: bool
        valid_to:
          description:
            - Expiry of the uploaded key material, as an RFC3339 timestamp.
            - Only meaningful when I(op_type=upload) with I(key_expiration=true).
          type: str
        policy:
          description:
            - Key policy document to attach to the key.
            - Mutually exclusive with I(policytemplate) and with the individual policy
              options (I(key_users), I(key_admins) and the rest). If none of them are
              given, AWS's default key policy is used.
          type: dict
        bypass_policy_lockout_safety_check:
          description:
            - Skip AWS's check that the policy leaves someone able to administer the key.
            - Setting this can produce a key nobody can manage.
          type: bool
        tags:
          description:
            - Tags to set on the key at creation. Use I(op_type=add_tags) and
              I(op_type=remove_tags) to change them afterwards.
          type: list
          elements: dict
          suboptions:
            tag_key:
              description: Key of the tag.
              type: str
            tag_value:
              description: Value of the tag.
              type: str
    policytemplate:
      description:
        - Id of a policy template to apply, created with
          M(thalesgroup.ciphertrust.cckm_aws_policy_template).
        - Mutually exclusive with an inline policy and with the individual policy options.
      type: str
    key_users:
      description:
        - IAM users allowed to use the key in cryptographic operations.
      type: list
      elements: str
    key_users_roles:
      description:
        - IAM roles allowed to use the key in cryptographic operations.
      type: list
      elements: str
    key_admins:
      description:
        - IAM users allowed to administer the key through the KMS API.
      type: list
      elements: str
    key_admins_roles:
      description:
        - IAM roles allowed to administer the key through the KMS API.
      type: list
      elements: str
    external_accounts:
      description:
        - AWS accounts, other than the key's own, allowed to use the key.
      type: list
      elements: str
    policy:
      description:
        - Key policy document, for I(op_type=update_policy).
        - For the create operations, set the policy under I(aws_param) instead.
      type: dict
    local_hosted_params:
      description:
        - Settings for a HYOK key hosted by a local custom key store.
        - Used when I(op_type=create_hyok).
      type: dict
      suboptions:
        custom_key_store_id:
          description:
            - Id of the locally-hosted custom key store to create the key in.
          type: str
        source_key_id:
          description:
            - Id of the backing key -- a Luna HSM key when I(source_key_tier=hsm-luna), a
              CipherTrust Manager key when I(source_key_tier=local).
          type: str
        source_key_tier:
          description:
            - Where the backing key lives. Defaults to C(hsm-luna).
          choices: [local, hsm-luna]
          type: str
        blocked:
          description:
            - Create the key already blocked, so it serves no cryptographic operations
              until I(op_type=unblock).
          type: bool
        linked_state:
          description:
            - Whether the key is linked with AWS on creation.
          type: bool
    source_key_identifier:
      description:
        - Identifier of the key whose material is to be uploaded or imported.
        - Required when I(op_type=upload).
      type: str
    source_key_tier:
      description:
        - Key source the material comes from. Defaults to C(local), meaning CipherTrust
          Manager's own key vault.
      choices: [local, dsm, hsm-luna, external-cm]
      type: str
    source_key_id:
      description:
        - Identifier of the source key for I(op_type=rotate), when I(source_key_tier) is
          something other than C(local).
      type: str
    key_expiration:
      description:
        - Whether the uploaded or rotated key material expires.
        - Set the expiry itself in I(valid_to).
      type: bool
    valid_to:
      description:
        - Expiry of the key material, as an RFC3339 timestamp.
        - Used with I(op_type=import_material) and I(op_type=rotate).
      type: str
    alias:
      description:
        - Alias to add or delete, without the C(alias/) prefix.
        - Required when I(op_type=add_alias) or I(op_type=delete_alias).
      type: str
    tags:
      description:
        - Tags to add to the key.
        - Required when I(op_type=add_tags).
      type: list
      elements: dict
      suboptions:
        tag_key:
          description: Key of the tag.
          type: str
        tag_value:
          description: Value of the tag.
          type: str
    tag_keys:
      description:
        - Keys of the tags to remove. Only the keys are needed, not their values.
        - Required when I(op_type=remove_tags).
      type: list
      elements: str
    description:
      description:
        - New description for the key.
        - Required when I(op_type=update_description); optional for I(op_type=rotate),
          where it describes the key rotation produces.
      type: str
    days:
      description:
        - Number of days AWS waits before destroying the key.
        - Required when I(op_type=schedule_deletion). AWS accepts 7 to 30.
      type: int
    rotation_period_in_days:
      description:
        - How often AWS rotates the key by itself, in days.
        - Only for I(op_type=enable_auto_rotation). AWS's own default is 365 days.
      type: int
    job_config_id:
      description:
        - Id of the scheduler configuration that will rotate the key.
        - Required when I(op_type=enable_rotation_job).
      type: str
    auto_rotate_disable_encrypt:
      description:
        - Remove encryption permissions from the old key after a scheduled rotation, so it
          can still decrypt existing data but not encrypt new data.
        - Mutually exclusive with I(auto_rotate_disable_encrypt_on_all_accounts).
      type: bool
    auto_rotate_disable_encrypt_on_all_accounts:
      description:
        - As I(auto_rotate_disable_encrypt), but applied for every account with access to
          the key rather than only the key's own account.
      type: bool
    auto_rotate_key_source:
      description:
        - Key source scheduled rotation takes new material from. Defaults to C(local).
      choices: [local, dsm, hsm-luna, external-cm]
      type: str
    auto_rotate_domain_id:
      description:
        - Id of the DSM domain scheduled rotation creates the new key in.
        - Used when I(auto_rotate_key_source=dsm).
      type: str
    auto_rotate_partition_id:
      description:
        - Id of the Luna HSM partition scheduled rotation creates the new key in.
        - Used when I(auto_rotate_key_source=hsm-luna).
      type: str
    auto_rotate_external_cm_domain_id:
      description:
        - Id of the external CipherTrust Manager domain scheduled rotation creates the new
          key in.
        - Used when I(auto_rotate_key_source=external-cm).
      type: str
    disable_encrypt:
      description:
        - Remove encryption permissions from the old key after I(op_type=rotate).
        - Mutually exclusive with I(disable_encrypt_on_all_accounts).
      type: bool
    disable_encrypt_on_all_accounts:
      description:
        - As I(disable_encrypt), but applied for every account with access to the key.
      type: bool
    retain_alias:
      description:
        - Keep the alias, timestamped, on the archived key after I(op_type=rotate).
      type: bool
    import_type:
      description:
        - Whether I(op_type=import_material) supplies new material or re-imports material
          the key already had.
      choices: [NEW_KEY_MATERIAL, EXISTING_KEY_MATERIAL]
      type: str
    key_material_id:
      description:
        - Id of the key material to act on.
        - For I(op_type=import_material) this re-imports existing material; for
          I(op_type=delete_material) it names which material to delete. Without it,
          C(delete_material) deletes the key's current material.
      type: str
    key_material_description:
      description:
        - Description recorded against the imported key material.
      type: str
    replica_region:
      description:
        - Region to replicate the multi-region primary key into.
        - Required when I(op_type=replicate).
      type: str
    primary_region:
      description:
        - Region to make the primary of a multi-region key. A replica must already exist
          there.
        - Required when I(op_type=update_primary_region).
      type: str
"""

EXAMPLES = """
- name: "Create a symmetric AWS key"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    kms: aws-production
    region: us-east-1
    aws_param:
      alias: payments-encryption
      description: "Encrypts the payments table"
      tags:
        - tag_key: environment
          tag_value: production
  register: _key

- name: "Create an asymmetric signing key"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: create
    kms: aws-production
    region: us-east-1
    aws_param:
      alias: release-signing
      key_usage: SIGN_VERIFY
      customer_master_key_spec: RSA_4096
    key_admins:
      - platform-admin
    key_users:
      - release-pipeline

- name: "Upload a CipherTrust Manager key into AWS KMS (BYOK)"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: upload
    kms: aws-production
    region: eu-west-1
    source_key_identifier: "{{ cm_key_id }}"
    source_key_tier: local
    aws_param:
      alias: byok-payments

- name: "Rotate the key, keeping the old one able to decrypt only"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: rotate
    key_id: "{{ _key.response.id }}"
    disable_encrypt: true
    description: "rotated by Ansible"

- name: "Let AWS rotate the key every 180 days"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: enable_auto_rotation
    key_id: "{{ _key.response.id }}"
    rotation_period_in_days: 180

- name: "Tag the key"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: add_tags
    key_id: "{{ _key.response.id }}"
    tags:
      - tag_key: cost-centre
        tag_value: "4815"

- name: "Replicate a multi-region key into eu-west-1"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: replicate
    key_id: "{{ _key.response.id }}"
    replica_region: eu-west-1

- name: "Schedule the key for deletion in 30 days"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: schedule_deletion
    key_id: "{{ _key.response.id }}"
    days: 30

- name: "Change one's mind"
  thalesgroup.ciphertrust.cckm_aws_key:
    localNode: "{{ cm_connection }}"
    op_type: cancel_deletion
    key_id: "{{ _key.response.id }}"
"""

RETURN = r"""
changed:
    description: Whether the module made a change.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing key when one was found during the GET-before-write
        idempotency check.
    returned: when a request was made or an existing key matched
    type: dict
    contains:
        id:
            description: CCKM's identifier for the key, used as I(key_id).
            type: str
            returned: when applicable
        kms:
            description: Name of the AWS account container holding the key.
            type: str
            returned: when applicable
        region:
            description: AWS region the key lives in.
            type: str
            returned: when applicable
        key_state:
            description: AWS key state, such as C(Enabled) or C(PendingDeletion).
            type: str
            returned: when applicable
        aws_param:
            description:
              - The key as AWS reports it -- ARN, key id, aliases, tags, policy,
                key state and rotation status.
            type: dict
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
    create_if_absent,
    find_resource_by_filters,
)

_KEY_SOURCES = ["local", "dsm", "hsm-luna", "external-cm"]

_CMK_SPECS = [
    "SYMMETRIC_DEFAULT",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "ECC_NIST_P256",
    "ECC_NIST_P384",
    "ECC_NIST_P521",
    "ECC_SECG_P256K1",
    "HMAC_224",
    "HMAC_256",
    "HMAC_384",
    "HMAC_512",
]

_tag = dict(
    tag_key=dict(type="str", no_log=False),
    tag_value=dict(type="str"),
)

_aws_param = dict(
    alias=dict(type="str"),
    description=dict(type="str"),
    key_usage=dict(type="str",
                   choices=["ENCRYPT_DECRYPT", "SIGN_VERIFY", "GENERATE_VERIFY_MAC"]),
    customer_master_key_spec=dict(type="str", choices=_CMK_SPECS),
    origin=dict(type="str", choices=["AWS_KMS", "EXTERNAL"]),
    multi_region=dict(type="bool"),
    valid_to=dict(type="str"),
    policy=dict(type="dict"),
    bypass_policy_lockout_safety_check=dict(type="bool"),
    tags=dict(type="list", elements="dict", options=_tag),
)

_local_hosted_params = dict(
    custom_key_store_id=dict(type="str"),
    source_key_id=dict(type="str", no_log=False),
    source_key_tier=dict(type="str", choices=["local", "hsm-luna"]),
    blocked=dict(type="bool"),
    linked_state=dict(type="bool"),
)

_OP_TYPES = [
    "create",
    "upload",
    "create_hyok",
    "create_in_custom_key_store",
    "replicate",
    "add_alias",
    "delete_alias",
    "add_tags",
    "remove_tags",
    "block",
    "unblock",
    "cancel_deletion",
    "schedule_deletion",
    "delete",
    "delete_material",
    "disable",
    "enable",
    "disable_auto_rotation",
    "enable_auto_rotation",
    "disable_rotation_job",
    "enable_rotation_job",
    "get_rotation_status",
    "download_public_key",
    "import_material",
    "link",
    "update_policy",
    "refresh",
    "rotate",
    "rotate_material",
    "update_description",
    "update_primary_region",
]

argument_spec = dict(
    op_type=dict(type="str", choices=_OP_TYPES, required=True),
    key_id=dict(type="str", no_log=False),
    kms=dict(type="str"),
    region=dict(type="str"),
    custom_key_store_id=dict(type="str"),
    aws_param=dict(type="dict", options=_aws_param),
    policytemplate=dict(type="str"),
    key_users=dict(type="list", elements="str", no_log=False),
    key_users_roles=dict(type="list", elements="str", no_log=False),
    key_admins=dict(type="list", elements="str", no_log=False),
    key_admins_roles=dict(type="list", elements="str", no_log=False),
    external_accounts=dict(type="list", elements="str"),
    policy=dict(type="dict"),
    local_hosted_params=dict(type="dict", options=_local_hosted_params),
    source_key_identifier=dict(type="str", no_log=False),
    source_key_tier=dict(type="str", choices=_KEY_SOURCES, no_log=False),
    source_key_id=dict(type="str", no_log=False),
    key_expiration=dict(type="bool", no_log=False),
    valid_to=dict(type="str"),
    alias=dict(type="str"),
    tags=dict(type="list", elements="dict", options=_tag),
    tag_keys=dict(type="list", elements="str", no_log=False),
    description=dict(type="str"),
    days=dict(type="int"),
    rotation_period_in_days=dict(type="int"),
    job_config_id=dict(type="str"),
    auto_rotate_disable_encrypt=dict(type="bool"),
    auto_rotate_disable_encrypt_on_all_accounts=dict(type="bool"),
    auto_rotate_key_source=dict(type="str", choices=_KEY_SOURCES, no_log=False),
    auto_rotate_domain_id=dict(type="str"),
    auto_rotate_partition_id=dict(type="str"),
    auto_rotate_external_cm_domain_id=dict(type="str"),
    disable_encrypt=dict(type="bool"),
    disable_encrypt_on_all_accounts=dict(type="bool"),
    retain_alias=dict(type="bool"),
    import_type=dict(type="str",
                     choices=["NEW_KEY_MATERIAL", "EXISTING_KEY_MATERIAL"]),
    key_material_id=dict(type="str", no_log=False),
    key_material_description=dict(type="str", no_log=False),
    replica_region=dict(type="str"),
    primary_region=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["kms", "region"]],
            ["op_type", "upload", ["kms", "region", "source_key_identifier"]],
            ["op_type", "create_in_custom_key_store", ["custom_key_store_id", "aws_param"]],
            ["op_type", "replicate", ["key_id", "replica_region"]],
            ["op_type", "add_alias", ["key_id", "alias"]],
            ["op_type", "delete_alias", ["key_id", "alias"]],
            ["op_type", "add_tags", ["key_id", "tags"]],
            ["op_type", "remove_tags", ["key_id", "tag_keys"]],
            ["op_type", "block", ["key_id"]],
            ["op_type", "unblock", ["key_id"]],
            ["op_type", "cancel_deletion", ["key_id"]],
            ["op_type", "schedule_deletion", ["key_id", "days"]],
            ["op_type", "delete", ["key_id"]],
            ["op_type", "delete_material", ["key_id"]],
            ["op_type", "disable", ["key_id"]],
            ["op_type", "enable", ["key_id"]],
            ["op_type", "disable_auto_rotation", ["key_id"]],
            ["op_type", "enable_auto_rotation", ["key_id"]],
            ["op_type", "disable_rotation_job", ["key_id"]],
            ["op_type", "enable_rotation_job", ["key_id", "job_config_id"]],
            ["op_type", "get_rotation_status", ["key_id"]],
            ["op_type", "download_public_key", ["key_id"]],
            ["op_type", "import_material", ["key_id"]],
            ["op_type", "link", ["key_id"]],
            ["op_type", "update_policy", ["key_id"]],
            ["op_type", "refresh", ["key_id"]],
            ["op_type", "rotate", ["key_id"]],
            ["op_type", "rotate_material", ["key_id"]],
            ["op_type", "update_description", ["key_id", "description"]],
            ["op_type", "update_primary_region", ["key_id", "primary_region"]],
        ),
        mutually_exclusive=[
            ["disable_encrypt", "disable_encrypt_on_all_accounts"],
            ["auto_rotate_disable_encrypt",
             "auto_rotate_disable_encrypt_on_all_accounts"],
        ],
        supports_check_mode=True,
    )
    return module


def _policy_kwargs(params):
    """The policy options every create-style operation shares."""
    return dict(
        policytemplate=params.get("policytemplate"),
        key_users=params.get("key_users"),
        key_users_roles=params.get("key_users_roles"),
        key_admins=params.get("key_admins"),
        key_admins_roles=params.get("key_admins_roles"),
        external_accounts=params.get("external_accounts"),
    )


def _find_existing_key(client, params):
    """The key a create would produce, if it is already there.

    An AWS alias is unique within one region of one account, so all three
    have to match. Without an alias there is nothing to match on -- AWS keys
    have no other user-chosen name -- so the create proceeds, which is what
    AWS itself would do.

    ``alias`` is not confirmed against the response: CCKM reports aliases
    inside ``aws_param`` as a list, not as a top-level ``alias`` field, so
    there is nothing to compare it with at that level. ``kms`` and ``region``
    are confirmed, which is what stops an unsupported filter from being
    silently ignored and returning an unrelated key.
    """
    aws_param = params.get("aws_param") or {}
    alias = aws_param.get("alias")
    if not alias:
        return None
    return find_resource_by_filters(
        client,
        cckm_aws.KEYS,
        filters={
            "alias": alias,
            "region": params.get("region"),
            "kms": params.get("kms"),
        },
        confirm_fields=("region", "kms"),
    )


# Operations that are a bare POST to <key>/<action> with no request body.
# The module's op_type is spelled with underscores; the URL uses hyphens.
_BARE_ACTIONS = {
    "block": "block",
    "unblock": "unblock",
    "cancel_deletion": "cancel-deletion",
    "disable": "disable",
    "enable": "enable",
    "disable_auto_rotation": "disable-auto-rotation",
    "disable_rotation_job": "disable-rotation-job",
    "get_rotation_status": "get-key-rotation-status",
    "refresh": "refresh",
    "rotate_material": "rotate-material",
}

# Operations that read rather than write. They are exempt from the check-mode
# guard, so --check reports what a real run would return.
_READ_ONLY = frozenset(["get_rotation_status", "download_public_key"])


def _action_body(op_type, params):
    """The request body for an action operation, or ``None`` for a bare POST."""
    if op_type == "add_alias" or op_type == "delete_alias":
        return dict(alias=params.get("alias"))

    if op_type == "add_tags":
        # This endpoint takes snake_case tag fields, unlike the PascalCase
        # ``Tags`` that go inside ``aws_param`` on a create.
        return dict(tags=params.get("tags"))

    if op_type == "remove_tags":
        # The API takes a bare list of tag keys here, not key/value pairs.
        return dict(tags=params.get("tag_keys"))

    if op_type == "schedule_deletion":
        return dict(days=params.get("days"))

    if op_type == "update_description":
        return dict(description=params.get("description"))

    if op_type == "update_primary_region":
        return dict(PrimaryRegion=params.get("primary_region"))

    if op_type == "enable_auto_rotation":
        return dict(rotation_period_in_days=params.get("rotation_period_in_days"))

    if op_type == "enable_rotation_job":
        return dict(
            job_config_id=params.get("job_config_id"),
            auto_rotate_disable_encrypt=params.get("auto_rotate_disable_encrypt"),
            auto_rotate_disable_encrypt_on_all_accounts=params.get(
                "auto_rotate_disable_encrypt_on_all_accounts"),
            auto_rotate_key_source=params.get("auto_rotate_key_source"),
            auto_rotate_domain_id=params.get("auto_rotate_domain_id"),
            auto_rotate_partition_id=params.get("auto_rotate_partition_id"),
            auto_rotate_external_cm_domain_id=params.get(
                "auto_rotate_external_cm_domain_id"),
        )

    if op_type == "delete_material":
        return dict(key_material_id=params.get("key_material_id"))

    if op_type == "import_material":
        return dict(
            source_key_identifier=params.get("source_key_identifier"),
            source_key_tier=params.get("source_key_tier"),
            key_expiration=params.get("key_expiration"),
            valid_to=params.get("valid_to"),
            key_material_description=params.get("key_material_description"),
            import_type=params.get("import_type"),
            key_material_id=params.get("key_material_id"),
        )

    if op_type == "rotate":
        return dict(
            source_key_tier=params.get("source_key_tier"),
            source_key_id=params.get("source_key_id"),
            disable_encrypt=params.get("disable_encrypt"),
            disable_encrypt_on_all_accounts=params.get(
                "disable_encrypt_on_all_accounts"),
            description=params.get("description"),
            key_expiration=params.get("key_expiration"),
            valid_to=params.get("valid_to"),
            retain_alias=params.get("retain_alias"),
        )

    if op_type == "update_policy":
        body = dict(policy=params.get("policy"))
        body.update(_policy_kwargs(params))
        return body

    if op_type == "link":
        body = dict(aws_param=cckm_aws.aws_key_params(params.get("aws_param")))
        body.update(_policy_kwargs(params))
        return body

    return None


# op_type -> the URL segment for the operations that carry a body.
_BODY_ACTIONS = {
    "add_alias": "add-alias",
    "delete_alias": "delete-alias",
    "add_tags": "add-tags",
    "remove_tags": "remove-tags",
    "schedule_deletion": "schedule-deletion",
    "update_description": "update-description",
    "update_primary_region": "update-primary-region",
    "enable_auto_rotation": "enable-auto-rotation",
    "enable_rotation_job": "enable-rotation-job",
    "delete_material": "delete-material",
    "import_material": "import-material",
    "rotate": "rotate",
    "update_policy": "policy",
    "link": "link",
}


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    node = module.params.get("localNode")
    client = CipherTrustClient(node)
    op_type = module.params.get("op_type")
    params = module.params

    with ciphertrust_operation(module):
        if op_type in ("create", "upload"):
            existing = _find_existing_key(client, params)
            if op_type == "create":
                create_fn = cckm_aws.key_create
                create_kwargs = dict(
                    node=node,
                    kms=params.get("kms"),
                    region=params.get("region"),
                    aws_param=params.get("aws_param"),
                    **_policy_kwargs(params)
                )
            else:
                create_fn = cckm_aws.key_upload
                create_kwargs = dict(
                    node=node,
                    kms=params.get("kms"),
                    region=params.get("region"),
                    source_key_identifier=params.get("source_key_identifier"),
                    source_key_tier=params.get("source_key_tier"),
                    key_expiration=params.get("key_expiration"),
                    aws_param=params.get("aws_param"),
                    **_policy_kwargs(params)
                )

            changed, response, diff = create_if_absent(
                module, existing, create_fn, create_kwargs)
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif op_type == "create_hyok":
            check_mode_action(module)
            result["response"] = cckm_aws.key_create_hyok(
                node=node,
                local_hosted_params=params.get("local_hosted_params"),
                aws_param=params.get("aws_param"),
                **_policy_kwargs(params)
            )
            result["changed"] = True

        elif op_type == "create_in_custom_key_store":
            check_mode_action(module)
            result["response"] = cckm_aws.key_create_in_custom_key_store(
                node=node,
                custom_key_store_id=params.get("custom_key_store_id"),
                aws_param=params.get("aws_param"),
                **_policy_kwargs(params)
            )
            result["changed"] = True

        elif op_type == "replicate":
            check_mode_action(module)
            result["response"] = cckm_aws.key_replicate(
                node=node,
                key_id=params.get("key_id"),
                replica_region=params.get("replica_region"),
                aws_param=params.get("aws_param"),
                **_policy_kwargs(params)
            )
            result["changed"] = True

        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_aws.key_delete(
                node=node, key_id=params.get("key_id"))
            result["changed"] = True

        elif op_type == "download_public_key":
            # A read: it returns the public half of an asymmetric key and
            # changes nothing, so it runs unchanged under --check.
            result["response"] = cckm_aws.key_download_public_key(
                node=node, key_id=params.get("key_id"))
            result["changed"] = False

        elif op_type in _BARE_ACTIONS or op_type in _BODY_ACTIONS:
            if op_type not in _READ_ONLY:
                check_mode_action(module)
            action = _BARE_ACTIONS.get(op_type) or _BODY_ACTIONS[op_type]
            result["response"] = cckm_aws.key_action(
                node=node,
                key_id=params.get("key_id"),
                action=action,
                fields=_action_body(op_type, params),
            )
            result["changed"] = op_type not in _READ_ONLY

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
