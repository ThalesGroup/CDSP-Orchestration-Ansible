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
module: cckm_gcp_key
short_description: Manage Cloud KMS keys, their versions and their IAM policy
description:
    - Creates a Cloud KMS key, uploads one from material CipherTrust Manager holds,
      updates a key, sets its IAM policy, and manages its versions.
    - Google Cloud puts key material in versions, so enabling, disabling, destroying and
      re-importing all act on a version rather than on the key. To act on every version
      at once use M(thalesgroup.ciphertrust.cckm_gcp_update_all_versions_job).
    - Read keys, versions and policies with
      M(thalesgroup.ciphertrust.cckm_gcp_key_info).
    - Cloud KMS does not allow a key to be deleted, only its versions destroyed, so this
      module has no delete operation.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) creates a key; C(upload) creates one from material CipherTrust
          Manager holds.
        - C(patch) updates rotation, labels or the primary version; C(set_policy)
          replaces the key's IAM policy.
        - C(refresh), C(enable_auto_rotation) and C(disable_auto_rotation) act on the
          key.
        - C(create_version) adds a version. C(enable_version), C(disable_version),
          C(schedule_destroy_version), C(cancel_schedule_destroy_version),
          C(refresh_version), C(re_import_version) and C(download_public_key) act on one
          version.
      choices:
        - create
        - upload
        - patch
        - set_policy
        - refresh
        - enable_auto_rotation
        - disable_auto_rotation
        - create_version
        - enable_version
        - disable_version
        - schedule_destroy_version
        - cancel_schedule_destroy_version
        - refresh_version
        - re_import_version
        - download_public_key
      required: true
      type: str
    key_id:
      description:
        - Identifier of the key in CCKM.
        - Required for every operation except C(create) and C(upload).
      type: str
    key_ring:
      description:
        - Identifier of the key ring to create the key in.
        - Required for C(create) and C(upload).
      type: str
    gcp_key_params:
      description:
        - Cloud KMS key parameters.
        - Required for C(create) and C(upload).
      type: dict
      suboptions:
        key_name:
          description:
            - Name for the key in Cloud KMS.
            - Required.
          type: str
        algorithm:
          description:
            - Algorithm for the key's versions.
            - Required.
          choices:
            - RSA_SIGN_PSS_2048_SHA256
            - RSA_SIGN_PSS_3072_SHA256
            - RSA_SIGN_PSS_4096_SHA256
            - RSA_SIGN_PSS_4096_SHA512
            - RSA_SIGN_PKCS1_2048_SHA256
            - RSA_SIGN_PKCS1_3072_SHA256
            - RSA_SIGN_PKCS1_4096_SHA256
            - RSA_SIGN_PKCS1_4096_SHA512
            - RSA_DECRYPT_OAEP_2048_SHA256
            - RSA_DECRYPT_OAEP_3072_SHA256
            - RSA_DECRYPT_OAEP_4096_SHA256
            - RSA_DECRYPT_OAEP_4096_SHA512
            - EC_SIGN_P256_SHA256
            - EC_SIGN_P384_SHA384
            - EC_SIGN_SECP256K1_SHA256
            - GOOGLE_SYMMETRIC_ENCRYPTION
            - HMAC_SHA256
          type: str
        purpose:
          description:
            - What the key may be used for.
            - Required.
          choices: [ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, MAC]
          type: str
        protection_level:
          description:
            - Where Cloud KMS holds the key material.
            - Required.
          choices: [SOFTWARE, HSM]
          type: str
        rotation_period:
          description:
            - How often Cloud KMS rotates the key, for example C(90d).
          type: str
        next_rotation_time:
          description:
            - When the next rotation is due.
          type: str
        destroy_scheduled_duration:
          description:
            - How long a version waits between being scheduled for destruction and being
              destroyed.
          type: str
        labels:
          description:
            - Cloud KMS labels to set on the key.
          type: dict
        import_only:
          description:
            - Only allow versions created by import.
            - Used by C(upload).
          type: bool
    version_id:
      description:
        - Identifier of the key version to act on.
      type: str
    source_key_id:
      description:
        - Identifier of the CipherTrust Manager key to upload or re-import.
      type: str
    source_key_tier:
      description:
        - Where the uploaded key material comes from.
      type: str
    version_algorithm:
      description:
        - Algorithm for a version created by C(create_version).
      choices:
        - RSA_SIGN_PSS_2048_SHA256
        - RSA_SIGN_PSS_3072_SHA256
        - RSA_SIGN_PSS_4096_SHA256
        - RSA_SIGN_PSS_4096_SHA512
        - RSA_SIGN_PKCS1_2048_SHA256
        - RSA_SIGN_PKCS1_3072_SHA256
        - RSA_SIGN_PKCS1_4096_SHA256
        - RSA_SIGN_PKCS1_4096_SHA512
        - RSA_DECRYPT_OAEP_2048_SHA256
        - RSA_DECRYPT_OAEP_3072_SHA256
        - RSA_DECRYPT_OAEP_4096_SHA256
        - RSA_DECRYPT_OAEP_4096_SHA512
        - EC_SIGN_P256_SHA256
        - EC_SIGN_P384_SHA384
        - EC_SIGN_SECP256K1_SHA256
        - GOOGLE_SYMMETRIC_ENCRYPTION
        - HMAC_SHA256
      type: str
    is_native:
      description:
        - Create the version in Cloud KMS rather than importing material.
      type: bool
    primary_version_id:
      description:
        - Version to make primary. Used by C(patch).
      type: str
    next_rotation_time:
      description:
        - When the next rotation is due.
      type: str
    rotation_period:
      description:
        - How often Cloud KMS rotates the key.
      type: str
    labels:
      description:
        - Cloud KMS labels to set. Used by C(patch).
      type: dict
    version_template_algorithm:
      description:
        - Algorithm for versions created by Cloud KMS rotation.
      choices:
        - RSA_SIGN_PSS_2048_SHA256
        - RSA_SIGN_PSS_3072_SHA256
        - RSA_SIGN_PSS_4096_SHA256
        - RSA_SIGN_PSS_4096_SHA512
        - RSA_SIGN_PKCS1_2048_SHA256
        - RSA_SIGN_PKCS1_3072_SHA256
        - RSA_SIGN_PKCS1_4096_SHA256
        - RSA_SIGN_PKCS1_4096_SHA512
        - RSA_DECRYPT_OAEP_2048_SHA256
        - RSA_DECRYPT_OAEP_3072_SHA256
        - RSA_DECRYPT_OAEP_4096_SHA256
        - RSA_DECRYPT_OAEP_4096_SHA512
        - EC_SIGN_P256_SHA256
        - EC_SIGN_P384_SHA384
        - EC_SIGN_SECP256K1_SHA256
        - GOOGLE_SYMMETRIC_ENCRYPTION
        - HMAC_SHA256
      type: str
    bindings:
      description:
        - IAM policy bindings. Used by C(set_policy).
      type: list
      elements: dict
    etag:
      description:
        - Etag of the policy being replaced, for concurrency control.
      type: str
    policy_version:
      description:
        - IAM policy schema version.
      type: int
    job_config_id:
      description:
        - Scheduler configuration for the rotation job.
      type: str
    auto_rotate_key_source:
      description:
        - Where rotated key material comes from.
      type: str
    auto_rotate_algorithm:
      description:
        - Algorithm for keys created by rotation.
      choices:
        - RSA_SIGN_PSS_2048_SHA256
        - RSA_SIGN_PSS_3072_SHA256
        - RSA_SIGN_PSS_4096_SHA256
        - RSA_SIGN_PSS_4096_SHA512
        - RSA_SIGN_PKCS1_2048_SHA256
        - RSA_SIGN_PKCS1_3072_SHA256
        - RSA_SIGN_PKCS1_4096_SHA256
        - RSA_SIGN_PKCS1_4096_SHA512
        - RSA_DECRYPT_OAEP_2048_SHA256
        - RSA_DECRYPT_OAEP_3072_SHA256
        - RSA_DECRYPT_OAEP_4096_SHA256
        - RSA_DECRYPT_OAEP_4096_SHA512
        - EC_SIGN_P256_SHA256
        - EC_SIGN_P384_SHA384
        - EC_SIGN_SECP256K1_SHA256
        - GOOGLE_SYMMETRIC_ENCRYPTION
        - HMAC_SHA256
      type: str
    auto_rotate_partition_id:
      description:
        - Luna partition to rotate key material from.
      type: str
    auto_rotate_domain_id:
      description:
        - DSM domain to rotate key material from.
      type: str
    auto_rotate_external_cm_domain_id:
      description:
        - Domain on an external CipherTrust Manager to rotate key material from.
      type: str
"""

EXAMPLES = """
- name: "Create a symmetric Cloud KMS key"
  thalesgroup.ciphertrust.cckm_gcp_key:
    localNode: "{{ cm_connection }}"
    op_type: create
    key_ring: "{{ _ring.response.id }}"
    gcp_key_params:
      key_name: payments
      algorithm: GOOGLE_SYMMETRIC_ENCRYPTION
      purpose: ENCRYPT_DECRYPT
      protection_level: SOFTWARE
      rotation_period: 90d

- name: "Add a version to the key"
  thalesgroup.ciphertrust.cckm_gcp_key:
    localNode: "{{ cm_connection }}"
    op_type: create_version
    key_id: "{{ _key.response.id }}"
    is_native: true

- name: "Schedule an old version for destruction"
  thalesgroup.ciphertrust.cckm_gcp_key:
    localNode: "{{ cm_connection }}"
    op_type: schedule_destroy_version
    key_id: "{{ _key.response.id }}"
    version_id: "1"

- name: "Cancel that destruction while it is still pending"
  thalesgroup.ciphertrust.cckm_gcp_key:
    localNode: "{{ cm_connection }}"
    op_type: cancel_schedule_destroy_version
    key_id: "{{ _key.response.id }}"
    version_id: "1"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(create), C(upload) and C(patch) report accurately. The version and job
        operations have no state to compare against, so they report C(true) whenever
        they run.
      - C(download_public_key) reads Cloud KMS but is a POST in the API, so it too
        reports C(true).
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing resource when one was found during a GET-before-write
        idempotency check.
    returned: when the operation returns a body
    type: dict
diff:
    description: Present only in C(--diff) mode when a change occurred.
    returned: when diff mode is enabled and the module made a change
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_gcp,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
    create_if_absent,
    find_resource_by_filters,
    idempotent_patch,
)
_gcp_key_params = dict(
    key_name=dict(type="str", no_log=False),
    algorithm=dict(type="str", choices=[
        "RSA_SIGN_PSS_2048_SHA256",
        "RSA_SIGN_PSS_3072_SHA256",
        "RSA_SIGN_PSS_4096_SHA256",
        "RSA_SIGN_PSS_4096_SHA512",
        "RSA_SIGN_PKCS1_2048_SHA256",
        "RSA_SIGN_PKCS1_3072_SHA256",
        "RSA_SIGN_PKCS1_4096_SHA256",
        "RSA_SIGN_PKCS1_4096_SHA512",
        "RSA_DECRYPT_OAEP_2048_SHA256",
        "RSA_DECRYPT_OAEP_3072_SHA256",
        "RSA_DECRYPT_OAEP_4096_SHA256",
        "RSA_DECRYPT_OAEP_4096_SHA512",
        "EC_SIGN_P256_SHA256",
        "EC_SIGN_P384_SHA384",
        "EC_SIGN_SECP256K1_SHA256",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        "HMAC_SHA256",
    ]),
    purpose=dict(type="str", choices=["ENCRYPT_DECRYPT", "ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "MAC"]),
    protection_level=dict(type="str", choices=["SOFTWARE", "HSM"]),
    rotation_period=dict(type="str"),
    next_rotation_time=dict(type="str"),
    destroy_scheduled_duration=dict(type="str"),
    labels=dict(type="dict"),
    import_only=dict(type="bool"),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "upload",
            "patch",
            "set_policy",
            "refresh",
            "enable_auto_rotation",
            "disable_auto_rotation",
            "create_version",
            "enable_version",
            "disable_version",
            "schedule_destroy_version",
            "cancel_schedule_destroy_version",
            "refresh_version",
            "re_import_version",
            "download_public_key",
        ],
        required=True,
    ),
    key_id=dict(type="str", no_log=False),
    key_ring=dict(type="str", no_log=False),
    gcp_key_params=dict(type="dict", no_log=False, options=_gcp_key_params),
    version_id=dict(type="str"),
    source_key_id=dict(type="str", no_log=False),
    source_key_tier=dict(type="str", no_log=False),
    version_algorithm=dict(type="str", choices=[
        "RSA_SIGN_PSS_2048_SHA256",
        "RSA_SIGN_PSS_3072_SHA256",
        "RSA_SIGN_PSS_4096_SHA256",
        "RSA_SIGN_PSS_4096_SHA512",
        "RSA_SIGN_PKCS1_2048_SHA256",
        "RSA_SIGN_PKCS1_3072_SHA256",
        "RSA_SIGN_PKCS1_4096_SHA256",
        "RSA_SIGN_PKCS1_4096_SHA512",
        "RSA_DECRYPT_OAEP_2048_SHA256",
        "RSA_DECRYPT_OAEP_3072_SHA256",
        "RSA_DECRYPT_OAEP_4096_SHA256",
        "RSA_DECRYPT_OAEP_4096_SHA512",
        "EC_SIGN_P256_SHA256",
        "EC_SIGN_P384_SHA384",
        "EC_SIGN_SECP256K1_SHA256",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        "HMAC_SHA256",
    ]),
    is_native=dict(type="bool"),
    primary_version_id=dict(type="str"),
    next_rotation_time=dict(type="str"),
    rotation_period=dict(type="str"),
    labels=dict(type="dict"),
    version_template_algorithm=dict(type="str", choices=[
        "RSA_SIGN_PSS_2048_SHA256",
        "RSA_SIGN_PSS_3072_SHA256",
        "RSA_SIGN_PSS_4096_SHA256",
        "RSA_SIGN_PSS_4096_SHA512",
        "RSA_SIGN_PKCS1_2048_SHA256",
        "RSA_SIGN_PKCS1_3072_SHA256",
        "RSA_SIGN_PKCS1_4096_SHA256",
        "RSA_SIGN_PKCS1_4096_SHA512",
        "RSA_DECRYPT_OAEP_2048_SHA256",
        "RSA_DECRYPT_OAEP_3072_SHA256",
        "RSA_DECRYPT_OAEP_4096_SHA256",
        "RSA_DECRYPT_OAEP_4096_SHA512",
        "EC_SIGN_P256_SHA256",
        "EC_SIGN_P384_SHA384",
        "EC_SIGN_SECP256K1_SHA256",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        "HMAC_SHA256",
    ]),
    bindings=dict(type="list", elements="dict"),
    etag=dict(type="str"),
    policy_version=dict(type="int"),
    job_config_id=dict(type="str"),
    auto_rotate_key_source=dict(type="str", no_log=False),
    auto_rotate_algorithm=dict(type="str", choices=[
        "RSA_SIGN_PSS_2048_SHA256",
        "RSA_SIGN_PSS_3072_SHA256",
        "RSA_SIGN_PSS_4096_SHA256",
        "RSA_SIGN_PSS_4096_SHA512",
        "RSA_SIGN_PKCS1_2048_SHA256",
        "RSA_SIGN_PKCS1_3072_SHA256",
        "RSA_SIGN_PKCS1_4096_SHA256",
        "RSA_SIGN_PKCS1_4096_SHA512",
        "RSA_DECRYPT_OAEP_2048_SHA256",
        "RSA_DECRYPT_OAEP_3072_SHA256",
        "RSA_DECRYPT_OAEP_4096_SHA256",
        "RSA_DECRYPT_OAEP_4096_SHA512",
        "EC_SIGN_P256_SHA256",
        "EC_SIGN_P384_SHA384",
        "EC_SIGN_SECP256K1_SHA256",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        "HMAC_SHA256",
    ]),
    auto_rotate_partition_id=dict(type="str"),
    auto_rotate_domain_id=dict(type="str"),
    auto_rotate_external_cm_domain_id=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["key_ring", "gcp_key_params"]],
            ["op_type", "upload", ["key_ring", "gcp_key_params", "source_key_id", "source_key_tier"]],
            ["op_type", "patch", ["key_id"]],
            ["op_type", "set_policy", ["key_id"]],
            ["op_type", "refresh", ["key_id"]],
            ["op_type", "enable_auto_rotation", ["key_id", "job_config_id", "auto_rotate_key_source", "auto_rotate_algorithm"]],
            ["op_type", "disable_auto_rotation", ["key_id"]],
            ["op_type", "create_version", ["key_id"]],
            ["op_type", "enable_version", ["key_id", "version_id"]],
            ["op_type", "disable_version", ["key_id", "version_id"]],
            ["op_type", "schedule_destroy_version", ["key_id", "version_id"]],
            ["op_type", "cancel_schedule_destroy_version", ["key_id", "version_id"]],
            ["op_type", "refresh_version", ["key_id", "version_id"]],
            ["op_type", "re_import_version", ["key_id", "version_id"]],
            ["op_type", "download_public_key", ["key_id", "version_id"]],
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
    params = module.params
    op_type = params.get("op_type")
    client = CipherTrustClient(node)

    with ciphertrust_operation(module):
        if op_type in (
                "create", "upload"):
            # A Cloud KMS key name is unique within its key ring, so both
            # have to match. Only key_ring_id is confirmed against the
            # response, for the reason find_resource_by_filters documents.
            existing = None
            key_params = params.get("gcp_key_params") or {}
            if key_params.get("key_name"):
                existing = find_resource_by_filters(
                    client, cckm_gcp.KEYS,
                    filters={"name": key_params.get("key_name"),
                             "key_ring_id": params.get("key_ring")},
                    confirm_fields=("name",),
                )
            if op_type == "create":
                create_fn = cckm_gcp.key_create
                create_kwargs = dict(
                    node=node,
                    key_ring=params.get("key_ring"),
                    gcp_key_params=params.get("gcp_key_params"),
                )
            else:
                create_fn = cckm_gcp.key_upload
                create_kwargs = dict(
                    node=node,
                    key_ring=params.get("key_ring"),
                    gcp_key_params=params.get("gcp_key_params"),
                    source_key_id=params.get("source_key_id"),
                    source_key_tier=params.get("source_key_tier"),
                )
            changed, response, diff = create_if_absent(
                module, existing, create_fn=create_fn,
                create_kwargs=create_kwargs)
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_gcp.KEYS,
                resource_id=params.get("key_id"),
                ignore_fields=("key_id",),
                patch_fn=cckm_gcp.key_patch,
                patch_kwargs=dict(
                    node=node,
                    key_id=params.get("key_id"),
                    primary_version_id=params.get("primary_version_id"),
                    next_rotation_time=params.get("next_rotation_time"),
                    rotation_period=params.get("rotation_period"),
                    labels=params.get("labels"),
                    version_template_algorithm=params.get(
                        "version_template_algorithm"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "set_policy":
            check_mode_action(module)
            result["response"] = cckm_gcp.key_policy_set(
                node=node,
                key_id=params.get("key_id"),
                bindings=params.get("bindings"),
                etag=params.get("etag"),
                version=params.get("policy_version"),
            )
            result["changed"] = True
        elif op_type in (
                "refresh", "enable_auto_rotation", "disable_auto_rotation"):
            check_mode_action(module)
            fields = None
            if op_type == "enable_auto_rotation":
                fields = dict(
                    job_config_id=params.get("job_config_id"),
                    auto_rotate_key_source=params.get("auto_rotate_key_source"),
                    auto_rotate_algorithm=params.get("auto_rotate_algorithm"),
                    auto_rotate_partition_id=params.get("auto_rotate_partition_id"),
                    auto_rotate_domain_id=params.get("auto_rotate_domain_id"),
                    auto_rotate_external_cm_domain_id=params.get(
                        "auto_rotate_external_cm_domain_id"),
                )
            result["response"] = cckm_gcp.key_action(
                node=node,
                key_id=params.get("key_id"),
                action=op_type.replace("_", "-"),
                fields=fields,
            )
            result["changed"] = True
        elif op_type == "create_version":
            check_mode_action(module)
            result["response"] = cckm_gcp.key_version_create(
                node=node,
                key_id=params.get("key_id"),
                source_key_tier=params.get("source_key_tier"),
                source_key_id=params.get("source_key_id"),
                algorithm=params.get("version_algorithm"),
                is_native=params.get("is_native"),
            )
            result["changed"] = True
        elif op_type in (
                "enable_version", "disable_version",
                "schedule_destroy_version", "cancel_schedule_destroy_version",
                "refresh_version", "re_import_version", "download_public_key"):
            check_mode_action(module)
            # The API spells these actions without the _version suffix the
            # op_type carries, and download_public_key has no suffix at all.
            action_name = {
                "enable_version": "enable",
                "disable_version": "disable",
                "schedule_destroy_version": "schedule-destroy",
                "cancel_schedule_destroy_version": "cancel-schedule-destroy",
                "refresh_version": "refresh",
                "re_import_version": "re-import",
                "download_public_key": "download-public-key",
            }[op_type]
            fields = None
            if op_type == "re_import_version":
                fields = dict(
                    source_key_tier=params.get("source_key_tier"),
                    source_key_id=params.get("source_key_id"),
                )
            result["response"] = cckm_gcp.key_version_action(
                node=node,
                key_id=params.get("key_id"),
                version_id=params.get("version_id"),
                action=action_name,
                fields=fields,
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
