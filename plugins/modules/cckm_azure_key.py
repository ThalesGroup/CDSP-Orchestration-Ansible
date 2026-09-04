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
module: cckm_azure_key
short_description: Manage Azure Key Vault keys through CCKM
description:
    - Creates a key in an Azure key vault, uploads key material from a source
      CipherTrust Manager can reach, updates a key, runs the Azure soft-delete
      lifecycle, controls the rotation and backup jobs, and manages cloud key backups.
    - Read keys and backups with M(thalesgroup.ciphertrust.cckm_azure_key_info).
    - Azure deletion is two-stage -- C(soft_delete) moves the key to the vault's recycle
      bin, from which C(recover) restores it, and C(hard_delete) purges it permanently.
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
        - C(create) creates a new key in the vault; C(upload) imports existing material.
        - C(patch) updates attributes, tags and permitted operations.
        - C(soft_delete), C(recover), C(hard_delete) and C(restore) drive the Azure
          deletion lifecycle; C(refresh) re-reads the key from Azure.
        - C(enable_rotation_job) / C(disable_rotation_job) and C(enable_backup_job) /
          C(disable_backup_job) control the scheduled jobs.
        - C(create_backup), C(patch_backup) and C(delete_backup) manage one cloud key
          backup; C(delete_backups) removes them all.
      choices:
        - create
        - upload
        - patch
        - soft_delete
        - hard_delete
        - recover
        - restore
        - refresh
        - enable_rotation_job
        - disable_rotation_job
        - enable_backup_job
        - disable_backup_job
        - delete_backups
        - create_backup
        - patch_backup
        - delete_backup
      required: true
      type: str
    key_id:
      description:
        - Identifier of the key in CCKM.
        - Required for every operation except C(create) and C(upload).
      type: str
    key_name:
      description:
        - Name for the key in Azure.
        - Azure key names accept alphanumerics and dashes only.
        - Required for C(create) and C(upload).
      type: str
    key_vault:
      description:
        - Name or id of the Azure vault.
        - Required for C(create) and C(upload); also names the destination vault for
          C(restore).
      type: str
    azure_param:
      description:
        - Azure key parameters.
        - Required for C(create).
      type: dict
      suboptions:
        kty:
          description:
            - Key type. The C(-HSM) variants require a premium vault or a managed HSM.
            - Required when creating a key.
          choices: [EC, EC-HSM, RSA, RSA-HSM]
          type: str
        key_size:
          description:
            - RSA key size in bits.
          choices: [2048, 3072, 4096]
          type: int
        crv:
          description:
            - Elliptic curve name, for the C(EC) key types.
          choices: [P-256, P-384, P-521, SECP256K1]
          type: str
        key_ops:
          description:
            - Permitted key operations.
          type: list
          elements: str
        tags:
          description:
            - Azure tags to set on the key.
          type: dict
        attributes:
          description:
            - Azure key attributes.
          type: dict
          suboptions:
            enabled:
              description:
                - Whether the object is enabled.
              type: bool
            nbf:
              description:
                - Not-before time, as an Azure timestamp.
              type: str
            exp:
              description:
                - Expiry time, as an Azure timestamp.
              type: str
    exportable:
      description:
        - Allow Azure to release the private key. Needs a premium vault or a managed
          HSM, and I(release_policy) must be set.
      type: bool
    release_policy:
      description:
        - Key release policy, required when I(exportable=true).
      type: dict
    attributes:
      description:
        - Azure key attributes to update. Used by C(patch).
      type: dict
      suboptions:
        enabled:
          description:
            - Whether the object is enabled.
          type: bool
        nbf:
          description:
            - Not-before time, as an Azure timestamp.
          type: str
        exp:
          description:
            - Expiry time, as an Azure timestamp.
          type: str
    tags:
      description:
        - Azure tags to set. Used by C(patch).
      type: dict
    key_ops:
      description:
        - Permitted key operations. Used by C(patch).
      type: list
      elements: str
    local_key_identifier:
      description:
        - Identifier of a CipherTrust Manager key to upload. Used by C(upload).
      type: str
    source_key_tier:
      description:
        - Where the uploaded key material comes from.
      type: str
    pfx:
      description:
        - PFX-encoded key material to upload.
        - CipherTrust Manager never returns this value.
      type: str
    password:
      description:
        - Password protecting I(pfx).
      type: str
    luna_key_identifier:
      description:
        - Identifier of a Luna HSM key to upload.
      type: str
    dsm_key_identifier:
      description:
        - Identifier of a DSM key to upload.
      type: str
    external_cm_key_identifier:
      description:
        - Identifier of a key on an external CipherTrust Manager.
      type: str
    kek_kid:
      description:
        - Key encryption key identifier used to wrap the uploaded material.
      type: str
    backup_id:
      description:
        - Identifier of a cloud key backup.
      type: str
    backup_name:
      description:
        - Name for a cloud key backup.
      type: str
    description:
      description:
        - Description for a cloud key backup.
      type: str
    azure_cloud_key_backup_id:
      description:
        - Backup to restore from. Used by C(restore).
      type: str
    job_config_id:
      description:
        - Scheduler configuration for the rotation job.
      type: str
    backup_job_config_id:
      description:
        - Scheduler configuration for the backup job.
      type: str
    auto_rotate_key_source:
      description:
        - Where rotated key material comes from.
      type: str
    auto_rotate_key_type:
      description:
        - Key type to create on rotation.
      choices: [EC, EC-HSM, RSA, RSA-HSM]
      type: str
    auto_rotate_key_size:
      description:
        - Key size to create on rotation.
      choices: [2048, 3072, 4096]
      type: int
    auto_rotate_ec_name:
      description:
        - Elliptic curve to use on rotation.
      choices: [P-256, P-384, P-521, SECP256K1]
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
    auto_rotate_enable_key:
      description:
        - Enable the key produced by a rotation.
      type: bool
    auto_rotate_release_policy:
      description:
        - Release policy applied to the key produced by a rotation.
      type: dict
"""

EXAMPLES = """
- name: "Create an RSA key in an Azure vault"
  thalesgroup.ciphertrust.cckm_azure_key:
    localNode: "{{ cm_connection }}"
    op_type: create
    key_name: payments-signing
    key_vault: production-vault
    azure_param:
      kty: RSA
      key_size: 2048
      key_ops:
        - sign
        - verify

- name: "Soft-delete the key, then recover it"
  thalesgroup.ciphertrust.cckm_azure_key:
    localNode: "{{ cm_connection }}"
    op_type: soft_delete
    key_id: "{{ _key.response.id }}"

- name: "Recover a soft-deleted key"
  thalesgroup.ciphertrust.cckm_azure_key:
    localNode: "{{ cm_connection }}"
    op_type: recover
    key_id: "{{ _key.response.id }}"

- name: "Take a cloud backup of the key"
  thalesgroup.ciphertrust.cckm_azure_key:
    localNode: "{{ cm_connection }}"
    op_type: create_backup
    key_id: "{{ _key.response.id }}"
    backup_name: nightly
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(create), C(upload) and C(patch) report accurately. The lifecycle and job
        operations have no state to compare against, so they report C(true) whenever
        they run.
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
    cckm_azure,
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
_attributes = dict(
    enabled=dict(type="bool"),
    nbf=dict(type="str"),
    exp=dict(type="str"),
)

_azure_param = dict(
    kty=dict(type="str", choices=["EC", "EC-HSM", "RSA", "RSA-HSM"]),
    key_size=dict(type="int", choices=[2048, 3072, 4096], no_log=False),
    crv=dict(type="str", choices=["P-256", "P-384", "P-521", "SECP256K1"]),
    key_ops=dict(type="list", elements="str", no_log=False),
    tags=dict(type="dict"),
    attributes=dict(type="dict", options=_attributes),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "upload",
            "patch",
            "soft_delete",
            "hard_delete",
            "recover",
            "restore",
            "refresh",
            "enable_rotation_job",
            "disable_rotation_job",
            "enable_backup_job",
            "disable_backup_job",
            "delete_backups",
            "create_backup",
            "patch_backup",
            "delete_backup",
        ],
        required=True,
    ),
    key_id=dict(type="str"),
    key_name=dict(type="str"),
    key_vault=dict(type="str", no_log=False),
    azure_param=dict(type="dict", options=_azure_param),
    exportable=dict(type="bool"),
    release_policy=dict(type="dict"),
    attributes=dict(type="dict", options=_attributes),
    tags=dict(type="dict"),
    key_ops=dict(type="list", elements="str", no_log=False),
    local_key_identifier=dict(type="str"),
    source_key_tier=dict(type="str", no_log=False),
    pfx=dict(type="str", no_log=True),
    password=dict(type="str", no_log=True),
    luna_key_identifier=dict(type="str"),
    dsm_key_identifier=dict(type="str"),
    external_cm_key_identifier=dict(type="str"),
    kek_kid=dict(type="str", no_log=False),
    backup_id=dict(type="str"),
    backup_name=dict(type="str"),
    description=dict(type="str"),
    azure_cloud_key_backup_id=dict(type="str"),
    job_config_id=dict(type="str"),
    backup_job_config_id=dict(type="str"),
    auto_rotate_key_source=dict(type="str", no_log=False),
    auto_rotate_key_type=dict(type="str", choices=["EC", "EC-HSM", "RSA", "RSA-HSM"]),
    auto_rotate_key_size=dict(type="int", choices=[2048, 3072, 4096]),
    auto_rotate_ec_name=dict(type="str", choices=["P-256", "P-384", "P-521", "SECP256K1"]),
    auto_rotate_partition_id=dict(type="str"),
    auto_rotate_domain_id=dict(type="str"),
    auto_rotate_external_cm_domain_id=dict(type="str"),
    auto_rotate_enable_key=dict(type="bool"),
    auto_rotate_release_policy=dict(type="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["key_name", "key_vault", "azure_param"]],
            ["op_type", "upload", ["key_name", "key_vault"]],
            ["op_type", "patch", ["key_id"]],
            ["op_type", "soft_delete", ["key_id"]],
            ["op_type", "hard_delete", ["key_id"]],
            ["op_type", "recover", ["key_id"]],
            ["op_type", "restore", ["key_id"]],
            ["op_type", "refresh", ["key_id"]],
            ["op_type", "enable_rotation_job", ["key_id", "job_config_id", "auto_rotate_key_source", "auto_rotate_key_type"]],
            ["op_type", "disable_rotation_job", ["key_id"]],
            ["op_type", "enable_backup_job", ["key_id", "backup_job_config_id"]],
            ["op_type", "disable_backup_job", ["key_id"]],
            ["op_type", "delete_backups", ["key_id"]],
            ["op_type", "create_backup", ["key_id"]],
            ["op_type", "patch_backup", ["key_id", "backup_id"]],
            ["op_type", "delete_backup", ["key_id", "backup_id"]],
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
            # An Azure key name is unique within a vault, so both have to
            # match. Only key_vault is confirmed against the response, for the
            # reason find_resource_by_filters documents: an unconfirmed filter
            # CipherTrust Manager ignores would otherwise return an unrelated
            # key.
            existing = None
            if params.get("key_name"):
                existing = find_resource_by_filters(
                    client, cckm_azure.KEYS,
                    filters={"key_name": params.get("key_name"),
                             "key_vault": params.get("key_vault")},
                    confirm_fields=("key_vault",),
                )
            if op_type == "create":
                create_fn = cckm_azure.key_create
                create_kwargs = dict(
                    node=node,
                    key_name=params.get("key_name"),
                    key_vault=params.get("key_vault"),
                    azure_param=params.get("azure_param"),
                    exportable=params.get("exportable"),
                    release_policy=params.get("release_policy"),
                )
            else:
                create_fn = cckm_azure.key_upload
                create_kwargs = dict(
                    node=node,
                    key_name=params.get("key_name"),
                    key_vault=params.get("key_vault"),
                    azure_param=params.get("azure_param"),
                    local_key_identifier=params.get("local_key_identifier"),
                    source_key_tier=params.get("source_key_tier"),
                    pfx=params.get("pfx"),
                    password=params.get("password"),
                    luna_key_identifier=params.get("luna_key_identifier"),
                    dsm_key_identifier=params.get("dsm_key_identifier"),
                    external_cm_key_identifier=params.get(
                        "external_cm_key_identifier"),
                    kek_kid=params.get("kek_kid"),
                    exportable=params.get("exportable"),
                    release_policy=params.get("release_policy"),
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
                endpoint=cckm_azure.KEYS,
                resource_id=params.get("key_id"),
                ignore_fields=("key_id",),
                patch_fn=cckm_azure.key_patch,
                patch_kwargs=dict(
                    node=node,
                    key_id=params.get("key_id"),
                    attributes=params.get("attributes"),
                    tags=params.get("tags"),
                    key_ops=params.get("key_ops"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type in (
                "soft_delete", "hard_delete", "recover", "restore", "refresh",
                "enable_rotation_job", "disable_rotation_job",
                "enable_backup_job", "disable_backup_job", "delete_backups"):
            check_mode_action(module)
            fields = None
            if op_type == "enable_rotation_job":
                fields = dict(
                    job_config_id=params.get("job_config_id"),
                    auto_rotate_key_source=params.get("auto_rotate_key_source"),
                    auto_rotate_key_type=params.get("auto_rotate_key_type"),
                    auto_rotate_key_size=params.get("auto_rotate_key_size"),
                    auto_rotate_ec_name=params.get("auto_rotate_ec_name"),
                    auto_rotate_partition_id=params.get("auto_rotate_partition_id"),
                    auto_rotate_domain_id=params.get("auto_rotate_domain_id"),
                    auto_rotate_external_cm_domain_id=params.get(
                        "auto_rotate_external_cm_domain_id"),
                    auto_rotate_enable_key=params.get("auto_rotate_enable_key"),
                    auto_rotate_release_policy=params.get("auto_rotate_release_policy"),
                )
            elif op_type == "enable_backup_job":
                fields = dict(
                    backup_job_config_id=params.get("backup_job_config_id"))
            elif op_type == "restore":
                fields = dict(
                    key_vault=params.get("key_vault"),
                    azure_cloud_key_backup_id=params.get("azure_cloud_key_backup_id"),
                )
            # "delete_backups" is the collection-wide purge, spelled
            # delete-backup by the API; the per-backup delete is a DELETE on
            # the backup itself and is handled below.
            action_name = ("delete-backup" if op_type == "delete_backups"
                           else op_type.replace("_", "-"))
            result["response"] = cckm_azure.key_action(
                node=node,
                key_id=params.get("key_id"),
                action=action_name,
                fields=fields,
            )
            result["changed"] = True
        elif op_type == "create_backup":
            check_mode_action(module)
            result["response"] = cckm_azure.key_backup_create(
                node=node,
                key_id=params.get("key_id"),
                name=params.get("backup_name"),
                description=params.get("description"),
            )
            result["changed"] = True
        elif op_type == "patch_backup":
            check_mode_action(module)
            result["response"] = cckm_azure.key_backup_patch(
                node=node,
                key_id=params.get("key_id"),
                backup_id=params.get("backup_id"),
                name=params.get("backup_name"),
                description=params.get("description"),
            )
            result["changed"] = True
        elif op_type == "delete_backup":
            check_mode_action(module)
            result["response"] = cckm_azure.key_backup_delete(
                node=node,
                key_id=params.get("key_id"),
                backup_id=params.get("backup_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
