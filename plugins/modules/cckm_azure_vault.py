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
module: cckm_azure_vault
short_description: Add and manage Azure key vaults in CCKM
description:
    - Adds an existing Azure key vault to CCKM, updates one CCKM already manages,
      controls its rotation job, replaces its access control list, or removes it from
      CCKM.
    - A vault is not created here. It already exists in Azure; discover the candidates
      with M(thalesgroup.ciphertrust.cckm_azure_vault_info) using I(op_type=available),
      then add the ones you want.
    - Removing a vault removes it from CCKM only. Nothing in Azure is deleted.
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
        - C(add) registers one or more Azure vaults with CCKM.
        - C(patch) updates a vault CCKM already manages.
        - C(enable_rotation_job) and C(disable_rotation_job) control scheduled key
          rotation for the vault.
        - C(update_acls) replaces the vault's access control list.
        - C(remove_vault) removes the vault from CCKM.
      choices:
        - add
        - patch
        - enable_rotation_job
        - disable_rotation_job
        - remove_vault
        - update_acls
      required: true
      type: str
    vault_id:
      description:
        - Identifier of the vault in CCKM.
        - Required for every operation except C(add).
      type: str
    connection:
      description:
        - Name or id of the Azure connection that reaches the vault.
        - Required for C(add) and C(patch).
      type: str
    subscription_id:
      description:
        - Azure subscription the vault belongs to.
        - Required for C(add).
      type: str
    vaults:
      description:
        - Azure vaults to add, as returned by
          M(thalesgroup.ciphertrust.cckm_azure_vault_info) with I(op_type=available).
        - Required for C(add).
      type: list
      elements: dict
    vault_name:
      description:
        - Name of the vault being added.
        - Optional, and used only to make C(add) idempotent -- when given, the module
          first looks for a vault of that name in the subscription and reports no change
          if it is already there.
      type: str
    cloud_key_backup_limit:
      description:
        - Maximum number of cloud key backups to retain.
      type: int
    job_config_id:
      description:
        - Scheduler configuration for the rotation job.
        - Required for C(enable_rotation_job).
      type: str
    override_key_scheduler:
      description:
        - Let the vault's rotation schedule override a per-key schedule.
      type: bool
    acls:
      description:
        - Access control entries to apply.
        - Required for C(update_acls).
      type: list
      elements: dict
"""

EXAMPLES = """
- name: "Add a discovered Azure vault to CCKM"
  thalesgroup.ciphertrust.cckm_azure_vault:
    localNode: "{{ cm_connection }}"
    op_type: add
    connection: azure-production
    subscription_id: "00000000-0000-0000-0000-000000000000"
    vault_name: production-vault
    vaults:
      - "{{ _available.response.vaults[0] }}"

- name: "Turn on scheduled rotation for the vault"
  thalesgroup.ciphertrust.cckm_azure_vault:
    localNode: "{{ cm_connection }}"
    op_type: enable_rotation_job
    vault_id: "{{ _vault.response.id }}"
    job_config_id: "{{ _scheduler.response.id }}"

- name: "Remove the vault from CCKM, leaving Azure untouched"
  thalesgroup.ciphertrust.cckm_azure_vault:
    localNode: "{{ cm_connection }}"
    op_type: remove_vault
    vault_id: "{{ _vault.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(add) and C(patch) report accurately. The remaining operations have no state to
        compare against, so they report C(true) whenever they run.
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
argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "add",
            "patch",
            "enable_rotation_job",
            "disable_rotation_job",
            "remove_vault",
            "update_acls",
        ],
        required=True,
    ),
    vault_id=dict(type="str"),
    connection=dict(type="str"),
    subscription_id=dict(type="str"),
    vaults=dict(type="list", elements="dict"),
    vault_name=dict(type="str"),
    cloud_key_backup_limit=dict(type="int", no_log=False),
    job_config_id=dict(type="str"),
    override_key_scheduler=dict(type="bool"),
    acls=dict(type="list", elements="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "add", ["connection", "subscription_id", "vaults"]],
            ["op_type", "patch", ["vault_id", "connection"]],
            ["op_type", "enable_rotation_job", ["vault_id", "job_config_id"]],
            ["op_type", "disable_rotation_job", ["vault_id"]],
            ["op_type", "remove_vault", ["vault_id"]],
            ["op_type", "update_acls", ["vault_id", "acls"]],
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
        if op_type == "add":
            existing = None
            if params.get("vault_name"):
                existing = find_resource_by_filters(
                    client, cckm_azure.VAULTS,
                    filters={"name": params.get("vault_name"),
                             "subscription_id": params.get("subscription_id")},
                    confirm_fields=("name",),
                )
            changed, response, diff = create_if_absent(
                module, existing,
                create_fn=cckm_azure.vault_add,
                create_kwargs=dict(
                    node=node,
                    connection=params.get("connection"),
                    subscription_id=params.get("subscription_id"),
                    vaults=params.get("vaults"),
                    cloud_key_backup_limit=params.get("cloud_key_backup_limit"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_azure.VAULTS,
                resource_id=params.get("vault_id"),
                ignore_fields=("vault_id",),
                patch_fn=cckm_azure.vault_patch,
                patch_kwargs=dict(
                    node=node,
                    vault_id=params.get("vault_id"),
                    connection=params.get("connection"),
                    cloud_key_backup_limit=params.get("cloud_key_backup_limit"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type in (
                "enable_rotation_job", "disable_rotation_job", "remove_vault"):
            check_mode_action(module)
            fields = None
            if op_type == "enable_rotation_job":
                fields = dict(
                    job_config_id=params.get("job_config_id"),
                    override_key_scheduler=params.get("override_key_scheduler"),
                )
            result["response"] = cckm_azure.vault_action(
                node=node,
                vault_id=params.get("vault_id"),
                action=op_type.replace("_", "-"),
                fields=fields,
            )
            result["changed"] = True
        elif op_type == "update_acls":
            check_mode_action(module)
            result["response"] = cckm_azure.vault_update_acls(
                node=node,
                vault_id=params.get("vault_id"),
                acls=params.get("acls"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
