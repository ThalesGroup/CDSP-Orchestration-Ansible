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
module: cckm_oci_key
short_description: Manage OCI Vault keys and their versions through CCKM
description:
    - Creates a key in an OCI Vault, uploads one from material CipherTrust Manager
      holds, creates one in an external vault, updates a key, manages its versions, and
      drives OCI's deferred deletion.
    - OCI deletion is scheduled rather than immediate -- C(schedule_deletion) sets a
      date some number of days ahead and C(cancel_deletion) calls it off until then. The
      same applies to a single version.
    - C(block) and C(unblock) stop and resume CCKM serving the key without deleting
      anything, which is the lever for an external vault.
    - Read keys and versions with M(thalesgroup.ciphertrust.cckm_oci_key_info).
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
        - C(create) creates a key; C(upload) imports material CipherTrust Manager holds;
          C(create_external) creates one in an external vault.
        - C(patch) updates names, tags and policy; C(delete) removes CCKM's record.
        - C(enable), C(disable), C(refresh), C(restore), C(block), C(unblock),
          C(change_compartment) and C(delete_backup) act on the key.
        - C(schedule_deletion) and C(cancel_deletion) drive OCI's deferred deletion;
          C(enable_auto_rotation) and C(disable_auto_rotation) control scheduled
          rotation.
        - C(create_version) adds a version; C(schedule_version_deletion) and
          C(cancel_version_deletion) act on one.
      choices:
        - create
        - upload
        - create_external
        - patch
        - delete
        - block
        - unblock
        - enable
        - disable
        - refresh
        - restore
        - schedule_deletion
        - cancel_deletion
        - change_compartment
        - delete_backup
        - enable_auto_rotation
        - disable_auto_rotation
        - create_version
        - schedule_version_deletion
        - cancel_version_deletion
      required: true
      type: str
    key_id:
      description:
        - Identifier of the key in CCKM.
        - Required for every operation except the three creates.
      type: str
    vault:
      description:
        - Identifier of the vault to create the key in.
        - Required for the three creates.
      type: str
    name:
      description:
        - Name for the key in OCI.
        - Required for the three creates.
      type: str
    algorithm:
      description:
        - Key algorithm.
        - Required for C(create).
      choices: [AES, RSA, ECDSA]
      type: str
    length:
      description:
        - Key length in bytes.
        - Required for C(create).
      type: int
    curve_id:
      description:
        - Elliptic curve, for I(algorithm=ECDSA).
      choices: [NIST_P256, NIST_P384, NIST_P521]
      type: str
    protection_mode:
      description:
        - Where OCI holds the key material.
        - Required for C(create) and C(upload).
      choices: [HSM, SOFTWARE]
      type: str
    compartment_id:
      description:
        - Compartment the key belongs to.
        - Required for C(create), C(upload) and C(change_compartment).
      type: str
    source_key_identifier:
      description:
        - Identifier of the CipherTrust Manager key to upload or import.
      type: str
    source_key_tier:
      description:
        - Where the uploaded key material comes from.
      type: str
    defined_tags:
      description:
        - OCI defined tags to set on the key.
      type: dict
    freeform_tags:
      description:
        - OCI free-form tags to set on the key.
      type: dict
    display_name:
      description:
        - Display name to set. Used by C(patch).
      type: str
    policy:
      description:
        - Policy applied to the key.
      type: str
    days:
      description:
        - How many days ahead the deletion is scheduled.
        - Required for C(schedule_deletion) and C(schedule_version_deletion).
      type: int
    version_id:
      description:
        - Identifier of the key version to act on.
      type: str
    is_native:
      description:
        - Create the version in OCI rather than importing material.
        - Required for C(create_version).
      type: bool
    job_config_id:
      description:
        - Scheduler configuration for the rotation job.
      type: str
    auto_rotate_key_source:
      description:
        - Where rotated key material comes from.
      type: str
    auto_rotate_partition_id:
      description:
        - Luna partition to rotate material from.
      type: str
    auto_rotate_domain_id:
      description:
        - DSM domain to rotate material from.
      type: str
    auto_rotate_external_cm_domain_id:
      description:
        - Domain on an external CipherTrust Manager to rotate material from.
      type: str
"""

EXAMPLES = """
- name: "Create an AES key in an OCI vault"
  thalesgroup.ciphertrust.cckm_oci_key:
    localNode: "{{ cm_connection }}"
    op_type: create
    vault: "{{ _vault.response.id }}"
    name: payments
    algorithm: AES
    length: 32
    protection_mode: HSM
    compartment_id: "ocid1.compartment.oc1..aaaa"

- name: "Schedule the key for deletion in 30 days"
  thalesgroup.ciphertrust.cckm_oci_key:
    localNode: "{{ cm_connection }}"
    op_type: schedule_deletion
    key_id: "{{ _key.response.id }}"
    days: 30

- name: "Call that deletion off"
  thalesgroup.ciphertrust.cckm_oci_key:
    localNode: "{{ cm_connection }}"
    op_type: cancel_deletion
    key_id: "{{ _key.response.id }}"

- name: "Stop serving an external vault key without deleting it"
  thalesgroup.ciphertrust.cckm_oci_key:
    localNode: "{{ cm_connection }}"
    op_type: block
    key_id: "{{ _key.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(create), C(upload), C(create_external) and C(patch) report accurately. The
        lifecycle and version operations have no state to compare against, so they
        report C(true) whenever they run.
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
    cckm_oci,
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
            "create",
            "upload",
            "create_external",
            "patch",
            "delete",
            "block",
            "unblock",
            "enable",
            "disable",
            "refresh",
            "restore",
            "schedule_deletion",
            "cancel_deletion",
            "change_compartment",
            "delete_backup",
            "enable_auto_rotation",
            "disable_auto_rotation",
            "create_version",
            "schedule_version_deletion",
            "cancel_version_deletion",
        ],
        required=True,
    ),
    key_id=dict(type="str", no_log=False),
    vault=dict(type="str"),
    name=dict(type="str"),
    algorithm=dict(type="str", choices=["AES", "RSA", "ECDSA"]),
    length=dict(type="int"),
    curve_id=dict(type="str", choices=["NIST_P256", "NIST_P384", "NIST_P521"]),
    protection_mode=dict(type="str", choices=["HSM", "SOFTWARE"]),
    compartment_id=dict(type="str"),
    source_key_identifier=dict(type="str", no_log=False),
    source_key_tier=dict(type="str", no_log=False),
    defined_tags=dict(type="dict"),
    freeform_tags=dict(type="dict"),
    display_name=dict(type="str"),
    policy=dict(type="str"),
    days=dict(type="int"),
    version_id=dict(type="str"),
    is_native=dict(type="bool"),
    job_config_id=dict(type="str"),
    auto_rotate_key_source=dict(type="str", no_log=False),
    auto_rotate_partition_id=dict(type="str"),
    auto_rotate_domain_id=dict(type="str"),
    auto_rotate_external_cm_domain_id=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["vault", "name", "algorithm", "length", "protection_mode", "compartment_id"]],
            ["op_type", "upload", ["vault", "name", "protection_mode", "compartment_id", "source_key_identifier", "source_key_tier"]],
            ["op_type", "create_external", ["vault", "name", "source_key_identifier", "source_key_tier"]],
            ["op_type", "patch", ["key_id"]],
            ["op_type", "delete", ["key_id"]],
            ["op_type", "block", ["key_id"]],
            ["op_type", "unblock", ["key_id"]],
            ["op_type", "enable", ["key_id"]],
            ["op_type", "disable", ["key_id"]],
            ["op_type", "refresh", ["key_id"]],
            ["op_type", "restore", ["key_id"]],
            ["op_type", "schedule_deletion", ["key_id", "days"]],
            ["op_type", "cancel_deletion", ["key_id"]],
            ["op_type", "change_compartment", ["key_id", "compartment_id"]],
            ["op_type", "delete_backup", ["key_id"]],
            ["op_type", "enable_auto_rotation", ["key_id", "job_config_id", "auto_rotate_key_source"]],
            ["op_type", "disable_auto_rotation", ["key_id"]],
            ["op_type", "create_version", ["key_id", "is_native"]],
            ["op_type", "schedule_version_deletion", ["key_id", "version_id", "days"]],
            ["op_type", "cancel_version_deletion", ["key_id", "version_id"]],
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
                "create", "upload", "create_external"):
            # An OCI key name is unique within its vault, so both have to
            # match. Only vault is confirmed against the response, for the
            # reason find_resource_by_filters documents.
            existing = None
            if params.get("name"):
                existing = find_resource_by_filters(
                    client, cckm_oci.KEYS,
                    filters={"key_name": params.get("name"),
                             "cckm_vault_id": params.get("vault")},
                    confirm_fields=("key_name",),
                )
            if op_type == "create":
                create_fn = cckm_oci.key_create
                create_kwargs = dict(
                    node=node,
                    vault=params.get("vault"),
                    name=params.get("name"),
                    algorithm=params.get("algorithm"),
                    length=params.get("length"),
                    protection_mode=params.get("protection_mode"),
                    compartment_id=params.get("compartment_id"),
                    curve_id=params.get("curve_id"),
                    defined_tags=params.get("defined_tags"),
                    freeform_tags=params.get("freeform_tags"),
                )
            elif op_type == "upload":
                create_fn = cckm_oci.key_upload
                create_kwargs = dict(
                    node=node,
                    vault=params.get("vault"),
                    name=params.get("name"),
                    protection_mode=params.get("protection_mode"),
                    compartment_id=params.get("compartment_id"),
                    source_key_identifier=params.get("source_key_identifier"),
                    source_key_tier=params.get("source_key_tier"),
                    defined_tags=params.get("defined_tags"),
                    freeform_tags=params.get("freeform_tags"),
                )
            else:
                create_fn = cckm_oci.key_create_external
                create_kwargs = dict(
                    node=node,
                    vault=params.get("vault"),
                    name=params.get("name"),
                    source_key_identifier=params.get("source_key_identifier"),
                    source_key_tier=params.get("source_key_tier"),
                    policy=params.get("policy"),
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
                endpoint=cckm_oci.KEYS,
                resource_id=params.get("key_id"),
                ignore_fields=("key_id",),
                patch_fn=cckm_oci.key_patch,
                patch_kwargs=dict(
                    node=node,
                    key_id=params.get("key_id"),
                    display_name=params.get("display_name"),
                    defined_tags=params.get("defined_tags"),
                    freeform_tags=params.get("freeform_tags"),
                    name=params.get("name"),
                    policy=params.get("policy"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_oci.key_delete(
                node=node,
                key_id=params.get("key_id"),
            )
            result["changed"] = True
        elif op_type in (
                "block", "unblock", "enable", "disable", "refresh", "restore",
                "schedule_deletion", "cancel_deletion", "change_compartment",
                "delete_backup", "enable_auto_rotation",
                "disable_auto_rotation"):
            check_mode_action(module)
            fields = None
            if op_type == "schedule_deletion":
                fields = dict(days=params.get("days"))
            elif op_type == "change_compartment":
                fields = dict(compartment_id=params.get("compartment_id"))
            elif op_type == "enable_auto_rotation":
                fields = dict(
                    job_config_id=params.get("job_config_id"),
                    auto_rotate_key_source=params.get("auto_rotate_key_source"),
                    auto_rotate_partition_id=params.get("auto_rotate_partition_id"),
                    auto_rotate_domain_id=params.get("auto_rotate_domain_id"),
                    auto_rotate_external_cm_domain_id=params.get(
                        "auto_rotate_external_cm_domain_id"),
                )
            result["response"] = cckm_oci.key_action(
                node=node,
                key_id=params.get("key_id"),
                action=op_type.replace("_", "-"),
                fields=fields,
            )
            result["changed"] = True
        elif op_type == "create_version":
            check_mode_action(module)
            result["response"] = cckm_oci.key_version_create(
                node=node,
                key_id=params.get("key_id"),
                is_native=params.get("is_native"),
                source_key_tier=params.get("source_key_tier"),
                source_key_identifier=params.get("source_key_identifier"),
            )
            result["changed"] = True
        elif op_type in (
                "schedule_version_deletion", "cancel_version_deletion"):
            check_mode_action(module)
            action_name = ("schedule-deletion"
                           if op_type == "schedule_version_deletion"
                           else "cancel-deletion")
            result["response"] = cckm_oci.key_version_action(
                node=node,
                key_id=params.get("key_id"),
                version_id=params.get("version_id"),
                action=action_name,
                fields=(dict(days=params.get("days"))
                        if op_type == "schedule_version_deletion" else None),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
