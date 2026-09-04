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
module: cckm_oci_vault
short_description: Add, create and manage OCI vaults in CCKM
description:
    - Adds an existing OCI Vault to CCKM, creates an external vault, updates one, blocks
      or unblocks it, replaces its access control list, or removes CCKM's record of it.
    - An added vault already exists in OCI -- discover the candidates with
      M(thalesgroup.ciphertrust.cckm_oci_vault_info) using I(op_type=available).
    - An external vault is different -- its key material stays in CipherTrust Manager
      and OCI reaches it over an endpoint, authenticated by an issuer created with
      M(thalesgroup.ciphertrust.cckm_oci_issuer).
    - Blocking a vault stops CCKM serving OCI's requests for its keys without deleting
      anything.
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
        - C(add) registers existing OCI vaults with CCKM.
        - C(create_external) creates a vault backed by CipherTrust Manager.
        - C(patch) updates a vault CCKM already manages.
        - C(block) and C(unblock) stop and resume serving the vault's keys.
        - C(update_acls) replaces the vault's access control list.
        - C(delete) removes CCKM's record of the vault.
      choices:
        - add
        - create_external
        - patch
        - block
        - unblock
        - update_acls
        - delete
      required: true
      type: str
    vault_id:
      description:
        - Identifier of the vault in CCKM.
        - Required for every operation except C(add) and C(create_external).
      type: str
    vault_ids:
      description:
        - OCIDs of the vaults to add.
        - Sent to CCKM as C(vault_id), which the API defines as a list.
        - Required for C(add).
      type: list
      elements: str
    connection:
      description:
        - Name or id of the OCI connection that reaches the vault.
        - Required for C(add).
      type: str
    region:
      description:
        - OCI region the vaults are in.
        - Required for C(add).
      type: str
    bucket_name:
      description:
        - Object Storage bucket the vault's backups are written to.
      type: str
    bucket_namespace:
      description:
        - Namespace of that bucket.
      type: str
    vault_name:
      description:
        - Name for an external vault.
        - Required for C(create_external).
      type: str
    tenancy:
      description:
        - Tenancy the external vault belongs to.
      type: str
    endpoint_url_hostname:
      description:
        - Hostname OCI reaches the external vault on.
        - Required for C(create_external).
      type: str
    endpoint_url_port:
      description:
        - Port OCI reaches the external vault on.
      type: int
    client_application_id:
      description:
        - OCI client application that authenticates to the external vault.
        - Required for C(create_external).
      type: str
    issuer_id:
      description:
        - Issuer that validates OCI's tokens, from
          M(thalesgroup.ciphertrust.cckm_oci_issuer).
        - Required for C(create_external).
      type: str
    policy:
      description:
        - Policy applied to the external vault.
      type: str
    source_key_tier:
      description:
        - Where the external vault's key material is held.
      type: str
    partition_id:
      description:
        - Luna partition holding the material, when I(source_key_tier) names one.
      type: str
    enable_success_audit_event:
      description:
        - Record an audit event for successful operations as well as failures.
      type: bool
    acls:
      description:
        - Access control entries to apply.
        - Required for C(update_acls).
      type: list
      elements: dict
"""

EXAMPLES = """
- name: "Add existing OCI vaults to CCKM"
  thalesgroup.ciphertrust.cckm_oci_vault:
    localNode: "{{ cm_connection }}"
    op_type: add
    connection: oci-production
    region: us-ashburn-1
    vault_ids:
      - "ocid1.vault.oc1.iad.aaaa"
    bucket_name: cckm-backups
    bucket_namespace: mynamespace

- name: "Create an external vault backed by CipherTrust Manager"
  thalesgroup.ciphertrust.cckm_oci_vault:
    localNode: "{{ cm_connection }}"
    op_type: create_external
    vault_name: hyok-vault
    endpoint_url_hostname: cm.example.com
    client_application_id: "ocid1.clientapp.oc1..aaaa"
    issuer_id: "{{ _issuer.response.id }}"

- name: "Stop serving the vault's keys without deleting anything"
  thalesgroup.ciphertrust.cckm_oci_vault:
    localNode: "{{ cm_connection }}"
    op_type: block
    vault_id: "{{ _vault.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(create_external) and C(patch) report accurately. The remaining operations have
        no state to compare against, so they report C(true) whenever they run.
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
            "add",
            "create_external",
            "patch",
            "block",
            "unblock",
            "update_acls",
            "delete",
        ],
        required=True,
    ),
    vault_id=dict(type="str"),
    vault_ids=dict(type="list", elements="str"),
    connection=dict(type="str"),
    region=dict(type="str"),
    bucket_name=dict(type="str"),
    bucket_namespace=dict(type="str"),
    vault_name=dict(type="str"),
    tenancy=dict(type="str"),
    endpoint_url_hostname=dict(type="str"),
    endpoint_url_port=dict(type="int"),
    client_application_id=dict(type="str"),
    issuer_id=dict(type="str"),
    policy=dict(type="str"),
    source_key_tier=dict(type="str", no_log=False),
    partition_id=dict(type="str"),
    enable_success_audit_event=dict(type="bool"),
    acls=dict(type="list", elements="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "add", ["connection", "region", "vault_ids"]],
            ["op_type", "create_external", ["vault_name", "endpoint_url_hostname", "client_application_id", "issuer_id"]],
            ["op_type", "patch", ["vault_id"]],
            ["op_type", "block", ["vault_id"]],
            ["op_type", "unblock", ["vault_id"]],
            ["op_type", "update_acls", ["vault_id", "acls"]],
            ["op_type", "delete", ["vault_id"]],
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
            check_mode_action(module)
            result["response"] = cckm_oci.vault_add(
                node=node,
                connection=params.get("connection"),
                region=params.get("region"),
                vault_id=params.get("vault_ids"),
                bucket_name=params.get("bucket_name"),
                bucket_namespace=params.get("bucket_namespace"),
            )
            result["changed"] = True
        elif op_type == "create_external":
            existing = None
            if params.get("vault_name"):
                existing = find_resource_by_filters(
                    client, cckm_oci.VAULTS,
                    filters={"vault_name": params.get("vault_name")},
                    confirm_fields=("vault_name",),
                )
            changed, response, diff = create_if_absent(
                module, existing,
                create_fn=cckm_oci.vault_create_external,
                create_kwargs=dict(
                    node=node,
                    vault_name=params.get("vault_name"),
                    endpoint_url_hostname=params.get("endpoint_url_hostname"),
                    client_application_id=params.get("client_application_id"),
                    issuer_id=params.get("issuer_id"),
                    connection=params.get("connection"),
                    tenancy=params.get("tenancy"),
                    endpoint_url_port=params.get("endpoint_url_port"),
                    policy=params.get("policy"),
                    source_key_tier=params.get("source_key_tier"),
                    partition_id=params.get("partition_id"),
                    enable_success_audit_event=params.get(
                        "enable_success_audit_event"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_oci.VAULTS,
                resource_id=params.get("vault_id"),
                ignore_fields=("vault_id",),
                patch_fn=cckm_oci.vault_patch,
                patch_kwargs=dict(
                    node=node,
                    vault_id=params.get("vault_id"),
                    connection=params.get("connection"),
                    bucket_name=params.get("bucket_name"),
                    bucket_namespace=params.get("bucket_namespace"),
                    vault_name=params.get("vault_name"),
                    issuer_id=params.get("issuer_id"),
                    endpoint_url_hostname=params.get("endpoint_url_hostname"),
                    endpoint_url_port=params.get("endpoint_url_port"),
                    policy=params.get("policy"),
                    enable_success_audit_event=params.get(
                        "enable_success_audit_event"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type in (
                "block", "unblock"):
            check_mode_action(module)
            result["response"] = cckm_oci.vault_action(
                node=node,
                vault_id=params.get("vault_id"),
                action=op_type,
            )
            result["changed"] = True
        elif op_type == "update_acls":
            check_mode_action(module)
            result["response"] = cckm_oci.vault_update_acls(
                node=node,
                vault_id=params.get("vault_id"),
                acls=params.get("acls"),
            )
            result["changed"] = True
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_oci.vault_delete(
                node=node,
                vault_id=params.get("vault_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
