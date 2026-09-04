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
module: cckm_gcp_key_ring
short_description: Add and manage Cloud KMS key rings in CCKM
description:
    - Adds an existing Cloud KMS key ring to CCKM, updates the connection one uses,
      replaces its access control list, or removes it from CCKM.
    - A key ring is not created here. It already exists in Google Cloud; discover the
      candidates with M(thalesgroup.ciphertrust.cckm_gcp_key_ring_info) using
      I(op_type=available), then add the ones you want.
    - Google Cloud does not allow a key ring to be deleted, so C(remove) only removes
      CCKM's record of it.
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
        - C(add) registers one or more key rings with CCKM.
        - C(patch) changes the connection a key ring is reached through.
        - C(update_acls) replaces the key ring's access control list.
        - C(remove) removes the key ring from CCKM.
      choices:
        - add
        - patch
        - update_acls
        - remove
      required: true
      type: str
    key_ring_id:
      description:
        - Identifier of the key ring in CCKM.
        - Required for every operation except C(add).
      type: str
    connection:
      description:
        - Name or id of the Google Cloud connection that reaches the key ring.
        - Required for C(add) and C(patch).
      type: str
    project_id:
      description:
        - Google Cloud project the key rings belong to.
        - Required for C(add).
      type: str
    key_rings:
      description:
        - Key rings to add, as returned by
          M(thalesgroup.ciphertrust.cckm_gcp_key_ring_info) with I(op_type=available).
        - Required for C(add).
      type: list
      elements: dict
    key_ring_name:
      description:
        - Name of the key ring being added.
        - Optional, and used only to make C(add) idempotent -- when given, the module
          first looks for a key ring of that name in the project and reports no change
          if it is already there.
      type: str
    acls:
      description:
        - Access control entries to apply.
        - Required for C(update_acls).
      type: list
      elements: dict
"""

EXAMPLES = """
- name: "Add a discovered key ring to CCKM"
  thalesgroup.ciphertrust.cckm_gcp_key_ring:
    localNode: "{{ cm_connection }}"
    op_type: add
    connection: gcp-production
    project_id: my-gcp-project
    key_ring_name: production-ring
    key_rings:
      - "{{ _available.response.key_rings[0] }}"

- name: "Remove CCKM's record of the key ring"
  thalesgroup.ciphertrust.cckm_gcp_key_ring:
    localNode: "{{ cm_connection }}"
    op_type: remove
    key_ring_id: "{{ _ring.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(add) and C(patch) report accurately. C(update_acls) and C(remove) have no
        state to compare against, so they report C(true) whenever they run.
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
argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "add",
            "patch",
            "update_acls",
            "remove",
        ],
        required=True,
    ),
    key_ring_id=dict(type="str", no_log=False),
    connection=dict(type="str"),
    project_id=dict(type="str"),
    key_rings=dict(type="list", elements="dict", no_log=False),
    key_ring_name=dict(type="str", no_log=False),
    acls=dict(type="list", elements="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "add", ["connection", "project_id", "key_rings"]],
            ["op_type", "patch", ["key_ring_id", "connection"]],
            ["op_type", "update_acls", ["key_ring_id", "acls"]],
            ["op_type", "remove", ["key_ring_id"]],
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
            if params.get("key_ring_name"):
                existing = find_resource_by_filters(
                    client, cckm_gcp.KEY_RINGS,
                    filters={"name": params.get("key_ring_name"),
                             "project_id": params.get("project_id")},
                    confirm_fields=("name",),
                )
            changed, response, diff = create_if_absent(
                module, existing,
                create_fn=cckm_gcp.key_ring_add,
                create_kwargs=dict(
                    node=node,
                    connection=params.get("connection"),
                    project_id=params.get("project_id"),
                    key_rings=params.get("key_rings"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_gcp.KEY_RINGS,
                resource_id=params.get("key_ring_id"),
                ignore_fields=("key_ring_id",),
                patch_fn=cckm_gcp.key_ring_patch,
                patch_kwargs=dict(
                    node=node,
                    key_ring_id=params.get("key_ring_id"),
                    connection=params.get("connection"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "update_acls":
            check_mode_action(module)
            result["response"] = cckm_gcp.key_ring_update_acls(
                node=node,
                key_ring_id=params.get("key_ring_id"),
                acls=params.get("acls"),
            )
            result["changed"] = True
        elif op_type == "remove":
            check_mode_action(module)
            result["response"] = cckm_gcp.key_ring_action(
                node=node,
                key_ring_id=params.get("key_ring_id"),
                action="remove-key-ring",
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
