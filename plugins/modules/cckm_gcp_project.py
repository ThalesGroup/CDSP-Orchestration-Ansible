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
module: cckm_gcp_project
short_description: Manage Google Cloud projects in CCKM
description:
    - Adds a Google Cloud project to CCKM, updates one, removes one, or replaces its
      access control list.
    - Discover the projects a connection can reach with
      M(thalesgroup.ciphertrust.cckm_gcp_project_info) using I(op_type=available).
    - Removing a project removes it from CCKM only. Nothing in Google Cloud is deleted.
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
        - C(create) registers a Google Cloud project with CCKM.
        - C(patch) updates a project CCKM already manages.
        - C(delete) removes the project from CCKM.
        - C(update_acls) replaces the project's access control list.
      choices:
        - create
        - patch
        - delete
        - update_acls
      required: true
      type: str
    gcp_project_id:
      description:
        - Identifier of the project record in CCKM.
        - Required for every operation except C(create). Distinct from I(project_id),
          which is the Google Cloud project's own id.
      type: str
    project_id:
      description:
        - Google Cloud project id.
        - Required for C(create).
      type: str
    connection:
      description:
        - Name or id of the Google Cloud connection that reaches the project.
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
- name: "Add a Google Cloud project to CCKM"
  thalesgroup.ciphertrust.cckm_gcp_project:
    localNode: "{{ cm_connection }}"
    op_type: create
    project_id: my-gcp-project
    connection: gcp-production

- name: "Remove the project from CCKM, leaving Google Cloud untouched"
  thalesgroup.ciphertrust.cckm_gcp_project:
    localNode: "{{ cm_connection }}"
    op_type: delete
    gcp_project_id: "{{ _project.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(create) and C(patch) report accurately. C(delete) and C(update_acls) have no
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
            "create",
            "patch",
            "delete",
            "update_acls",
        ],
        required=True,
    ),
    gcp_project_id=dict(type="str"),
    project_id=dict(type="str"),
    connection=dict(type="str"),
    enable_success_audit_event=dict(type="bool"),
    acls=dict(type="list", elements="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["project_id"]],
            ["op_type", "patch", ["gcp_project_id"]],
            ["op_type", "delete", ["gcp_project_id"]],
            ["op_type", "update_acls", ["gcp_project_id", "acls"]],
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
        if op_type == "create":
            existing = find_resource_by_filters(
                client, cckm_gcp.PROJECTS,
                filters={"name": params.get("project_id")},
                confirm_fields=("name",),
            )
            changed, response, diff = create_if_absent(
                module, existing,
                create_fn=cckm_gcp.project_create,
                create_kwargs=dict(
                    node=node,
                    project_id=params.get("project_id"),
                    connection=params.get("connection"),
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
                endpoint=cckm_gcp.PROJECTS,
                resource_id=params.get("gcp_project_id"),
                ignore_fields=("gcp_project_id",),
                patch_fn=cckm_gcp.project_patch,
                patch_kwargs=dict(
                    node=node,
                    gcp_project_id=params.get("gcp_project_id"),
                    enable_success_audit_event=params.get(
                        "enable_success_audit_event"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_gcp.project_delete(
                node=node,
                gcp_project_id=params.get("gcp_project_id"),
            )
            result["changed"] = True
        elif op_type == "update_acls":
            check_mode_action(module)
            result["response"] = cckm_gcp.project_update_acls(
                node=node,
                gcp_project_id=params.get("gcp_project_id"),
                acls=params.get("acls"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
