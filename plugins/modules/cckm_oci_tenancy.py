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
module: cckm_oci_tenancy
short_description: Add and remove OCI tenancies in CCKM
description:
    - Registers an Oracle Cloud Infrastructure tenancy with CCKM, or removes CCKM's
      record of one.
    - A tenancy is OCI's root container; compartments, vaults and keys all sit inside
      one, so this is the first CCKM OCI call a playbook makes.
    - Removing a tenancy removes it from CCKM only. Nothing in OCI is deleted.
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
        - C(add) registers a tenancy with CCKM.
        - C(delete) removes CCKM's record of it.
      choices:
        - add
        - delete
      required: true
      type: str
    tenancy_id:
      description:
        - Identifier of the tenancy record in CCKM.
        - Required for C(delete).
      type: str
    tenancy:
      description:
        - Name of the OCI tenancy.
      type: str
    tenancy_ocid:
      description:
        - OCID of the tenancy.
      type: str
    connection:
      description:
        - Name or id of the OCI connection that reaches the tenancy.
      type: str
"""

EXAMPLES = """
- name: "Register an OCI tenancy with CCKM"
  thalesgroup.ciphertrust.cckm_oci_tenancy:
    localNode: "{{ cm_connection }}"
    op_type: add
    tenancy: production-tenancy
    tenancy_ocid: "ocid1.tenancy.oc1..aaaa"
    connection: oci-production

- name: "Remove CCKM's record of the tenancy"
  thalesgroup.ciphertrust.cckm_oci_tenancy:
    localNode: "{{ cm_connection }}"
    op_type: delete
    tenancy_id: "{{ _tenancy.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(add) reports accurately when I(tenancy) is given, because the module can look
        the tenancy up first. C(delete) has no state to compare against, so it reports
        C(true) whenever it runs.
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
)
argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "add",
            "delete",
        ],
        required=True,
    ),
    tenancy_id=dict(type="str"),
    tenancy=dict(type="str"),
    tenancy_ocid=dict(type="str"),
    connection=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "delete", ["tenancy_id"]],
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
            if params.get("tenancy"):
                existing = find_resource_by_filters(
                    client, cckm_oci.TENANCY,
                    filters={"tenancy": params.get("tenancy")},
                    confirm_fields=("tenancy",),
                )
            changed, response, diff = create_if_absent(
                module, existing,
                create_fn=cckm_oci.tenancy_add,
                create_kwargs=dict(
                    node=node,
                    tenancy_ocid=params.get("tenancy_ocid"),
                    tenancy=params.get("tenancy"),
                    connection=params.get("connection"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_oci.tenancy_delete(
                node=node,
                tenancy_id=params.get("tenancy_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
