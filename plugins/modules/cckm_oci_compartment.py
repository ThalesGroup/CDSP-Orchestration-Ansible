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
module: cckm_oci_compartment
short_description: Add and remove OCI compartments in CCKM
description:
    - Adds one or more OCI compartments to CCKM, or removes CCKM's record of one.
    - Discover the compartments a connection can reach with
      M(thalesgroup.ciphertrust.cckm_oci_compartment_info) using I(op_type=available).
    - Removing a compartment removes it from CCKM only. Nothing in OCI is deleted.
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
        - C(add) registers compartments with CCKM.
        - C(delete) removes CCKM's record of one.
      choices:
        - add
        - delete
      required: true
      type: str
    compartment_id:
      description:
        - Identifier of the compartment record in CCKM.
        - Required for C(delete).
      type: str
    compartment_ids:
      description:
        - OCIDs of the compartments to add.
        - Sent to CCKM as C(compartment_id), which the API defines as a list.
        - Required for C(add).
      type: list
      elements: str
    connection:
      description:
        - Name or id of the OCI connection that reaches the compartments.
        - Required for C(add).
      type: str
"""

EXAMPLES = """
- name: "Add two compartments to CCKM"
  thalesgroup.ciphertrust.cckm_oci_compartment:
    localNode: "{{ cm_connection }}"
    op_type: add
    connection: oci-production
    compartment_ids:
      - "ocid1.compartment.oc1..aaaa"
      - "ocid1.compartment.oc1..bbbb"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - Both operations act rather than converge, so they report C(true) whenever they
        run.
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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
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
    compartment_id=dict(type="str"),
    compartment_ids=dict(type="list", elements="str"),
    connection=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "add", ["connection", "compartment_ids"]],
            ["op_type", "delete", ["compartment_id"]],
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

    with ciphertrust_operation(module):
        if op_type == "add":
            check_mode_action(module)
            result["response"] = cckm_oci.compartment_add(
                node=node,
                connection=params.get("connection"),
                compartment_id=params.get("compartment_ids"),
            )
            result["changed"] = True
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_oci.compartment_delete(
                node=node,
                compartment_id=params.get("compartment_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
