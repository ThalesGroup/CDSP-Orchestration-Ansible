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
module: cckm_oci_synchronization_job
short_description: Start and cancel CCKM OCI synchronisation jobs
description:
    - Starts a job that synchronises OCI Vault keys into CCKM, or cancels a running one.
    - The job runs asynchronously. Poll it with
      M(thalesgroup.ciphertrust.cckm_oci_synchronization_job_info).
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
        - C(start) begins a synchronisation; C(cancel) stops a running one.
      choices:
        - start
        - cancel
      required: true
      type: str
    job_id:
      description:
        - Identifier of the job.
        - Required for C(cancel).
      type: str
    vaults:
      description:
        - Vaults to synchronise. Ignored when I(synchronize_all=true).
      type: list
      elements: str
    synchronize_all:
      description:
        - Synchronise every vault CCKM manages.
      type: bool
"""

EXAMPLES = """
- name: "Synchronise one vault"
  thalesgroup.ciphertrust.cckm_oci_synchronization_job:
    localNode: "{{ cm_connection }}"
    op_type: start
    vaults:
      - "{{ _vault.response.id }}"
  register: _sync
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - Starting a synchronisation always reports C(true) -- each run creates a new job
        rather than converging on a state.
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
            "start",
            "cancel",
        ],
        required=True,
    ),
    job_id=dict(type="str"),
    vaults=dict(type="list", elements="str"),
    synchronize_all=dict(type="bool"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "cancel", ["job_id"]],
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
        if op_type == "start":
            check_mode_action(module)
            result["response"] = cckm_oci.sync_start(
                node=node,
                vaults=params.get("vaults"),
                synchronize_all=params.get("synchronize_all"),
            )
            result["changed"] = True
        elif op_type == "cancel":
            check_mode_action(module)
            result["response"] = cckm_oci.sync_cancel(
                node=node,
                job_id=params.get("job_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
