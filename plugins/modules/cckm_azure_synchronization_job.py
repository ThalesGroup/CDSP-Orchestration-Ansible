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
module: cckm_azure_synchronization_job
short_description: Start and cancel CCKM Azure synchronisation jobs
description:
    - Starts a job that synchronises Azure keys, certificates or secrets into CCKM, or
      cancels a running one.
    - Each kind of vault object has its own synchronisation service, chosen with
      I(scope).
    - The job runs asynchronously. Poll it with
      M(thalesgroup.ciphertrust.cckm_azure_synchronization_job_info).
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
    scope:
      description:
        - Which synchronisation service to drive.
      choices: [keys, certificates, secrets]
      type: str
    job_id:
      description:
        - Identifier of the job.
        - Required for C(cancel).
      type: str
    key_vaults:
      description:
        - Vaults to synchronise. Ignored when I(synchronize_all=true).
      type: list
      elements: str
    synchronize_all:
      description:
        - Synchronise every vault CCKM manages.
      type: bool
    take_cloud_key_backup:
      description:
        - Take a cloud key backup of each key as it is synchronised.
      type: bool
"""

EXAMPLES = """
- name: "Synchronise the keys in one vault"
  thalesgroup.ciphertrust.cckm_azure_synchronization_job:
    localNode: "{{ cm_connection }}"
    op_type: start
    scope: keys
    key_vaults:
      - production-vault
  register: _sync

- name: "Synchronise every vault's certificates"
  thalesgroup.ciphertrust.cckm_azure_synchronization_job:
    localNode: "{{ cm_connection }}"
    op_type: start
    scope: certificates
    synchronize_all: true
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
    cckm_azure,
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
    scope=dict(type="str", choices=["keys", "certificates", "secrets"]),
    job_id=dict(type="str"),
    key_vaults=dict(type="list", elements="str", no_log=False),
    synchronize_all=dict(type="bool"),
    take_cloud_key_backup=dict(type="bool"),
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
            result["response"] = cckm_azure.sync_start(
                node=node,
                scope=params.get("scope"),
                key_vaults=params.get("key_vaults"),
                synchronize_all=params.get("synchronize_all"),
                take_cloud_key_backup=params.get("take_cloud_key_backup"),
            )
            result["changed"] = True
        elif op_type == "cancel":
            check_mode_action(module)
            result["response"] = cckm_azure.sync_cancel(
                node=node,
                scope=params.get("scope"),
                job_id=params.get("job_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
