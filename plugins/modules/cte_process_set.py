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
module: cte_process_set
short_description: Create and manage CTE process-sets
description:
    - Create and edit CTE Process set or add, edit, or remove a process to or from the process set
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch, add_process, patch_process, delete_process]
      required: true
      type: str
    id:
      description:
        - Identifier of the CTE ProcessSet to be patched or deleted
      type: str
    process_index:
      aliases: [processIndex]
      description:
        - Identifier of the CTE Process within ProcessSet to be patched or deleted
      type: int
    name:
      description:
        - Name of the process set
      type: str
    description:
      description:
        - Description of the process set
      type: str
    processes:
      description:
        - List of processes to be added to the process set
      type: list
      elements: dict
      suboptions:
        directory:
          description:
            - directory path of the process which shall be associated with the process-set
          type: str
        file:
          description:
            - file name of the process which shall be associated with the process-set
          type: str
        signature:
          description:
            - Signature-set ID or Name which shall be associated with the process-set
          type: str
    directory:
      description:
        - directory path of the process which shall be associated with the process-set
      type: str
    file:
      description:
        - file name of the process which shall be associated with the process-set
      type: str
    signature:
      description:
        - Signature-set ID or Name which shall be associated with the process-set
      type: str
"""

EXAMPLES = """
- name: "Create CTE ProcessSet"
  thalesgroup.ciphertrust.cte_process_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: TestProcessSet
    description: "via Ansible"
    processes:
      - signature: TestSignSet
        directory: "/home/testUser"
        file: "*"
      - signature: TestSignSet
        directory: "/home/test"
        file: "test.bin"
  register: process_set

- name: "Add process to ProcessSet"
  thalesgroup.ciphertrust.cte_process_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_process
    id: "processSetID"
    processes:
      - signature: TestSignSet
        directory: "/home/testAnother"
        file: "*"
"""

RETURN = r"""
changed:
    description: Whether any change was made to CipherTrust Manager state.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing resource when one was found during the GET-before-write
        idempotency check.
    returned: when a write was attempted or an existing resource matched
    type: dict
    contains:
        id:
            description: Unique identifier of the resource on CipherTrust Manager.
            type: str
            returned: when applicable
            sample: "4ae2649a705e479589ef65759d3287f6"
        name:
            description: Name of the resource.
            type: str
            returned: when applicable
        uri:
            description: Canonical resource URI.
            type: str
            returned: when applicable
        createdAt:
            description: RFC3339 timestamp of resource creation.
            type: str
            returned: when applicable
        updatedAt:
            description: RFC3339 timestamp of last modification.
            type: str
            returned: when applicable
diff:
    description: Present only in C(--diff) mode when a change occurred.
    returned: when diff mode is enabled and the module made a change
    type: dict
    contains:
        before:
            description: Prior state of the resource (empty for create operations).
            type: dict
        after:
            description: Target state after the change.
            type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_create,
    idempotent_patch,
    check_mode_action,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import (
    createProcessSet,
    updateProcessSet,
    addProcessToSet,
    updateProcessInSetByIndex,
    deleteProcessInSetByIndex,
)

_process = dict(
    directory=dict(type="str"),
    file=dict(type="str"),
    signature=dict(type="str"),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "add_process",
            "patch_process",
            "delete_process",
        ],
        required=True,
    ),
    id=dict(type="str"),
    processIndex=dict(type="int"),
    name=dict(type="str"),
    description=dict(type="str"),
    processes=dict(type="list", elements="dict", options=_process),
    directory=dict(type="str"),
    file=dict(type="str"),
    signature=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name"]],
            ["op_type", "patch", ["id"]],
            ["op_type", "add_process", ["id"]],
            ["op_type", "patch_process", ["id", "processIndex"]],
            ["op_type", "delete_process", ["id", "processIndex"]],
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

    client = CipherTrustClient(module.params.get("localNode"))

    with ciphertrust_operation(module):
        if module.params.get("op_type") == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint="transparent-encryption/processsets",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createProcessSet,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    description=module.params.get("description"),
                    processes=module.params.get("processes"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="transparent-encryption/processsets",
                resource_id=module.params.get("id"),
                ignore_fields=("id",),
                patch_fn=updateProcessSet,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    id=module.params.get("id"),
                    description=module.params.get("description"),
                    processes=module.params.get("processes"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "add_process":
            check_mode_action(module)
            response = addProcessToSet(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                processes=module.params.get("processes"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "patch_process":
            check_mode_action(module)
            response = updateProcessInSetByIndex(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                processIndex=str(module.params.get("processIndex")),
                directory=module.params.get("directory"),
                file=module.params.get("file"),
                signature=module.params.get("signature"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "delete_process":
            check_mode_action(module)
            response = deleteProcessInSetByIndex(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                processIndex=str(module.params.get("processIndex")),
            )
            result["response"] = response
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
