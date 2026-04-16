#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: cte_resource_set
short_description: Create and manage CTE resource-sets
description:
    - Create and edit CTE resource set or add, edit, or remove a resource to or from the resource set
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch, add_resource, patch_resource, delete_resource]
      required: true
      type: str
    id:
      description:
        - Identifier of the CTE ResourceSet to be patched or deleted
      type: str
    resourceIndex:
      description:
        - Identifier of the CTE Resource within ResourceSet to be patched or deleted
      type: int
    name:
      description:
        - Name of the resource set
      type: str
    description:
      description:
        - Description of the resource set
      type: str
    classification_tags:
      description:
        - Classification set to be added to the resource set
      type: list
      elements: dict
      suboptions:
        attributes:
          description:
            - List of attributes to be added to the tag
          type: list
          elements: dict
          suboptions:
            data_type:
              description: Data type of the attribute
              type: str
            name:
              description: Name of the attribute
              type: str
            operator:
              description: Operator to be applied to the attribute
              type: str
              choices: ['eq', 'lt', 'ne', 'le', 'gt', 'ge']
            value:
              description: Value of the attribute
              type: str
        description:
          description:
            - Description of the classification tag
          type: str
        name:
          description:
            - Name of the tag in the classification set
          type: str
    resources:
      description:
        - List of resources to be added to the resource set
      type: list
      elements: dict
      suboptions:
        directory:
          description:
            - Directory of the resource to be added to the resource set
          type: str
        file:
          description:
            - File name of the resource to be added to the resource set
          type: str
        hdfs:
          description:
            - Whether the specified path is a HDFS path
          type: bool
        include_subfolders:
          description:
            - Whether to include subfolders to the resource
          type: bool
    type:
      description:
        - Type of the resource set i.e. Directory or Classification. Default value is Directory
      type: str
      choices: [Directory, Classification]
    directory:
      description:
        - directory path of the Resource which shall be associated with the resource-set
      type: str
    file:
      description:
        - file name of the Resource which shall be associated with the resource-set
      type: str
    hdfs:
      description:
        - Whether the specified path is a HDFS path
      type: bool
    include_subfolders:
      description:
        - Flag to include subfolders in the Resource
      type: bool
"""

EXAMPLES = """
- name: "Create CTE ResourceSet"
  thalesgroup.ciphertrust.cte_resource_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: "RS-Ans-001"
    description: "Created via Ansible"
    type: Directory
    resources:
      - directory: "/"
        file: "*"
        include_subfolders: true
        hdfs: false
  register: resource_set

- name: "Add resource to a ResourceSet"
  thalesgroup.ciphertrust.cte_resource_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: add_resource
    id: "resourceSetID"
    resources:
      - directory: "/tmp"
        file: "*"
        include_subfolders: true
        hdfs: false
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
    createResourceSet,
    updateResourceSet,
    addResourceToSet,
    updateResourceInSetByIndex,
    deleteResourceInSetByIndex,
)

_resource = dict(
    directory=dict(type="str"),
    file=dict(type="str"),
    hdfs=dict(type="bool"),
    include_subfolders=dict(type="bool"),
)

_classification_tag_attribute = dict(
    data_type=dict(type="str"),
    name=dict(type="str"),
    operator=dict(type="str", choices=["eq", "lt", "ne", "le", "gt", "ge"]),
    value=dict(type="str"),
)

_classification_tag = dict(
    attributes=dict(
        type="list", elements="dict", options=_classification_tag_attribute
    ),
    description=dict(type="str"),
    name=dict(type="str"),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "add_resource",
            "patch_resource",
            "delete_resource",
        ],
        required=True,
    ),
    id=dict(type="str"),
    resourceIndex=dict(type="int"),
    name=dict(type="str"),
    description=dict(type="str"),
    classification_tags=dict(type="list", elements="dict", options=_classification_tag),
    resources=dict(type="list", elements="dict", options=_resource),
    type=dict(type="str", choices=["Directory", "Classification"]),
    directory=dict(type="str"),
    file=dict(type="str"),
    hdfs=dict(type="bool"),
    include_subfolders=dict(type="bool"),
)


def validate_parameters(cte_resource_set_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name"]],
            ["op_type", "patch", ["id"]],
            ["op_type", "add_resource", ["id"]],
            ["op_type", "patch_resource", ["id", "resourceIndex"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        cte_resource_set_module=module,
    )

    result = dict(
        changed=False,
    )

    client = CipherTrustClient(module.params.get("localNode"))

    with ciphertrust_operation(module):
        if module.params.get("op_type") == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint="transparent-encryption/resourcesets",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createResourceSet,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    classification_tags=module.params.get("classification_tags"),
                    description=module.params.get("description"),
                    resources=module.params.get("resources"),
                    type=module.params.get("type"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="transparent-encryption/resourcesets",
                resource_id=module.params.get("id"),
                patch_fn=updateResourceSet,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    id=module.params.get("id"),
                    classification_tags=module.params.get("classification_tags"),
                    description=module.params.get("description"),
                    resources=module.params.get("resources"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "add_resource":
            check_mode_action(module)
            response = addResourceToSet(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                resources=module.params.get("resources"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "patch_resource":
            check_mode_action(module)
            response = updateResourceInSetByIndex(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                resourceIndex=str(module.params.get("resourceIndex")),
                directory=module.params.get("directory"),
                file=module.params.get("file"),
                hdfs=module.params.get("hdfs"),
                include_subfolders=module.params.get("include_subfolders"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "delete_resource":
            check_mode_action(module)
            response = deleteResourceInSetByIndex(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                resourceIndex=str(module.params.get("resourceIndex")),
            )
            result["response"] = response
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
