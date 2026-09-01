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
module: cte_csi_storage_group
short_description: Manage CTE CSI Storage Group
description:
    - Define and manage CipherTrust Transparent Encryption (CTE) Container Storage Interface (CSI) and also add guard policies and clients to the same.
    - This will allow administrator to apply data protection/reveal based on the client or the guard points.
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch, add_client, remove_client, add_guard_point, patch_guard_point, remove_guard_point]
      required: true
      type: str
    id:
      description:
        - Identifier of the CTE CSI Storage Group to be patched
      type: str
    client_id:
      description:
        - Identifier of the client added added to the CSI Group
      type: str
    gp_id:
      description:
        - Identifier of the guard point added to the CSI Group
      type: str
    k8s_namespace:
      description:
        - Name of the K8s namespace
      type: str
    k8s_storage_class:
      description:
        - Name of the K8s StorageClass
      type: str
    name:
      description:
        - Name to uniquely identify the CSI storage group. This name will be visible on the CipherTrust Manager
      type: str
    client_profile:
      description:
        - Optional Client Profile for the storage group. If not provided, the default profile will be used
      type: str
    description:
      description:
        - Optional description for the storage group
      type: str
    client_list:
      description: List of identifiers of clients to be associated with the client group. This identifier can be the name or UUID.
      type: list
      elements: str
    policy_list:
      description: List of CSI policy identifiers to be associated with the storage group. This identifier can be the name or UUID.
      type: list
      elements: str
    guard_enabled:
      description: Enable or disable the GuardPolicy. Set to true to enable, false to disable.
      type: bool
"""

EXAMPLES = """
- name: "Create CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: AnsibleCSI_SG_1
    k8s_namespace: AnsibleK8s_NS_1
    k8s_storage_class: AnsibleK8s_SC_1
    description: "Test CSIStorageGroup"
    client_profile: DefaultClientProfile
  register: csi_sg

- name: "Edit CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    id: "sg_id"
    description: "Test CSIStorageGroup Updated"
    client_profile: DefaultClientProfile

- name: "Add clients to the CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_client
    id: "sg_id"
    client_list:
      - Client1
      - Client2

- name: "Add guardpolicy to the CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_guard_point
    id: "sg_id"
    policy_list:
      - CSI_Policy_1
      - CSI_Policy_2
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
    createCSIStorageGroup,
    updateCSIStorageGroup,
    csiGroupAddClient,
    csiGroupAddGuardPoint,
    csiGroupRemoveClient,
    csiGroupUpdateGuardPoint,
    csiGroupRemoveGuardPoint,
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "add_client",
            "remove_client",
            "add_guard_point",
            "patch_guard_point",
            "remove_guard_point",
        ],
        required=True,
    ),
    id=dict(type="str"),
    client_id=dict(type="str"),
    gp_id=dict(type="str"),
    k8s_namespace=dict(type="str"),
    k8s_storage_class=dict(type="str"),
    name=dict(type="str"),
    client_profile=dict(type="str"),
    description=dict(type="str"),
    client_list=dict(type="list", elements="str"),
    policy_list=dict(type="list", elements="str"),
    guard_enabled=dict(type="bool"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["k8s_namespace", "k8s_storage_class", "name"]],
            ["op_type", "patch", ["id"]],
            ["op_type", "add_client", ["id", "client_list"]],
            ["op_type", "remove_client", ["id", "client_id"]],
            ["op_type", "add_guard_point", ["id", "policy_list"]],
            ["op_type", "patch_guard_point", ["id", "gp_id"]],
            ["op_type", "remove_guard_point", ["id", "gp_id"]],
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
                endpoint="transparent-encryption/csigroups",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createCSIStorageGroup,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    description=module.params.get("description"),
                    k8s_namespace=module.params.get("k8s_namespace"),
                    k8s_storage_class=module.params.get("k8s_storage_class"),
                    client_profile=module.params.get("client_profile"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="transparent-encryption/csigroups",
                resource_id=module.params.get("id"),
                ignore_fields=("id",),
                patch_fn=updateCSIStorageGroup,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    id=module.params.get("id"),
                    description=module.params.get("description"),
                    client_profile=module.params.get("client_profile"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "add_client":
            check_mode_action(module)
            response = csiGroupAddClient(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_list=module.params.get("client_list"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "remove_client":
            check_mode_action(module)
            response = csiGroupRemoveClient(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_id=module.params.get("client_id"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "add_guard_point":
            check_mode_action(module)
            response = csiGroupAddGuardPoint(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                policy_list=module.params.get("policy_list"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "patch_guard_point":
            check_mode_action(module)
            response = csiGroupUpdateGuardPoint(
                node=module.params.get("localNode"),
                gp_id=module.params.get("gp_id"),
                guard_enabled=module.params.get("guard_enabled"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "remove_guard_point":
            check_mode_action(module)
            response = csiGroupRemoveGuardPoint(
                node=module.params.get("localNode"),
                gp_id=module.params.get("gp_id"),
            )
            result["response"] = response
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
