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
module: cm_resource_delete
short_description: Delete CipherTrust Manager resource using ID
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically delete resource APIs.
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
options:
    key:
        description:
            - This is a string type of option that can have either the name of the ID of the resource to be deleted
        type: str
    resource_type:
        description:
            - This is a string type of option that can hold the resource type.
        required: true
        choices:
          - keys
          - protection-policies
          - access-policies
          - user-sets
          - interfaces
          - character-sets
          - users
          - dpg-policies
          - client-profiles
          - masking-formats
          - resourceset
          - signatureset
          - userset
          - processset
          - cte-policy
          - cte-client-group
          - csigroup
          - cte-client
          - azure-key-vault
          - azure-secret
          - azure-certificate
          - azure-key
          - cluster
        type: str
"""

EXAMPLES = """
# Delete Resource at CipherTrust Manager
- name: "Delete key on Ciphertrust Manager"
  thalesgroup.ciphertrust.cm_resource_delete:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    key: "resource_id"
    resource_type: "keys"
"""

RETURN = r"""
changed:
    description: Always C(true) when the action is performed; C(false) in check mode.
    returned: always
    type: bool
    sample: true
response:
    description: Raw response payload from the CipherTrust Manager API.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    DELETEByNameOrId,
    DeleteWithoutData,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)

_arr_resource_type_choices = [
    "keys",
    "protection-policies",
    "access-policies",
    "user-sets",
    "interfaces",
    "character-sets",
    "users",
    "dpg-policies",
    "client-profiles",
    "masking-formats",
    "resourceset",
    "signatureset",
    "userset",
    "processset",
    "cte-policy",
    "cte-client-group",
    "csigroup",
    "cte-client",
    "azure-key-vault",
    "azure-secret",
    "azure-certificate",
    "azure-key",
    "cluster",
]

argument_spec = dict(
    key=dict(type="str", no_log=False),
    resource_type=dict(type="str", choices=_arr_resource_type_choices, required=True),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=[],
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    endpoint = ""
    resource_type = module.params.get("resource_type")
    # Create the API end point based on the resource_type
    if resource_type == "keys":
        endpoint = "vault/keys2"
    elif resource_type == "interfaces":
        endpoint = "configs/interfaces"
    elif resource_type == "users":
        endpoint = "usermgmt/users"
    elif resource_type == "client-profiles":
        endpoint = "data-protection/client-profiles"
    elif resource_type == "dpg-policies":
        endpoint = "data-protection/dpg-policies"
    elif resource_type == "access-policies":
        endpoint = "data-protection/access-policies"
    elif resource_type == "user-sets":
        endpoint = "data-protection/user-sets"
    elif resource_type == "protection-policies":
        endpoint = "data-protection/protection-policies"
    elif resource_type == "character-sets":
        endpoint = "data-protection/character-sets"
    elif resource_type == "masking-formats":
        endpoint = "data-protection/masking-formats"
    elif resource_type == "resourceset":
        endpoint = "transparent-encryption/resourcesets"
    elif resource_type == "signatureset":
        endpoint = "transparent-encryption/signaturesets"
    elif resource_type == "userset":
        endpoint = "transparent-encryption/usersets"
    elif resource_type == "processset":
        endpoint = "transparent-encryption/processsets"
    elif resource_type == "cte-policy":
        endpoint = "transparent-encryption/policies"
    elif resource_type == "cte-client-group":
        endpoint = "transparent-encryption/clientgroups"
    elif resource_type == "csigroup":
        endpoint = "transparent-encryption/csigroups"
    elif resource_type == "azure-key-vault":
        endpoint = "cckm/azure/vaults"
    elif resource_type == "azure-secret":
        endpoint = "cckm/azure/secrets"
    elif resource_type == "azure-certificate":
        endpoint = "cckm/azure/certificates"
    elif resource_type == "azure-key":
        endpoint = "cckm/azure/keys"
    elif resource_type == "cluster":
        endpoint = "cluster"
    else:
        module.fail_json(msg="resource_type not supported yet")

    with ciphertrust_operation(module):
        check_mode_action(module)
        if resource_type == "cluster":
            response = DELETEByNameOrId(
                key=module.params.get("key"),
                cm_node=module.params.get("localNode"),
                cm_api_endpoint=endpoint,
            )
        else:
            response = DeleteWithoutData(
                cm_node=module.params.get("localNode"),
                cm_api_endpoint=endpoint,
            )
        result["response"] = response
        result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
