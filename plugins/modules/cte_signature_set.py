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
module: cte_signature_set
short_description: Create and manage CTE Signature Sets
description:
    - Create and edit CTE signature set or add, edit, or remove a signature to or from the signature set
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
options:
    localNode:
      description:
        - this holds the connection parameters required to communicate with an instance of CipherTrust Manager (CM)
        - holds IP/FQDN of the server, username, password, and port
      required: true
      type: dict
      suboptions:
        server_ip:
          description: CM Server IP or FQDN
          type: str
          required: true
        server_private_ip:
          description: internal or private IP of the CM Server, if different from the server_ip
          type: str
          required: true
        server_port:
          description: Port on which CM server is listening
          type: int
          required: true
        user:
          description: admin username of CM
          type: str
          required: true
        password:
          description: admin password of CM
          type: str
          required: true
        verify:
          description: if SSL verification is required
          type: bool
          required: true
        auth_domain_path:
          description: user's domain path
          type: str
          required: true
    op_type:
      description: Operation to be performed
      choices: [create, patch, add_signature, get_signature, delete_signature, sign_app, query_sign_app, cancel_sign_app]
      required: true
      type: str
    id:
      description:
        - Identifier of the CTE SignatureSet to be patched
      type: str
    signature_id:
      description:
        - Identifier of the Signature within the CTE SignatureSet to be patched
      type: str
    name:
      description:
        - Name of the signature set
      type: str
    description:
      description:
        - Description of the signature set
      type: str
    source_list:
      description:
        - Path of the directory or file to be signed. If a directory is specified, all files in the directory and its subdirectories are signed.
      type: list
      elements: str
    signatures:
      description:
        - Name of the signature set
      type: list
      elements: dict
      suboptions:
        file_name:
          description: file name
          type: str
        hash_value:
          description: hash value
          type: str
    client_id:
      description:
        - ID of the client where the signing request is to be sent
      type: str
    file_name:
        description: file name
        type: str
    hash_value:
        description: hash value
        type: str
"""

EXAMPLES = """
- name: "Create CTE Signature Set"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: create
    name: TestSignSet
    source_list:
      - "/usr/bin"
      - "/usr/sbin"
  register: signature_set

- name: "Add signature to a Signature Set"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: add_signature
    id: "signatureSetID"
    source_list:
      - "/usr/bin"
  register: signature

- name: "Remove a signature from a Signature Set"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: delete_signature
    id: "signatureSetID"
    signature_id: "signatureSetID"

- name: "Sends a signature signing request to the client"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: sign_app
    id: "signatureSetID"
    client_id: Client1
"""

RETURN = """

"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import (
    createSignatureSet,
    updateSignatureSet,
    addSignatureToSet,
    deleteSignatureInSetById,
    sendSignAppRequest,
    querySignAppRequest,
    cancelSignAppRequest,
    getSignatureFromSetByFilter,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

_signature = dict(
    file_name=dict(type="str"),
    hash_value=dict(type="str"),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "add_signature",
            "get_signature",
            "delete_signature",
            "sign_app",
            "query_sign_app",
            "cancel_sign_app",
        ],
        required=True,
    ),
    id=dict(type="str"),
    signature_id=dict(type="str"),
    name=dict(type="str"),
    description=dict(type="str"),
    source_list=dict(type="list", elements="str"),
    signatures=dict(type="list", elements="dict", options=_signature),
    client_id=dict(type="str"),
    hash_value=dict(type="str"),
    file_name=dict(type="str"),
)


def validate_parameters(cte_signature_set_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name"]],
            ["op_type", "patch", ["id"]],
            ["op_type", "add_signature", ["id", "signatures"]],
            ["op_type", "get_signature", ["id"]],
            ["op_type", "delete_signature", ["id", "signature_id"]],
            ["op_type", "sign_app", ["id", "client_id"]],
            ["op_type", "query_sign_app", ["id", "client_id"]],
            ["op_type", "cancel_sign_app", ["id", "client_id"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        cte_signature_set_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get("op_type") == "create":
        try:
            response = createSignatureSet(
                node=module.params.get("localNode"),
                name=module.params.get("name"),
                description=module.params.get("description"),
                source_list=module.params.get("source_list"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "patch":
        try:
            response = updateSignatureSet(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                description=module.params.get("description"),
                source_list=module.params.get("source_list"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "add_signature":
        try:
            response = addSignatureToSet(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                signatures=module.params.get("signatures"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "get_signature":
        try:
            response = getSignatureFromSetByFilter(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                hash_value=module.params.get("hash_value"),
                file_name=module.params.get("file_name"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "delete_signature":
        try:
            response = deleteSignatureInSetById(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                signature_id=module.params.get("signature_id"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "sign_app":
        try:
            response = sendSignAppRequest(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_id=module.params.get("client_id"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "query_sign_app":
        try:
            response = querySignAppRequest(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_id=module.params.get("client_id"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "cancel_sign_app":
        try:
            response = cancelSignAppRequest(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_id=module.params.get("client_id"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    else:
        module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
