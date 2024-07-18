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
module: dpg_policy_save
short_description: Manage DPG execution behavior for REST URLs and associated encryption parameters
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG policy API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
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
      choices: ['create', 'patch', 'add-api-url', 'update-api-url', 'delete-api-url']
      required: true
      type: str
    policy_id:
      description:
        - Identifier of the DPG Policy to be patched
      type: str
    name:
      description: Name of the DPG policy
      type: str
      required: false
    description:
      description: Description of the DPG policy
      type: str
      required: false
    api_url_id:
      description: API URL ID to be updated
      type: str
    proxy_config:
      description: List of API urls to be added to the proxy configuration
      type: list
      elements: dict
      required: false
      suboptions:
        api_url:
          description: URL of the application server from which the request will received.
          type: str
        destination_url:
          description: URL of the application server where the request will be served.
          type: str
        json_request_post_tokens:
          description: API tokens to be protected in a POST Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_response_post_tokens:
          description: API tokens to be protected in a POST Response
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_request_get_tokens:
          description: API tokens to be protected in a GET Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_response_get_tokens:
          description: API tokens to be protected in a GET Response
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_request_put_tokens:
          description: API tokens to be protected in a PUT Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_response_put_tokens:
          description: API tokens to be protected in a PUT Response
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_request_patch_tokens:
          description: API tokens to be protected in a PATCH Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_response_patch_tokens:
          description: API tokens to be protected in a PATCH Response
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_request_delete_tokens:
          description: API tokens to be protected in a DELETE Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        json_response_delete_tokens:
          description: API tokens to be protected in a DELETE Response
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        url_request_post_tokens:
          description: API tokens to be protected in a POST Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        url_request_get_tokens:
          description: API tokens to be protected in a GET Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        url_request_put_tokens:
          description: API tokens to be protected in a PUT Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        url_request_patch_tokens:
          description: API tokens to be protected in a PATCH Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
        url_request_delete_tokens:
          description: API tokens to be protected in a DELETE Request
          type: list
          elements: dict
          suboptions:
            name:
              description:
                - Name
              type: str
            operation:
              description:
                - API Operation
              type: str
            protection_policy:
              description:
                - Protection Policy to be associated
              type: str
            access_policy:
              description:
                - Access Policy to be associated
              type: str
            external_version_header:
              description:
                - Opetional external version header
              type: str
    api_url:
      description: URL of the application server from which the request will received.
      type: str
    destination_url:
      description: URL of the application server where the request will be served.
      type: str
    json_request_post_tokens:
      description: API tokens to be protected in a POST Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_response_post_tokens:
      description: API tokens to be protected in a POST Response
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_request_get_tokens:
      description: API tokens to be protected in a GET Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_response_get_tokens:
      description: API tokens to be protected in a GET Response
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_request_put_tokens:
      description: API tokens to be protected in a PUT Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_response_put_tokens:
      description: API tokens to be protected in a PUT Response
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_request_patch_tokens:
      description: API tokens to be protected in a PATCH Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_response_patch_tokens:
      description: API tokens to be protected in a PATCH Response
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_request_delete_tokens:
      description: API tokens to be protected in a DELETE Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    json_response_delete_tokens:
      description: API tokens to be protected in a DELETE Response
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    url_request_post_tokens:
      description: API tokens to be protected in a POST Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    url_request_get_tokens:
      description: API tokens to be protected in a GET Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    url_request_put_tokens:
      description: API tokens to be protected in a PUT Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    url_request_patch_tokens:
      description: API tokens to be protected in a PATCH Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
    url_request_delete_tokens:
      description: API tokens to be protected in a DELETE Request
      type: list
      elements: dict
      suboptions:
        name:
          description:
            - Name
          type: str
        operation:
          description:
            - API Operation
          type: str
        protection_policy:
          description:
            - Protection Policy to be associated
          type: str
        access_policy:
          description:
            - Access Policy to be associated
          type: str
        external_version_header:
          description:
            - Opetional external version header
          type: str
"""

EXAMPLES = """
- name: "Create DPG Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: create
    name: DPGPolicyName
    proxy_config:
    - api_url: "/api/sample/resource/id"
      destination_url: "http://localhost:8080"
      json_request_post_tokens:
      - name: "creditCard.[*].CCNumber"
        operation: "protect"
        protection_policy: "CC_ProtectionPolicy"
      - name: "creditCard.[*].cvv"
        operation: "protect"
        protection_policy: "cvv_ProtectionPolicy"
      json_response_get_tokens:
      - name: "creditCard.[*].cvv"
        operation: "reveal"
        protection_policy: "cvv_ProtectionPolicy"
        access_policy: "cc_access_policy"
  register: _result

- name: "Patch DPG Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: patch
    policy_id: <DPGPolicyID>
    description: "Updated via Ansible"

- name: "Add api_url to DPG Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: add-api-url
    policy_id: <DPGPolicyID>
    api_url: "/api/v2/sample/resource/id"
    destination_url: "http://localhost:8080"
    json_request_post_tokens:
    - name: "creditCard.[*].cvv"
      operation: "protect"
      protection_policy: "cvv_ProtectionPolicy"

- name: "Update api_url in DPG Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: update-api-url
    policy_id: <DPGPolicyID>
    api_url_id: <API_URL_ID>
    destination_url: "http://localhost:8081"

- name: "Delete api_url from DPG Policy"
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: delete-api-url
    policy_id: <DPGPolicyID>
    api_url_id: <API_URL_ID>

- name: "Delete DPG Policy by ID"
  thalesgroup.ciphertrust.cm_resource_delete:
    key: <DPGPolicyID>
    resource_type: "dpg-policies"
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
"""

RETURN = """

"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import (
    createDPGPolicy,
    updateDPGPolicy,
    dpgPolicyAddAPIUrl,
    dpgPolicyUpdateAPIUrl,
    dpgPolicyDeleteAPIUrl,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

_api_token = dict(
    name=dict(type="str"),
    operation=dict(type="str"),
    protection_policy=dict(type="str"),
    access_policy=dict(type="str"),
    external_version_header=dict(type="str"),
)

_proxy_config = dict(
    api_url=dict(type="str"),
    destination_url=dict(type="str"),
    json_request_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_request_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_request_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_request_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_request_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=["create", "patch", "add-api-url", "update-api-url", "delete-api-url"],
        required=True,
    ),
    policy_id=dict(type="str"),
    name=dict(type="str"),
    description=dict(type="str"),
    proxy_config=dict(type="list", elements="dict", options=_proxy_config),
    # op_type=add-api-url
    api_url=dict(type="str"),
    destination_url=dict(type="str"),
    json_request_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_request_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_request_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_request_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_request_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    json_response_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    url_request_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False
    ),
    # op_type=update-api-url or delete-api-url
    api_url_id=dict(type="str"),
)


def validate_parameters(dpg_policy_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(["op_type", "patch", ["policy_id"]],),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        dpg_policy_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get("op_type") == "create":
        try:
            response = createDPGPolicy(
                node=module.params.get("localNode"),
                name=module.params.get("name"),
                description=module.params.get("description"),
                proxy_config=module.params.get("proxy_config"),
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
            response = updateDPGPolicy(
                node=module.params.get("localNode"),
                policy_id=module.params.get("policy_id"),
                description=module.params.get("description"),
                proxy_config=module.params.get("proxy_config"),
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

    elif module.params.get("op_type") == "add-api-url":
        try:
            response = dpgPolicyAddAPIUrl(
                node=module.params.get("localNode"),
                policy_id=module.params.get("policy_id"),
                api_url=module.params.get("api_url"),
                destination_url=module.params.get("destination_url"),
                json_request_delete_tokens=module.params.get(
                    "json_request_delete_tokens"
                ),
                json_request_get_tokens=module.params.get("json_request_get_tokens"),
                json_request_patch_tokens=module.params.get(
                    "json_request_patch_tokens"
                ),
                json_request_post_tokens=module.params.get("json_request_post_tokens"),
                json_request_put_tokens=module.params.get("json_request_put_tokens"),
                json_response_delete_tokens=module.params.get(
                    "json_response_delete_tokens"
                ),
                json_response_get_tokens=module.params.get("json_response_get_tokens"),
                json_response_patch_tokens=module.params.get(
                    "json_response_patch_tokens"
                ),
                json_response_post_tokens=module.params.get(
                    "json_response_post_tokens"
                ),
                json_response_put_tokens=module.params.get("json_response_put_tokens"),
                url_request_delete_tokens=module.params.get(
                    "url_request_delete_tokens"
                ),
                url_request_get_tokens=module.params.get("url_request_get_tokens"),
                url_request_patch_tokens=module.params.get("url_request_patch_tokens"),
                url_request_post_tokens=module.params.get("url_request_post_tokens"),
                url_request_put_tokens=module.params.get("url_request_put_tokens"),
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

    elif module.params.get("op_type") == "update-api-url":
        try:
            response = dpgPolicyUpdateAPIUrl(
                node=module.params.get("localNode"),
                policy_id=module.params.get("policy_id"),
                api_url_id=module.params.get("api_url_id"),
                destination_url=module.params.get("destination_url"),
                json_request_delete_tokens=module.params.get(
                    "json_request_delete_tokens"
                ),
                json_request_get_tokens=module.params.get("json_request_get_tokens"),
                json_request_patch_tokens=module.params.get(
                    "json_request_patch_tokens"
                ),
                json_request_post_tokens=module.params.get("json_request_post_tokens"),
                json_request_put_tokens=module.params.get("json_request_put_tokens"),
                json_response_delete_tokens=module.params.get(
                    "json_response_delete_tokens"
                ),
                json_response_get_tokens=module.params.get("json_response_get_tokens"),
                json_response_patch_tokens=module.params.get(
                    "json_response_patch_tokens"
                ),
                json_response_post_tokens=module.params.get(
                    "json_response_post_tokens"
                ),
                json_response_put_tokens=module.params.get("json_response_put_tokens"),
                url_request_delete_tokens=module.params.get(
                    "url_request_delete_tokens"
                ),
                url_request_get_tokens=module.params.get("url_request_get_tokens"),
                url_request_patch_tokens=module.params.get("url_request_patch_tokens"),
                url_request_post_tokens=module.params.get("url_request_post_tokens"),
                url_request_put_tokens=module.params.get("url_request_put_tokens"),
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

    elif module.params.get("op_type") == "delete-api-url":
        try:
            response = dpgPolicyDeleteAPIUrl(
                node=module.params.get("localNode"),
                policy_id=module.params.get("policy_id"),
                api_url_id=module.params.get("api_url_id"),
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
