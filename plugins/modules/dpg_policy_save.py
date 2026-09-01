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
module: dpg_policy_save
short_description: Manage DPG execution behavior for REST URLs and associated encryption parameters
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG policy API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.partial_diff
options:
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
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
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
            sample: "myResource"
        uri:
            description: Canonical resource URI.
            type: str
            returned: when applicable
            sample: "kylo:kylo:data-protection:dpg-policies:4ae2649a705e"
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
            description: Target state after the change (or empty-body create target in check mode).
            type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import (
    createDPGPolicy,
    updateDPGPolicy,
    dpgPolicyAddAPIUrl,
    dpgPolicyUpdateAPIUrl,
    dpgPolicyDeleteAPIUrl,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_create,
    idempotent_patch,
    check_mode_action,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    AnsibleCMValidationException,
    AnsibleCMParameterException,
    AnsibleCMFormatException,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.validation import (
    validate_required_parameters,
    validate_parameter_types,
    validate_parameter_formats,
    validate_choice,
    validate_dict_keys,
    DOCUMENTATION_LINKS,
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
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_request_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_request_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_request_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_request_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
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
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_request_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_request_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_request_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_request_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    json_response_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_delete_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_get_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_patch_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_post_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    url_request_put_tokens=dict(
        type="list", elements="dict", options=_api_token, required=False, no_log=False
    ),
    # op_type=update-api-url or delete-api-url
    api_url_id=dict(type="str"),
)


def validate_parameters(dpg_policy_module):
    """
    Validate parameters for dpg_policy_save module based on op_type.
    Raises appropriate exceptions with detailed error messages.
    """
    op_type = dpg_policy_module.params.get("op_type")

    # Validate op_type choice
    valid_op_types = ["create", "patch", "add-api-url", "update-api-url", "delete-api-url"]
    try:
        validate_choice("op_type", op_type, valid_op_types)
    except AnsibleCMValidationException as e:
        raise AnsibleCMValidationException(
            message=f"Invalid op_type '{op_type}'. "
                    f"Expected one of: {', '.join(valid_op_types)}. "
                    f"Example: op_type: create",
            documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
        )

    # Required parameters for each op_type
    required_params = {
        "create": ["name"],
        "patch": ["policy_id"],
        "add-api-url": ["policy_id", "api_url", "destination_url"],
        "update-api-url": ["policy_id", "api_url_id", "destination_url"],
        "delete-api-url": ["policy_id", "api_url_id"],
    }

    # Validate required parameters based on op_type
    if op_type in required_params:
        try:
            validate_required_parameters(
                parameters=dpg_policy_module,
                required=required_params[op_type],
                module_name="dpg_policy_save"
            )
        except AnsibleCMParameterException as e:
            raise AnsibleCMParameterException(
                message=f"Missing required parameters for op_type '{op_type}': {e.message}. "
                        f"Required for op_type '{op_type}': {', '.join(required_params[op_type])}. "
                        f"Example: policy_id: 'policy-123'",
                documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
            )

    # Validate parameter types
    try:
        if op_type == "create":
            if dpg_policy_module.params.get("name"):
                validate_parameter_types(
                    parameters=dpg_policy_module,
                    expected_types={"name": str, "description": str},
                    module_name="dpg_policy_save"
                )
        elif op_type == "patch":
            if dpg_policy_module.params.get("policy_id"):
                validate_parameter_types(
                    parameters=dpg_policy_module,
                    expected_types={"policy_id": str, "description": str},
                    module_name="dpg_policy_save"
                )
        elif op_type in ["add-api-url", "update-api-url", "delete-api-url"]:
            if dpg_policy_module.params.get("policy_id"):
                validate_parameter_types(
                    parameters=dpg_policy_module,
                    expected_types={"policy_id": str, "api_url": str, "destination_url": str, "api_url_id": str},
                    module_name="dpg_policy_save"
                )
    except AnsibleCMFormatException as e:
        raise AnsibleCMFormatException(
            message=f"Invalid parameter type: {e.message}. "
                    f"Expected string for parameter. "
                    f"Example: policy_id: 'policy-123' (string)",
            documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
        )

    # Validate proxy_config if provided
    try:
        if dpg_policy_module.params.get("proxy_config"):
            proxy_config = dpg_policy_module.params.get("proxy_config")
            if not isinstance(proxy_config, list):
                raise AnsibleCMFormatException(
                    message="proxy_config must be a list. "
                            "Expected: list of dictionaries. "
                            "Example: proxy_config: [{api_url: '/api/v2/...', destination_url: 'http://...'}]",
                    documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
                )

            # Validate each proxy_config item
            for idx, config in enumerate(proxy_config):
                if not isinstance(config, dict):
                    raise AnsibleCMFormatException(
                        message=f"proxy_config[{idx}] must be a dictionary. "
                                f"Expected: dictionary with api_url and destination_url. "
                                f"Example: {{api_url: '/api/v2/...', destination_url: 'http://localhost:8080'}}",
                        documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
                    )

                # Validate api_url format
                if "api_url" in config:
                    validate_parameter_formats(
                        parameters=dpg_policy_module,
                        format_rules={"api_url": r"^/api/.*"},
                        module_name="dpg_policy_save"
                    )

                # Validate destination_url format (basic URL validation)
                if "destination_url" in config:
                    destination_url = config["destination_url"]
                    if not (destination_url.startswith("http://") or destination_url.startswith("https://")):
                        raise AnsibleCMFormatException(
                            message=f"proxy_config[{idx}].destination_url must be a valid URL starting with http:// or https://. "
                                    f"Got: '{destination_url}'. "
                                    f"Example: destination_url: 'http://localhost:8080' or 'https://api.example.com'",
                            documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
                        )
    except AnsibleCMFormatException as e:
        raise AnsibleCMFormatException(
            message=f"Invalid proxy_config: {e.message}. "
                    f"Expected: list of dictionaries with api_url and destination_url. "
                    f"Example: proxy_config: [{{api_url: '/api/v2/sample/resource/id', destination_url: 'http://localhost:8080'}}]",
            documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
        )

    # Validate API tokens if provided
    try:
        token_params = [
            "json_request_delete_tokens", "json_request_get_tokens", "json_request_patch_tokens",
            "json_request_post_tokens", "json_request_put_tokens",
            "json_response_delete_tokens", "json_response_get_tokens", "json_response_patch_tokens",
            "json_response_post_tokens", "json_response_put_tokens",
            "url_request_delete_tokens", "url_request_get_tokens", "url_request_patch_tokens",
            "url_request_post_tokens", "url_request_put_tokens"
        ]

        for token_param in token_params:
            if dpg_policy_module.params.get(token_param):
                tokens = dpg_policy_module.params.get(token_param)
                if not isinstance(tokens, list):
                    raise AnsibleCMFormatException(
                        message=f"{token_param} must be a list. "
                                f"Expected: list of dictionaries with name, operation, protection_policy. "
                                f"Example: [{'{'}name: 'creditCard.[*].CCNumber', operation: 'protect', protection_policy: 'CC_ProtectionPolicy'{'}'}]",
                        documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
                    )

                # Validate each token
                for idx, token in enumerate(tokens):
                    if not isinstance(token, dict):
                        raise AnsibleCMFormatException(
                            message=f"{token_param}[{idx}] must be a dictionary. "
                                    f"Expected: dictionary with name, operation, protection_policy. "
                                    f"Example: {{'name': 'creditCard.[*].CCNumber', 'operation': 'protect', 'protection_policy': 'CC_ProtectionPolicy'}}",
                            documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
                        )

                    # Validate required keys in token
                    required_token_keys = ["name", "operation", "protection_policy"]
                    try:
                        validate_dict_keys(
                            data=token,
                            required_keys=required_token_keys,
                            optional_keys=["access_policy", "external_version_header"],
                            parameter_name=f"{token_param}[{idx}]",
                            module_name="dpg_policy_save"
                        )
                    except AnsibleCMParameterException as e:
                        raise AnsibleCMParameterException(
                            message=f"Invalid token in {token_param}: {e.message}. "
                                    f"Required keys: {', '.join(required_token_keys)}. "
                                    f"Example: {{'name': 'creditCard.[*].CCNumber', 'operation': 'protect', 'protection_policy': 'CC_ProtectionPolicy'}}",
                            documentation_link=DOCUMENTATION_LINKS.get("dpg_policy_save", "")
                        )

                    # Validate operation value
                    if "operation" in token:
                        validate_choice(
                            parameter_name=f"{token_param}[{idx}].operation",
                            value=token["operation"],
                            choices=["protect", "reveal", "mask", "truncate"],
                            module_name="dpg_policy_save"
                        )
    except (AnsibleCMFormatException, AnsibleCMParameterException) as e:
        raise

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

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    client = CipherTrustClient(module.params.get("localNode"))

    op_type = module.params.get("op_type")

    with ciphertrust_operation(module):
        validate_parameters(dpg_policy_module=module)

        if op_type == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint="data-protection/dpg-policies",
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=createDPGPolicy,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    name=module.params.get("name"),
                    description=module.params.get("description"),
                    proxy_config=module.params.get("proxy_config"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint="data-protection/dpg-policies",
                resource_id=module.params.get("policy_id"),
                ignore_fields=("policy_id",),
                patch_fn=updateDPGPolicy,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    policy_id=module.params.get("policy_id"),
                    description=module.params.get("description"),
                    proxy_config=module.params.get("proxy_config"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif op_type == "add-api-url":
            check_mode_action(module)
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
            result["changed"] = True

        elif op_type == "update-api-url":
            check_mode_action(module)
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
            result["changed"] = True

        elif op_type == "delete-api-url":
            check_mode_action(module)
            response = dpgPolicyDeleteAPIUrl(
                node=module.params.get("localNode"),
                policy_id=module.params.get("policy_id"),
                api_url_id=module.params.get("api_url_id"),
            )
            result["response"] = response
            result["changed"] = True

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
