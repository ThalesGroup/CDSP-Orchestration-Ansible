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
module: dpg_masking_format_save
short_description: Manage masking formats for DPG
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG Masking Format API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
version_added: "1.0.0"
author: Anurag Jain, Developer Advocate Thales Group
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
      choices: [create, patch]
      required: true
      type: str
    masking_format_id:
      description:
        - Identifier of the Masking Format to be patched
      type: str
    name:
      description: Unique name for the masking format
      type: str
    ending_characters:
      description: Number of ending characters to be masked
      type: int
      required: false
    mask_char:
      description: Character used for masking
      type: str
      required: false
    show:
      description: Flag to show/hide the starting/ending characters while revealing the data
      type: bool
      required: false
    starting_characters:
      description: Number of starting characters to be masked
      type: str
"""

EXAMPLES = """
- name: "Create Masking Format"
  thalesgroup.ciphertrust.dpg_masking_format_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: create
    name: AnsibleIntegrationTest_MaskingFormat
    ending_characters: 2
    mask_char: X
    show: true
    starting_characters: 4

- name: "Patch Masking Format"
  thalesgroup.ciphertrust.dpg_masking_format_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: patch
    masking_format_id: <MaskingFormatID>
    ending_characters: 4
    mask_char: O
    starting_characters: 2

- name: "Delete Masking Format ID"
  thalesgroup.ciphertrust.cm_resource_delete:
    key: <MaskingFormatID>
    resource_type: "masking-formats"
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
    createMaskingFormat,
    updateMaskingFormat,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    masking_format_id=dict(type="str"),
    name=dict(type="str"),
    starting_characters=dict(type="int"),
    ending_characters=dict(type="int"),
    mask_char=dict(type="str"),
    show=dict(type="bool"),
)


def validate_parameters(dpg_masking_format_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["masking_format_id"]],
            ["op_type", "create", ["name"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        dpg_masking_format_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get("op_type") == "create":
        try:
            response = createMaskingFormat(
                node=module.params.get("localNode"),
                name=module.params.get("name"),
                ending_characters=module.params.get("ending_characters"),
                mask_char=module.params.get("mask_char"),
                show=module.params.get("show"),
                starting_characters=module.params.get("starting_characters"),
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
            response = updateMaskingFormat(
                node=module.params.get("localNode"),
                masking_format_id=module.params.get("masking_format_id"),
                name=module.params.get("name"),
                ending_characters=module.params.get("ending_characters"),
                mask_char=module.params.get("mask_char"),
                show=module.params.get("show"),
                starting_characters=module.params.get("starting_characters"),
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
