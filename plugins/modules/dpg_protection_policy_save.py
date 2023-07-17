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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import ThalesCipherTrustModule
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import createProtectionPolicy, updateProtectionPolicy
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: domain_save
short_description: Manage DPG protection policies governing crypto operations
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with domains management API
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
          default: 5432
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
          default: false     
    op_type:
      description: Operation to be performed
      choices: [create, patch]
      required: true
      type: str
    policy_name:
      description:
        - Identifier of the access policy to be patched
      type: str
    algorithm:
      description: Algorithm to be used during crypto operations
      type: str
    key:
      description: Name of the key
      type: str
    name:
      description: Unique name for the protection policy
      type: str
    allow_single_char_input:
      description: If true, null or single-character inputs are passed untransformed. If false, row transformation fails
      type: bool
    character_set_id:
      description: ID of the Characterset
      required: false
      type: str
    iv:
      description: IV to be used during crypto operations
      required: false
      type: str
    tweak:
      description: Tweak data to be used during crypto operations
      required: false
      type: str
    tweak_algorithm:
      description: Tweak algorithm to be used during crypto operations
      choices: [SHA1, SHA256, None]
      required: false
      type: str
'''

EXAMPLES = '''
- name: "Create Access Policy"
  thalesgroup.ciphertrust.dpg_protection_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create

- name: "Patch Access Policy"
  thalesgroup.ciphertrust.dpg_protection_policy_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: patch
'''

RETURN = '''

'''

argument_spec = dict(
    op_type=dict(type='str', options=['create', 'patch'], required=True),
    policy_name=dict(type='str'),
    algorithm=dict(type='str'),
    key=dict(type='str'),
    name=dict(type='str'),
    allow_single_char_input=dict(type='bool'),
    character_set_id=dict(type='str'),
    iv=dict(type='str'),
    tweak=dict(type='str'),
    tweak_algorithm=dict(type='str', options=['SHA1', 'SHA256', 'None']),
)

def validate_parameters(dpg_protection_policy_module):
    return True

def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'patch', ['policy_name']],
            ['op_type', 'create', ['algorithm', 'key', 'name']]
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        dpg_protection_policy_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createProtectionPolicy(
          node=module.params.get('localNode'),
          algorithm=module.params.get('algorithm'),
          key=module.params.get('key'),
          name=module.params.get('name'),
          allow_single_char_input=module.params.get('allow_single_char_input'),
          character_set_id=module.params.get('character_set_id'),
          iv=module.params.get('iv'),
          tweak=module.params.get('tweak'),
          tweak_algorithm=module.params.get('tweak_algorithm'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateProtectionPolicy(
          node=module.params.get('localNode'),
          policy_name=module.params.get('policy_name'),
          algorithm=module.params.get('algorithm'),
          key=module.params.get('key'),
          allow_single_char_input=module.params.get('allow_single_char_input'),
          character_set_id=module.params.get('character_set_id'),
          iv=module.params.get('iv'),
          tweak=module.params.get('tweak'),
          tweak_algorithm=module.params.get('tweak_algorithm'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    else:
        module.fail_json(msg="invalid op_type")
        
    module.exit_json(**result)

if __name__ == '__main__':
    main()