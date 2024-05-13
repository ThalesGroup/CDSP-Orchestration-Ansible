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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.services import (
    restartCMServices,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

DOCUMENTATION = """
---
module: cm_services
short_description: Reset, restart CipherTrust Manager Services as well as check the status
description:
    - Reset CipherTrust Manager Services
    - Restart CipherTrust Manager Services
    - Get status of CipherTrust Manager Services
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
        auth_domain_path:
          description: user's domain path
          type: str
          required: true  
    op_type:
      description: Operation to be performed
      choices: [restart]
      required: true
      type: str
    delay:
      description: Delay in seconds before restart, defaults to 5 seconds
      type: int
      required: false
      default: 5
    services:
      description: An array of services to restart. If this parameter is ommitted, the entire application is restarted. Options include - nae-kmip, web
      type: list
      elements: str
"""

EXAMPLES = '''
- name: "Restart CM Services"
  thalesgroup.ciphertrust.cm_services:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: restart
    delay: 5
    services:
      - nae-kmip
      - web
'''

RETURN = """

"""

argument_spec = dict(
    op_type=dict(type='str', options=[
      'restart',
    ], required=True),
    delay=dict(type='int'),
    services=dict(type='list', element='str'),
)


def validate_parameters(cm_services):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'restart', ['services']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        cm_services=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'restart':
      try:
        response = restartCMServices(
          node=module.params.get('localNode'),
          delay=module.params.get('delay'),
          services=module.params.get('services'),
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


if __name__ == "__main__":
    main()
