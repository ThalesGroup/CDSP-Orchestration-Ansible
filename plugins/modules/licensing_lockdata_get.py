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

DOCUMENTATION = '''
---
module: licensing_lockdata_get
short_description: Get license lockdata used to get license code
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with create group API
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
'''

EXAMPLES = '''
- name: "Get Licensing Lockdata"
  thalesgroup.ciphertrust.licensing_lockdata_get:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
'''

RETURN = '''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.licensing import (
    getLockdata,
)

def main():
    localNode = dict(
        server_ip=dict(type="str", required=True),
        server_private_ip=dict(type="str", required=True),
        server_port=dict(type="int", required=True),
        user=dict(type="str", required=True),
        password=dict(type="str", required=True),
        verify=dict(type="bool", required=True),
    )
    module = AnsibleModule(
        argument_spec=dict(
            localNode=dict(type="dict", options=localNode, required=True),
        ),
    )

    localNode = module.params.get("localNode")

    result = dict(
        changed=False,
    )

    response = dict()
    response = getLockdata(node=localNode)

    result["response"] = response

    module.exit_json(**result)


if __name__ == "__main__":
    main()
