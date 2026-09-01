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
module: cm_cluster
short_description: Create or join CipherTrust Manager node cluster
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with cluster management.
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
options:
    op_type:
        description: Operation to be performed
        choices: [new, join]
        required: true
        type: str
    nodes:
        description: list of CM nodes willing to join the cluster
        type: list
        elements: dict
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
"""

EXAMPLES = """
- name: "Create new cluster"
  thalesgroup.ciphertrust.cm_cluster:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: new

- name: "Join cluster"
  thalesgroup.ciphertrust.cm_cluster:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: join
    nodes:
      - server_ip: "IP/FQDN of CipherTrust Manager"
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cluster import (
    new,
    csr,
    sign,
    join,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)

import ast
import json

_joining_node = dict(
    server_ip=dict(type="str", required=True),
    server_private_ip=dict(type="str", required=True),
    server_port=dict(type="int", required=True),
    user=dict(type="str", required=True),
    password=dict(type="str", required=True, no_log=True),
    verify=dict(type="bool", required=True),
)
argument_spec = dict(
    op_type=dict(type="str", choices=["new", "join"], required=True),
    nodes=dict(type="list", elements="dict", options=_joining_node),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(["op_type", "join", ["nodes"]],),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def _parse_signing_response(output):
    """Extract the signed-certificate payload from a cluster sign response.

    CipherTrust Manager returns this payload as a string in the response's
    ``description`` field. It is JSON in current releases but has historically
    been a Python-style dict literal, so both are accepted. Anything else, or
    a payload missing the fields the join step needs, is reported as an API
    error rather than raising ValueError or KeyError out of the module.
    """
    description_str = output.get("description") if isinstance(output, dict) else None
    if not isinstance(description_str, str):
        raise CMApiException(
            message="Cluster signing response has no 'description' payload; "
                    "got fields: {0}".format(
                        sorted(output) if isinstance(output, dict) else type(output).__name__
                    ),
            api_error_code=0,
        )

    try:
        parsed = json.loads(description_str)
    except (ValueError, TypeError):
        try:
            parsed = ast.literal_eval(description_str)
        except (ValueError, SyntaxError, TypeError):
            raise CMApiException(
                message="Could not parse the cluster signing response payload.",
                api_error_code=0,
            )

    if not isinstance(parsed, dict):
        raise CMApiException(
            message="Cluster signing payload is a {0}, expected a mapping.".format(
                type(parsed).__name__
            ),
            api_error_code=0,
        )

    missing = [f for f in ("cert", "cachain", "mkek_blob") if f not in parsed]
    if missing:
        raise CMApiException(
            message="Cluster signing payload is missing {0}; got fields: {1}".format(
                ", ".join(missing), sorted(parsed)
            ),
            api_error_code=0,
        )
    return parsed


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    with ciphertrust_operation(module):
        if module.params.get("op_type") == "new":
            check_mode_action(module)
            response = new(
                node=module.params.get("localNode"),
            )
            result["response"] = response
            result["changed"] = True

        elif module.params.get("op_type") == "join":
            check_mode_action(module)
            _joining_nodes = module.params.get("nodes")

            for node in _joining_nodes:
                # Send request for CSR generation to the new node
                strCSR = csr(
                    master=module.params.get("localNode"),
                    node=node,
                )

                # Send request for CSR signing to member node
                output = sign(
                    master=module.params.get("localNode"),
                    node=node,
                    csr=strCSR,
                )
                description_dict = _parse_signing_response(output)
                cert = description_dict['cert']
                caChain = description_dict['cachain']
                mkek_blob = description_dict['mkek_blob']

                # Last but not least, send the join request to new node with signed certificate
                output = join(
                    master=module.params.get("localNode"),
                    node=node,
                    cert=cert,
                    caChain=caChain,
                    mkek_blob=mkek_blob,
                )
                result["output"] = output
                result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
