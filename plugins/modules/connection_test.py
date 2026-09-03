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
module: connection_test
short_description: Test a cloud connection stored in CipherTrust Manager
description:
    - Asks CipherTrust Manager to verify that a stored cloud connection's
      credentials still work, by reaching the cloud provider with them.
    - Use this to confirm a connection created by
      M(thalesgroup.ciphertrust.connection_aws_save),
      M(thalesgroup.ciphertrust.connection_azure_save),
      M(thalesgroup.ciphertrust.connection_gcp_save) or
      M(thalesgroup.ciphertrust.connection_oci_save) is usable, and to detect
      credentials that have since expired or been revoked.
    - This module never alters the connection. It reports C(changed=false),
      because a test is a read of the provider's state rather than a change to
      CipherTrust Manager.
    - A failed test fails the task. CipherTrust Manager answers a failed test
      with HTTP 200 and C(connection_ok=false) rather than an error status, so
      a module that only checked the HTTP status would report success for a
      connection whose credentials have expired. Set C(failed_when) to
      C(false) to survey connections without failing the play.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    cloud:
      description:
        - Cloud provider the connection belongs to.
      choices: [aws, azure, gcp, oci]
      required: true
      type: str
    connection_id:
      description:
        - Name or id of the connection to test.
      required: true
      type: str
"""

EXAMPLES = """
- name: "Test an AWS connection"
  thalesgroup.ciphertrust.connection_test:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    cloud: aws
    connection_id: aws-production

- name: "Fail the play early if the Azure credentials have expired"
  thalesgroup.ciphertrust.connection_test:
    localNode: "{{ cm_connection }}"
    cloud: azure
    connection_id: azure-production

- name: "Report which connections are healthy without failing the play"
  thalesgroup.ciphertrust.connection_test:
    localNode: "{{ cm_connection }}"
    cloud: "{{ item.cloud }}"
    connection_id: "{{ item.name }}"
  loop:
    - { cloud: aws, name: aws-production }
    - { cloud: gcp, name: gcp-production }
  register: _connection_tests
  failed_when: false
"""

RETURN = r"""
changed:
    description:
      - Always C(false). Testing a connection reads the provider's state and
        changes nothing in CipherTrust Manager.
    returned: always
    type: bool
    sample: false
connection_ok:
    description: Whether CipherTrust Manager reached the cloud provider.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API.
    returned: always
    type: dict
    contains:
        connection_ok:
            description: C(true) when the test succeeded.
            type: bool
            returned: always
        connection_error:
            description: Why the test failed, as reported by the provider.
            type: str
            returned: when the test failed
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connections import (
    SUPPORTED_CLOUDS,
    test_error,
    test_existing,
    test_failed,
)

argument_spec = dict(
    cloud=dict(type="str", choices=list(SUPPORTED_CLOUDS), required=True),
    connection_id=dict(type="str", required=True),
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

    # A test performs no write, so check mode can run it as-is rather than
    # reporting a change it would not have made.
    with ciphertrust_operation(module):
        response = test_existing(
            node=module.params.get("localNode"),
            cloud=module.params.get("cloud"),
            connection_id=module.params.get("connection_id"),
        )

    result["response"] = response
    connection_ok = (response or {}).get("connection_ok")
    result["connection_ok"] = connection_ok

    # CipherTrust Manager reports a failed test as a successful request whose
    # body says the connection did not work. Reporting that as a passing task
    # would make this module worthless for its one purpose.
    if test_failed(response):
        module.fail_json(
            msg="Connection test failed for {0} connection '{1}': {2}".format(
                module.params.get("cloud"),
                module.params.get("connection_id"),
                test_error(response),
            ),
            **result
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
