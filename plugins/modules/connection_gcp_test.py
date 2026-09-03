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
module: connection_gcp_test
short_description: Test Google Cloud credentials without storing them
description:
    - Asks CipherTrust Manager to verify a set of Google Cloud credentials by reaching
      Google Cloud with them, without storing a connection.
    - Use this before M(thalesgroup.ciphertrust.connection_gcp_save) to fail early on
      credentials that do not work, or to check a replacement credential before rotating
      the one a connection already uses.
    - To test credentials already stored in a connection, use
      M(thalesgroup.ciphertrust.connection_test) instead.
    - A failed test fails the task. CipherTrust Manager answers a failed test with HTTP
      200 and C(connection_ok=false) rather than an error status, so a module that checked
      only the HTTP status would report success for credentials the provider refused. Set
      C(failed_when) to C(false) to check credentials without failing the play.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    key_file:
      description:
        - Contents of the private key file for a GCP service account.
        - Required when I(op_type=create). Pass the file's contents, for example with the
          C(file) lookup, not a path.
        - CipherTrust Manager never returns this value, so supplying it on a patch makes
          the task report C(changed) on every run.
        - Required.
      required: true
      type: str
"""

EXAMPLES = """
- name: "Check a GCP service account key before creating a connection"
  thalesgroup.ciphertrust.connection_gcp_test:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    key_file: "{{ lookup('file', 'service-account.json') }}"

- name: "Check a rotated key before replacing the one in use"
  thalesgroup.ciphertrust.connection_gcp_test:
    localNode: "{{ cm_connection }}"
    key_file: "{{ lookup('file', 'service-account-new.json') }}"
  register: _new_key

- name: "Rotate the key on the connection only if the new one works"
  thalesgroup.ciphertrust.connection_gcp_save:
    localNode: "{{ cm_connection }}"
    op_type: patch
    connection_id: gcp-production
    key_file: "{{ lookup('file', 'service-account-new.json') }}"
  when: _new_key.connection_ok
"""

RETURN = r"""
changed:
    description:
      - Always C(false). Testing credentials stores nothing and changes
        nothing in CipherTrust Manager.
    returned: always
    type: bool
    sample: false
connection_ok:
    description: Whether CipherTrust Manager reached Google Cloud with these credentials.
    returned: always
    type: bool
    sample: true
response:
    description: The raw response dictionary from the CipherTrust Manager API.
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
    test_error,
    test_failed,
    test_parameters,
)

_CLOUD = "gcp"

argument_spec = dict(
    key_file=dict(type="str", no_log=True, required=True),
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

    # Nothing is stored, so this is safe to run under --check as-is.
    with ciphertrust_operation(module):
        response = test_parameters(
            node=module.params.get("localNode"),
            cloud=_CLOUD,
            key_file=module.params.get("key_file"),
        )

    result["response"] = response
    result["connection_ok"] = (response or {}).get("connection_ok")

    # A failed test comes back as HTTP 200 with connection_ok=false, so the
    # body has to be read; the status code alone would report success.
    if test_failed(response):
        module.fail_json(
            msg="Google Cloud credentials were rejected: {0}".format(
                test_error(response)
            ),
            **result
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
