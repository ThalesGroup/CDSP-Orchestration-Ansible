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
module: connection_oci_test
short_description: Test OCI credentials without storing them
description:
    - Asks CipherTrust Manager to verify a set of OCI credentials by reaching OCI with
      them, without storing a connection.
    - Use this before M(thalesgroup.ciphertrust.connection_oci_save) to fail early on
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
    user_ocid:
      description:
        - OCID of the user the API key belongs to.
        - Required when I(op_type=create).
        - Required.
      required: true
      type: str
    tenancy_ocid:
      description:
        - OCID of the tenancy.
        - Required when I(op_type=create).
        - Required.
      required: true
      type: str
    fingerprint:
      description:
        - Fingerprint of the public key added to the user.
        - Required when I(op_type=create).
        - Required.
      required: true
      type: str
    region:
      description:
        - Oracle Cloud Infrastructure region, for example C(us-ashburn-1).
        - Required when I(op_type=create).
        - Required.
      required: true
      type: str
    credentials:
      description:
        - API signing key for the connection.
        - Required when I(op_type=create).
        - Required.
      required: true
      type: dict
      suboptions:
        key_file:
          description:
            - Contents of the PEM private key for the API signing key.
            - Pass the file's contents, for example with the C(file) lookup, not a path.
            - CipherTrust Manager never returns this value, so supplying it on a patch
              makes the task report C(changed) on every run.
          type: str
        pass_phrase:
          description:
            - Passphrase protecting I(credentials.key_file), if encrypted.
          type: str
"""

EXAMPLES = """
- name: "Check OCI credentials before creating a connection"
  thalesgroup.ciphertrust.connection_oci_test:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    user_ocid: "ocid1.user.oc1..aaaaaaaa"
    tenancy_ocid: "ocid1.tenancy.oc1..bbbbbbbb"
    fingerprint: "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34"
    region: us-ashburn-1
    credentials:
      key_file: "{{ lookup('file', 'oci_api_key.pem') }}"
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
    description: Whether CipherTrust Manager reached OCI with these credentials.
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

_CLOUD = "oci"

_credentials = dict(
    key_file=dict(type="str", no_log=True),
    pass_phrase=dict(type="str", no_log=True),
)

argument_spec = dict(
    user_ocid=dict(type="str", required=True),
    tenancy_ocid=dict(type="str", required=True),
    fingerprint=dict(type="str", required=True),
    region=dict(type="str", required=True),
    credentials=dict(type="dict", required=True, options=_credentials),
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
            user_ocid=module.params.get("user_ocid"),
            tenancy_ocid=module.params.get("tenancy_ocid"),
            fingerprint=module.params.get("fingerprint"),
            region=module.params.get("region"),
            credentials=module.params.get("credentials"),
        )

    result["response"] = response
    result["connection_ok"] = (response or {}).get("connection_ok")

    # A failed test comes back as HTTP 200 with connection_ok=false, so the
    # body has to be read; the status code alone would report success.
    if test_failed(response):
        module.fail_json(
            msg="OCI credentials were rejected: {0}".format(
                test_error(response)
            ),
            **result
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
