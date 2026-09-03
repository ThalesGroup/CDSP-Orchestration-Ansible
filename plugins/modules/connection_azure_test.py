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
module: connection_azure_test
short_description: Test Azure credentials without storing them
description:
    - Asks CipherTrust Manager to verify a set of Azure credentials by reaching Azure with
      them, without storing a connection.
    - Use this before M(thalesgroup.ciphertrust.connection_azure_save) to fail early on
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
    client_id:
      description:
        - Client id of the Azure application (service principal).
        - Required when I(op_type=create).
        - Required.
      required: true
      type: str
    tenant_id:
      description:
        - Tenant id of the Azure application.
        - Required when I(op_type=create).
        - Required.
      required: true
      type: str
    client_secret:
      description:
        - Client secret for the Azure application.
        - Required unless I(is_certificate_used=true).
        - CipherTrust Manager never returns this value, so supplying it on a patch makes
          the task report C(changed) on every run.
        - Required.
      required: true
      type: str
    cloud_name:
      description:
        - Azure cloud to connect to. Defaults to C(AzureCloud).
      choices: [AzureCloud, AzureChinaCloud, AzureUSGovernment, AzureStack]
      type: str
    certificate:
      description:
        - Certificate to authenticate with, when I(is_certificate_used=true).
      type: str
    azure_stack_connection_type:
      description:
        - Directory service backing an Azure Stack deployment.
        - Only used when I(cloud_name=AzureStack).
      choices: [AAD, ADFS]
      type: str
    azure_stack_server_cert:
      description:
        - Azure Stack server certificate.
      type: str
    active_directory_endpoint:
      description:
        - Azure Stack Active Directory authority URL.
      type: str
    management_url:
      description:
        - Azure Stack management URL.
      type: str
"""

EXAMPLES = """
- name: "Check Azure credentials before creating a connection"
  thalesgroup.ciphertrust.connection_azure_test:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    client_id: "00000000-0000-0000-0000-000000000000"
    tenant_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "{{ vault_azure_client_secret }}"

- name: "Report on credentials without failing the play"
  thalesgroup.ciphertrust.connection_azure_test:
    localNode: "{{ cm_connection }}"
    client_id: "00000000-0000-0000-0000-000000000000"
    tenant_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "{{ vault_azure_client_secret }}"
  register: _azure_check
  failed_when: false
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
    description: Whether CipherTrust Manager reached Azure with these credentials.
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

_CLOUD = "azure"

argument_spec = dict(
    client_id=dict(type="str", no_log=False, required=True),
    tenant_id=dict(type="str", required=True),
    client_secret=dict(type="str", no_log=True, required=True),
    cloud_name=dict(type="str", choices=["AzureCloud", "AzureChinaCloud", "AzureUSGovernment", "AzureStack"]),
    certificate=dict(type="str"),
    azure_stack_connection_type=dict(type="str", choices=["AAD", "ADFS"]),
    azure_stack_server_cert=dict(type="str"),
    active_directory_endpoint=dict(type="str"),
    management_url=dict(type="str"),
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
            client_id=module.params.get("client_id"),
            tenant_id=module.params.get("tenant_id"),
            client_secret=module.params.get("client_secret"),
            cloud_name=module.params.get("cloud_name"),
            certificate=module.params.get("certificate"),
            azure_stack_connection_type=module.params.get("azure_stack_connection_type"),
            azure_stack_server_cert=module.params.get("azure_stack_server_cert"),
            active_directory_endpoint=module.params.get("active_directory_endpoint"),
            management_url=module.params.get("management_url"),
        )

    result["response"] = response
    result["connection_ok"] = (response or {}).get("connection_ok")

    # A failed test comes back as HTTP 200 with connection_ok=false, so the
    # body has to be read; the status code alone would report success.
    if test_failed(response):
        module.fail_json(
            msg="Azure credentials were rejected: {0}".format(
                test_error(response)
            ),
            **result
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
