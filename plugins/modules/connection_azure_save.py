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
module: connection_azure_save
short_description: Manage Azure connections in CipherTrust Manager's connection manager
description:
    - Create or update an Azure connection in the CipherTrust Manager connection manager.
    - An Azure connection stores the service-principal credentials CipherTrust Manager
      uses to reach an Azure tenant, and is referenced by products such as CCKM.
    - Authenticate with a client secret or with a certificate.
    - Delete a connection with M(thalesgroup.ciphertrust.cm_resource_delete) using
      I(resource_type=azure-connection), and test one with
      M(thalesgroup.ciphertrust.connection_test).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description: Operation to be performed
      choices: [create, patch]
      required: true
      type: str
    connection_id:
      description:
        - Name or id of the connection to update.
        - Required when I(op_type=patch).
      type: str
    name:
      description:
        - Unique name for the connection.
        - Required when I(op_type=create). CipherTrust Manager does not allow a connection
          to be renamed, so it cannot be patched.
      type: str
    client_id:
      description:
        - Client id of the Azure application (service principal).
        - Required when I(op_type=create).
      type: str
    tenant_id:
      description:
        - Tenant id of the Azure application.
        - Required when I(op_type=create).
      type: str
    client_secret:
      description:
        - Client secret for the Azure application.
        - Required unless I(is_certificate_used=true).
        - CipherTrust Manager never returns this value, so supplying it on a patch makes
          the task report C(changed) on every run.
      type: str
    cloud_name:
      description:
        - Azure cloud to connect to. Defaults to C(AzureCloud).
      choices: [AzureCloud, AzureChinaCloud, AzureUSGovernment, AzureStack]
      type: str
    is_certificate_used:
      description:
        - Authenticate with a certificate instead of a client secret.
      type: bool
    certificate:
      description:
        - Certificate to authenticate with, when I(is_certificate_used=true).
      type: str
    cert_duration:
      description:
        - Validity of a CipherTrust Manager generated certificate, in days.
        - Defaults to 730 (two years).
      type: int
    external_certificate_used:
      description:
        - Set to C(true) when I(certificate) was generated outside CipherTrust Manager.
      type: bool
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
    resource_manager_url:
      description:
        - Azure Stack resource manager URL.
      type: str
    vault_resource_url:
      description:
        - Azure Stack vault service resource URL.
      type: str
    key_vault_dns_suffix:
      description:
        - Azure Stack key vault DNS suffix.
      type: str
    products:
      description:
        - CipherTrust products that may use this connection.
        - C(cckm) is the value for cloud connections; GCP connections also accept C(ddc).
      type: list
      elements: str
    description:
      description:
        - Description of the connection.
      type: str
    meta:
      description:
        - Arbitrary end-user or service data stored alongside the connection.
      type: dict
    labels:
      description:
        - Key/value pairs used to group resources, following Kubernetes label conventions.
      type: dict
"""

EXAMPLES = """
- name: "Create an Azure connection with a client secret"
  thalesgroup.ciphertrust.connection_azure_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: azure-production
    description: "Production Azure tenant"
    products:
      - cckm
    client_id: "00000000-0000-0000-0000-000000000000"
    tenant_id: "11111111-1111-1111-1111-111111111111"
    client_secret: "{{ vault_azure_client_secret }}"
    cloud_name: AzureCloud

- name: "Create an Azure connection authenticated with a certificate"
  thalesgroup.ciphertrust.connection_azure_save:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: azure-cert
    client_id: "00000000-0000-0000-0000-000000000000"
    tenant_id: "11111111-1111-1111-1111-111111111111"
    is_certificate_used: true
    cert_duration: 365

- name: "Repoint an Azure connection at a different cloud"
  thalesgroup.ciphertrust.connection_azure_save:
    localNode: "{{ cm_connection }}"
    op_type: patch
    connection_id: azure-production
    cloud_name: AzureUSGovernment
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
        existing connection when one was found during the GET-before-write
        idempotency check.
      - Secrets are never returned by CipherTrust Manager, so they do not
        appear here.
    returned: when a write was attempted or an existing connection matched
    type: dict
    contains:
        id:
            description: Unique identifier of the connection.
            type: str
            returned: when applicable
        name:
            description: Name of the connection.
            type: str
            returned: when applicable
        uri:
            description: Canonical resource URI.
            type: str
            returned: when applicable
        createdAt:
            description: RFC3339 timestamp of creation.
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
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connections import (
    create,
    patch,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    idempotent_create,
    idempotent_patch,
)

_CLOUD = "azure"
_ENDPOINT = "connectionmgmt/services/azure/connections"

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    connection_id=dict(type="str"),
    name=dict(type="str"),
    client_id=dict(type="str", no_log=False),
    tenant_id=dict(type="str"),
    client_secret=dict(type="str", no_log=True),
    cloud_name=dict(type="str", choices=["AzureCloud", "AzureChinaCloud", "AzureUSGovernment", "AzureStack"]),
    is_certificate_used=dict(type="bool"),
    certificate=dict(type="str"),
    cert_duration=dict(type="int"),
    external_certificate_used=dict(type="bool"),
    azure_stack_connection_type=dict(type="str", choices=["AAD", "ADFS"]),
    azure_stack_server_cert=dict(type="str"),
    active_directory_endpoint=dict(type="str"),
    management_url=dict(type="str"),
    resource_manager_url=dict(type="str"),
    vault_resource_url=dict(type="str"),
    key_vault_dns_suffix=dict(type="str", no_log=False),
    products=dict(type="list", elements="str"),
    description=dict(type="str"),
    meta=dict(type="dict"),
    labels=dict(type="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["connection_id"]],
            ["op_type", "create", ["name", "client_id", "tenant_id"]],
        ),
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

    with ciphertrust_operation(module):
        if module.params.get("op_type") == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint=_ENDPOINT,
                lookup_param="name",
                lookup_value=module.params.get("name"),
                create_fn=create,
                create_kwargs=dict(
                    node=module.params.get("localNode"),
                    cloud=_CLOUD,
                    name=module.params.get("name"),
                    client_id=module.params.get("client_id"),
                    tenant_id=module.params.get("tenant_id"),
                    client_secret=module.params.get("client_secret"),
                    cloud_name=module.params.get("cloud_name"),
                    is_certificate_used=module.params.get("is_certificate_used"),
                    certificate=module.params.get("certificate"),
                    cert_duration=module.params.get("cert_duration"),
                    external_certificate_used=module.params.get("external_certificate_used"),
                    azure_stack_connection_type=module.params.get("azure_stack_connection_type"),
                    azure_stack_server_cert=module.params.get("azure_stack_server_cert"),
                    active_directory_endpoint=module.params.get("active_directory_endpoint"),
                    management_url=module.params.get("management_url"),
                    resource_manager_url=module.params.get("resource_manager_url"),
                    vault_resource_url=module.params.get("vault_resource_url"),
                    key_vault_dns_suffix=module.params.get("key_vault_dns_suffix"),
                    products=module.params.get("products"),
                    description=module.params.get("description"),
                    meta=module.params.get("meta"),
                    labels=module.params.get("labels"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif module.params.get("op_type") == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=_ENDPOINT,
                resource_id=module.params.get("connection_id"),
                ignore_fields=("cloud", "connection_id"),
                patch_fn=patch,
                patch_kwargs=dict(
                    node=module.params.get("localNode"),
                    cloud=_CLOUD,
                    connection_id=module.params.get("connection_id"),
                    client_id=module.params.get("client_id"),
                    tenant_id=module.params.get("tenant_id"),
                    client_secret=module.params.get("client_secret"),
                    cloud_name=module.params.get("cloud_name"),
                    is_certificate_used=module.params.get("is_certificate_used"),
                    certificate=module.params.get("certificate"),
                    cert_duration=module.params.get("cert_duration"),
                    external_certificate_used=module.params.get("external_certificate_used"),
                    azure_stack_connection_type=module.params.get("azure_stack_connection_type"),
                    azure_stack_server_cert=module.params.get("azure_stack_server_cert"),
                    active_directory_endpoint=module.params.get("active_directory_endpoint"),
                    management_url=module.params.get("management_url"),
                    resource_manager_url=module.params.get("resource_manager_url"),
                    vault_resource_url=module.params.get("vault_resource_url"),
                    key_vault_dns_suffix=module.params.get("key_vault_dns_suffix"),
                    products=module.params.get("products"),
                    description=module.params.get("description"),
                    meta=module.params.get("meta"),
                    labels=module.params.get("labels"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
