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
module: cckm_azure_certificate
short_description: Manage Azure Key Vault certificates through CCKM
description:
    - Creates a certificate in an Azure key vault, imports an existing one, updates a
      certificate, and drives the Azure soft-delete lifecycle.
    - Read certificates with M(thalesgroup.ciphertrust.cckm_azure_certificate_info).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) creates a certificate from a policy; C(import) uploads an existing
          certificate and its private key.
        - C(patch) updates attributes and tags.
        - C(delete) removes the CCKM record; C(soft_delete), C(recover), C(hard_delete)
          and C(restore) drive the Azure lifecycle.
      choices:
        - create
        - import
        - patch
        - delete
        - soft_delete
        - hard_delete
        - recover
        - restore
      required: true
      type: str
    certificate_id:
      description:
        - Identifier of the certificate in CCKM.
        - Required for every operation except C(create) and C(import).
      type: str
    cert_name:
      description:
        - Name for the certificate in Azure.
        - Azure certificate names accept alphanumerics and hyphens only.
        - Required for C(create) and C(import).
      type: str
    key_vault:
      description:
        - Name or id of the Azure vault.
        - Required for C(create) and C(import).
      type: str
    azure_param:
      description:
        - Azure certificate parameters.
        - Required for C(create).
      type: dict
      suboptions:
        policy:
          description:
            - Azure certificate policy -- issuer, key properties and X.509 properties.
            - Required when creating a certificate.
          type: dict
        tags:
          description:
            - Azure tags to set on the certificate.
          type: dict
    caid:
      description:
        - Identifier of the CipherTrust Manager CA to import from.
      type: str
    source_cert_identifier:
      description:
        - Identifier of the certificate to import from CipherTrust Manager.
      type: str
    private_key_pem:
      description:
        - PEM-encoded private key to import.
        - CipherTrust Manager never returns this value.
      type: str
    certificate:
      description:
        - PEM-encoded certificate to import.
      type: str
    password:
      description:
        - Password protecting the imported private key.
      type: str
    attributes:
      description:
        - Azure certificate attributes to update. Used by C(patch).
      type: dict
      suboptions:
        enabled:
          description:
            - Whether the object is enabled.
          type: bool
        nbf:
          description:
            - Not-before time, as an Azure timestamp.
          type: str
        exp:
          description:
            - Expiry time, as an Azure timestamp.
          type: str
    tags:
      description:
        - Azure tags to set. Used by C(patch).
      type: dict
"""

EXAMPLES = """
- name: "Import an existing certificate into an Azure vault"
  thalesgroup.ciphertrust.cckm_azure_certificate:
    localNode: "{{ cm_connection }}"
    op_type: import
    cert_name: web-tls
    key_vault: production-vault
    certificate: "{{ lookup('file', 'web.crt') }}"
    private_key_pem: "{{ lookup('file', 'web.key') }}"

- name: "Soft-delete the certificate"
  thalesgroup.ciphertrust.cckm_azure_certificate:
    localNode: "{{ cm_connection }}"
    op_type: soft_delete
    certificate_id: "{{ _cert.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(create), C(import) and C(patch) report accurately; the lifecycle operations
        report C(true) whenever they run.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing resource when one was found during a GET-before-write
        idempotency check.
    returned: when the operation returns a body
    type: dict
diff:
    description: Present only in C(--diff) mode when a change occurred.
    returned: when diff mode is enabled and the module made a change
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_azure,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
    create_if_absent,
    find_resource_by_filters,
    idempotent_patch,
)
_azure_param = dict(
    policy=dict(type="dict"),
    tags=dict(type="dict"),
)

_attributes = dict(
    enabled=dict(type="bool"),
    nbf=dict(type="str"),
    exp=dict(type="str"),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "import",
            "patch",
            "delete",
            "soft_delete",
            "hard_delete",
            "recover",
            "restore",
        ],
        required=True,
    ),
    certificate_id=dict(type="str"),
    cert_name=dict(type="str"),
    key_vault=dict(type="str", no_log=False),
    azure_param=dict(type="dict", options=_azure_param),
    caid=dict(type="str"),
    source_cert_identifier=dict(type="str"),
    private_key_pem=dict(type="str", no_log=True),
    certificate=dict(type="str"),
    password=dict(type="str", no_log=True),
    attributes=dict(type="dict", options=_attributes),
    tags=dict(type="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["cert_name", "key_vault", "azure_param"]],
            ["op_type", "import", ["cert_name", "key_vault"]],
            ["op_type", "patch", ["certificate_id"]],
            ["op_type", "delete", ["certificate_id"]],
            ["op_type", "soft_delete", ["certificate_id"]],
            ["op_type", "hard_delete", ["certificate_id"]],
            ["op_type", "recover", ["certificate_id"]],
            ["op_type", "restore", ["certificate_id"]],
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

    node = module.params.get("localNode")
    params = module.params
    op_type = params.get("op_type")
    client = CipherTrustClient(node)

    with ciphertrust_operation(module):
        if op_type in (
                "create", "import"):
            existing = None
            if params.get("cert_name"):
                existing = find_resource_by_filters(
                    client, cckm_azure.CERTIFICATES,
                    filters={"cert_name": params.get("cert_name"),
                             "key_vault": params.get("key_vault")},
                    confirm_fields=("key_vault",),
                )
            if op_type == "create":
                create_fn = cckm_azure.certificate_create
                create_kwargs = dict(
                    node=node,
                    cert_name=params.get("cert_name"),
                    key_vault=params.get("key_vault"),
                    azure_param=params.get("azure_param"),
                )
            else:
                create_fn = cckm_azure.certificate_import
                create_kwargs = dict(
                    node=node,
                    cert_name=params.get("cert_name"),
                    key_vault=params.get("key_vault"),
                    caid=params.get("caid"),
                    source_cert_identifier=params.get("source_cert_identifier"),
                    private_key_pem=params.get("private_key_pem"),
                    certificate=params.get("certificate"),
                    password=params.get("password"),
                    azure_param=params.get("azure_param"),
                )
            changed, response, diff = create_if_absent(
                module, existing, create_fn=create_fn,
                create_kwargs=create_kwargs)
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_azure.CERTIFICATES,
                resource_id=params.get("certificate_id"),
                ignore_fields=("certificate_id",),
                patch_fn=cckm_azure.certificate_patch,
                patch_kwargs=dict(
                    node=node,
                    certificate_id=params.get("certificate_id"),
                    attributes=params.get("attributes"),
                    tags=params.get("tags"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_azure.certificate_delete(
                node=node,
                certificate_id=params.get("certificate_id"),
            )
            result["changed"] = True
        elif op_type in (
                "soft_delete", "hard_delete", "recover", "restore"):
            check_mode_action(module)
            result["response"] = cckm_azure.certificate_action(
                node=node,
                certificate_id=params.get("certificate_id"),
                action=op_type.replace("_", "-"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
