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
module: cckm_oci_issuer
short_description: Manage the OIDC issuers CCKM uses for OCI external vaults
description:
    - Registers an OIDC issuer with CCKM, updates one, or removes it.
    - An issuer validates the tokens OCI presents when it calls into an external vault,
      so one must exist before M(thalesgroup.ciphertrust.cckm_oci_vault) can create one.
    - Read issuers with M(thalesgroup.ciphertrust.cckm_oci_issuer_info).
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
        - C(create) registers an issuer.
        - C(patch) updates one.
        - C(delete) removes it.
      choices:
        - create
        - patch
        - delete
      required: true
      type: str
    issuer_id:
      description:
        - Identifier of the issuer in CCKM.
        - Required for C(patch) and C(delete).
      type: str
    name:
      description:
        - Name for the issuer.
        - Required for C(create).
      type: str
    jwks_uri_protected:
      description:
        - Whether reaching the JWKS URI needs authentication.
        - Required for C(create). When true, I(client_id) and I(client_secret) are used
          to fetch it.
      type: bool
    issuer:
      description:
        - The issuer identifier OCI's tokens carry.
      type: str
    openid_config_url:
      description:
        - OpenID configuration URL to discover the issuer's keys from.
      type: str
    jwks_uri:
      description:
        - JWKS URI to fetch the issuer's keys from.
      type: str
    client_id:
      description:
        - Client id used to fetch a protected JWKS URI.
      type: str
    client_secret:
      description:
        - Client secret used to fetch a protected JWKS URI.
        - CipherTrust Manager never returns this value, so supplying it on a patch makes
          the task report C(changed) on every run.
      type: str
    regional_jwks_uris:
      description:
        - Per-region JWKS URIs.
      type: list
      elements: str
    regional_open_id_config_urls:
      description:
        - Per-region OpenID configuration URLs.
      type: list
      elements: str
"""

EXAMPLES = """
- name: "Register an OIDC issuer for an external vault"
  thalesgroup.ciphertrust.cckm_oci_issuer:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: oci-issuer
    jwks_uri_protected: false
    openid_config_url: "https://idcs.example.com/.well-known/openid-configuration"
  register: _issuer
"""

RETURN = r"""
changed:
    description:
      - C(true) when the operation was carried out.
      - C(create) and C(patch) report accurately. C(delete) has no state to compare
        against, so it reports C(true) whenever it runs.
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
    cckm_oci,
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
argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "delete",
        ],
        required=True,
    ),
    issuer_id=dict(type="str"),
    name=dict(type="str"),
    jwks_uri_protected=dict(type="bool"),
    issuer=dict(type="str"),
    openid_config_url=dict(type="str"),
    jwks_uri=dict(type="str"),
    client_id=dict(type="str", no_log=False),
    client_secret=dict(type="str", no_log=True),
    regional_jwks_uris=dict(type="list", elements="str"),
    regional_open_id_config_urls=dict(type="list", elements="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name", "jwks_uri_protected"]],
            ["op_type", "patch", ["issuer_id"]],
            ["op_type", "delete", ["issuer_id"]],
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
        if op_type == "create":
            existing = find_resource_by_filters(
                client, cckm_oci.ISSUERS,
                filters={"name": params.get("name")},
                confirm_fields=("name",),
            )
            changed, response, diff = create_if_absent(
                module, existing,
                create_fn=cckm_oci.issuer_create,
                create_kwargs=dict(
                    node=node,
                    name=params.get("name"),
                    jwks_uri_protected=params.get("jwks_uri_protected"),
                    openid_config_url=params.get("openid_config_url"),
                    issuer=params.get("issuer"),
                    jwks_uri=params.get("jwks_uri"),
                    client_id=params.get("client_id"),
                    client_secret=params.get("client_secret"),
                    regional_jwks_uris=params.get("regional_jwks_uris"),
                    regional_open_id_config_urls=params.get(
                        "regional_open_id_config_urls"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_oci.ISSUERS,
                resource_id=params.get("issuer_id"),
                ignore_fields=("issuer_id",),
                patch_fn=cckm_oci.issuer_patch,
                patch_kwargs=dict(
                    node=node,
                    issuer_id=params.get("issuer_id"),
                    name=params.get("name"),
                    jwks_uri_protected=params.get("jwks_uri_protected"),
                    client_id=params.get("client_id"),
                    client_secret=params.get("client_secret"),
                    regional_jwks_uris=params.get("regional_jwks_uris"),
                    regional_open_id_config_urls=params.get(
                        "regional_open_id_config_urls"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff
        elif op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_oci.issuer_delete(
                node=node,
                issuer_id=params.get("issuer_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
