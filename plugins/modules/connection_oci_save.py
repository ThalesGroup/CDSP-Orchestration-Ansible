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
module: connection_oci_save
short_description: Manage OCI connections in CipherTrust Manager's connection manager
description:
    - Create or update an Oracle Cloud Infrastructure connection in the CipherTrust
      Manager connection manager.
    - An OCI connection stores the API signing key CipherTrust Manager uses to reach an
      OCI tenancy.
    - Delete a connection with M(thalesgroup.ciphertrust.cm_resource_delete) using
      I(resource_type=oci-connection), and test one with
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
    user_ocid:
      description:
        - OCID of the user the API key belongs to.
        - Required when I(op_type=create).
      type: str
    tenancy_ocid:
      description:
        - OCID of the tenancy.
        - Required when I(op_type=create).
      type: str
    fingerprint:
      description:
        - Fingerprint of the public key added to the user.
        - Required when I(op_type=create).
      type: str
    region:
      description:
        - Oracle Cloud Infrastructure region, for example C(us-ashburn-1).
        - Required when I(op_type=create).
      type: str
    credentials:
      description:
        - API signing key for the connection.
        - Required when I(op_type=create).
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
"""

EXAMPLES = """
- name: "Create an OCI connection"
  thalesgroup.ciphertrust.connection_oci_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: oci-production
    description: "Production OCI tenancy"
    user_ocid: "ocid1.user.oc1..aaaaaaaa"
    tenancy_ocid: "ocid1.tenancy.oc1..bbbbbbbb"
    fingerprint: "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34"
    region: us-ashburn-1
    credentials:
      key_file: "{{ lookup('file', 'oci_api_key.pem') }}"
      pass_phrase: "{{ vault_oci_key_passphrase }}"

- name: "Update the description of an OCI connection"
  thalesgroup.ciphertrust.connection_oci_save:
    localNode: "{{ cm_connection }}"
    op_type: patch
    connection_id: oci-production
    description: "Production OCI tenancy (Ashburn)"
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

_CLOUD = "oci"
_ENDPOINT = "connectionmgmt/services/oci/connections"

_credentials = dict(
    key_file=dict(type="str", no_log=True),
    pass_phrase=dict(type="str", no_log=True),
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    connection_id=dict(type="str"),
    name=dict(type="str"),
    user_ocid=dict(type="str"),
    tenancy_ocid=dict(type="str"),
    fingerprint=dict(type="str"),
    region=dict(type="str"),
    credentials=dict(type="dict", options=_credentials),
    products=dict(type="list", elements="str"),
    description=dict(type="str"),
    meta=dict(type="dict"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["connection_id"]],
            ["op_type", "create", ["name", "credentials", "fingerprint", "region", "tenancy_ocid", "user_ocid"]],
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
                    user_ocid=module.params.get("user_ocid"),
                    tenancy_ocid=module.params.get("tenancy_ocid"),
                    fingerprint=module.params.get("fingerprint"),
                    region=module.params.get("region"),
                    credentials=module.params.get("credentials"),
                    products=module.params.get("products"),
                    description=module.params.get("description"),
                    meta=module.params.get("meta"),
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
                    user_ocid=module.params.get("user_ocid"),
                    tenancy_ocid=module.params.get("tenancy_ocid"),
                    fingerprint=module.params.get("fingerprint"),
                    region=module.params.get("region"),
                    credentials=module.params.get("credentials"),
                    products=module.params.get("products"),
                    description=module.params.get("description"),
                    meta=module.params.get("meta"),
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
