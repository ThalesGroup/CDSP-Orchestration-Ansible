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
module: cckm_aws_custom_key_store_info
short_description: Read AWS custom key stores in CCKM
description:
    - List, filter and read the AWS custom key stores CipherTrust Cloud Key Manager (CCKM)
      manages, along with their health and their credentials.
    - This module only reads. Use M(thalesgroup.ciphertrust.cckm_aws_custom_key_store) to
      create a store or act on one.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
options:
    op_type:
      description:
        - What to read.
        - C(list) returns stores matching the filters; C(get) returns one store.
        - C(health) reports whether the store's backing key material is reachable.
        - C(list_credentials) returns the store's credentials, and C(get_credential) one
          of them. Neither returns the secret half of a credential.
      choices: [list, get, health, list_credentials, get_credential]
      default: list
      type: str
    custom_key_store_id:
      description:
        - Name or id of the custom key store to read.
        - Required for every operation except I(op_type=list).
      type: str
    credential_id:
      description:
        - Id of the credential to read.
        - Required when I(op_type=get_credential).
      type: str
    access_key_id:
      description:
        - Filter credentials by access key id.
        - Only used when I(op_type=list_credentials).
      type: str
    id:
      description:
        - Filter by store id.
      type: str
    name:
      description:
        - Filter by store name.
      type: str
    kms:
      description:
        - Filter by the name of the AWS account container.
      type: list
      elements: str
    kms_id:
      description:
        - Filter by the id of the AWS account container.
      type: list
      elements: str
    region:
      description:
        - Filter by AWS region.
      type: list
      elements: str
    cloud_name:
      description:
        - Filter by AWS partition.
      type: list
      elements: str
    type:
      description:
        - Filter by CCKM's view of the store, C(LOCAL), C(REMOTE) or C(CloudHSM).
      type: str
    custom_key_store_type:
      description:
        - Filter by AWS's kind of store.
      choices: [EXTERNAL_KEY_STORE, AWS_CLOUDHSM]
      type: str
    connection_state:
      description:
        - Filter by AWS's connection state, such as C(CONNECTED) or C(DISCONNECTED).
      type: list
      elements: str
    source_key_tier:
      description:
        - Filter by where a locally-hosted store's backing keys live.
      choices: [local, hsm-luna]
      type: str
    xks_proxy_connectivity:
      description:
        - Filter by how AWS KMS reaches the store.
      choices: [VPC_ENDPOINT_SERVICE, PUBLIC_ENDPOINT]
      type: str
    blocked:
      description:
        - Filter by whether the store is blocked.
      type: bool
    linked_state:
      description:
        - Filter by whether the store is linked with AWS.
      type: bool
    skip:
      description:
        - Number of results to skip, for paging through a long list.
      type: int
    limit:
      description:
        - Maximum number of results to return.
      type: int
    sort:
      description:
        - Comma-separated fields to sort by. Prefix a field with C(-) to sort descending.
      type: str
"""

EXAMPLES = """
- name: "List every custom key store"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: list
  register: _stores

- name: "Find the external key stores AWS cannot currently reach"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    custom_key_store_type: EXTERNAL_KEY_STORE
    connection_state:
      - DISCONNECTED

- name: "Read one store"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    custom_key_store_id: xks-production
  register: _store

- name: "Check the store is healthy"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store_info:
    localNode: "{{ cm_connection }}"
    op_type: health
    custom_key_store_id: "{{ _store.response.id }}"

- name: "List the store's credentials"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store_info:
    localNode: "{{ cm_connection }}"
    op_type: list_credentials
    custom_key_store_id: "{{ _store.response.id }}"
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
response:
    description:
      - For I(op_type=get), I(op_type=health) and I(op_type=get_credential),
        the record itself. For the list operations, a page of results under
        C(resources).
      - The secret half of a credential is never returned by CipherTrust
        Manager, so it does not appear here.
    returned: on success
    type: dict
    contains:
        total:
            description: Number of records matching the filters.
            type: int
            returned: for list-style operations
        resources:
            description: The matching records.
            type: list
            elements: dict
            returned: for list-style operations
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=["list", "get", "health", "list_credentials", "get_credential"],
        default="list",
    ),
    custom_key_store_id=dict(type="str"),
    credential_id=dict(type="str", no_log=False),
    access_key_id=dict(type="str", no_log=False),
    id=dict(type="str"),
    name=dict(type="str"),
    kms=dict(type="list", elements="str"),
    kms_id=dict(type="list", elements="str"),
    region=dict(type="list", elements="str"),
    cloud_name=dict(type="list", elements="str"),
    type=dict(type="str"),
    custom_key_store_type=dict(type="str",
                               choices=["EXTERNAL_KEY_STORE", "AWS_CLOUDHSM"]),
    connection_state=dict(type="list", elements="str"),
    source_key_tier=dict(type="str", choices=["local", "hsm-luna"], no_log=False),
    xks_proxy_connectivity=dict(type="str",
                                choices=["VPC_ENDPOINT_SERVICE", "PUBLIC_ENDPOINT"]),
    blocked=dict(type="bool"),
    linked_state=dict(type="bool"),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = ("id", "name", "kms", "kms_id", "region", "cloud_name", "type",
                 "custom_key_store_type", "connection_state", "source_key_tier",
                 "xks_proxy_connectivity", "blocked", "linked_state",
                 "skip", "limit", "sort")

_CREDENTIAL_FILTERS = ("access_key_id", "skip", "limit", "sort")


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["custom_key_store_id"]],
            ["op_type", "health", ["custom_key_store_id"]],
            ["op_type", "list_credentials", ["custom_key_store_id"]],
            ["op_type", "get_credential", ["custom_key_store_id", "credential_id"]],
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
    op_type = module.params.get("op_type")
    params = module.params

    def _filters(names):
        return {name: params.get(name) for name in names
                if params.get(name) is not None}

    # Reading changes nothing, so every operation runs unchanged under --check.
    with ciphertrust_operation(module):
        if op_type == "list":
            result["response"] = cckm_aws.custom_key_store_list(
                node=node, filters=_filters(_LIST_FILTERS))

        elif op_type == "get":
            result["response"] = cckm_aws.custom_key_store_get(
                node=node,
                custom_key_store_id=params.get("custom_key_store_id"))

        elif op_type == "health":
            result["response"] = cckm_aws.custom_key_store_health(
                node=node,
                custom_key_store_id=params.get("custom_key_store_id"))

        elif op_type == "list_credentials":
            result["response"] = cckm_aws.custom_key_store_credentials_list(
                node=node,
                custom_key_store_id=params.get("custom_key_store_id"),
                filters=_filters(_CREDENTIAL_FILTERS))

        elif op_type == "get_credential":
            result["response"] = cckm_aws.custom_key_store_credential_get(
                node=node,
                custom_key_store_id=params.get("custom_key_store_id"),
                credential_id=params.get("credential_id"))

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
