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
module: cckm_aws_key_info
short_description: Read AWS KMS keys known to CCKM
description:
    - List, filter and read the AWS KMS keys CipherTrust Cloud Key Manager (CCKM) knows
      about, along with their versions and rotation history.
    - This module only reads. Use M(thalesgroup.ciphertrust.cckm_aws_key) to create keys
      or act on them.
    - CCKM reports the keys it has recorded. A key created outside CCKM appears only after
      a synchronization job has run; see
      M(thalesgroup.ciphertrust.cckm_aws_synchronization_job).
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
        - C(list) returns keys matching the filters; C(get) returns one key by its CCKM
          id; C(versions) and C(rotations) return a key's version and rotation history.
      choices: [list, get, versions, rotations]
      default: list
      type: str
    key_id:
      description:
        - CCKM's id for the key.
        - Required for every operation except I(op_type=list).
      type: str
    id:
      description:
        - Filter by CCKM's internal id.
      type: str
    keyid:
      description:
        - Filter by the AWS key id.
      type: str
    arn:
      description:
        - Filter by the AWS key ARN.
      type: str
    alias:
      description:
        - Filter by key alias.
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
    origin:
      description:
        - Filter by key origin, such as C(AWS_KMS) or C(EXTERNAL).
      type: list
      elements: str
    keystate:
      description:
        - Filter by AWS key state, such as C(Enabled) or C(PendingDeletion).
      type: list
      elements: str
    keyusage:
      description:
        - Filter by what the key may be used for.
      type: list
      elements: str
    keymanager:
      description:
        - Filter by key manager, C(CUSTOMER) or C(AWS).
      type: list
      elements: str
    customer_master_key_spec:
      description:
        - Filter by key spec, such as C(SYMMETRIC_DEFAULT) or C(RSA_4096).
      type: list
      elements: str
    key_material_origin:
      description:
        - Filter by where the key material came from.
      type: list
      elements: str
    key_source:
      description:
        - Filter by the key source uploaded material came from.
      type: list
      elements: str
    multi_region:
      description:
        - Filter by whether the key is multi-region.
      type: list
      elements: bool
    multi_region_key_type:
      description:
        - Filter by C(PRIMARY) or C(REPLICA).
      type: list
      elements: str
    custom_key_store_id:
      description:
        - Filter by the id of the custom key store holding the key.
      type: list
      elements: str
    custom_key_store_name:
      description:
        - Filter by the name of the custom key store holding the key.
      type: list
      elements: str
    enabled:
      description:
        - Filter by whether the key is enabled.
      type: bool
    gone:
      description:
        - Filter by whether the key has been deleted in AWS but is still recorded here.
      type: bool
    blocked:
      description:
        - Filter by whether a HYOK key is blocked.
      type: bool
    rotation_job_enabled:
      description:
        - Filter by whether CCKM's scheduled rotation is enabled for the key.
      type: bool
    job_config_id:
      description:
        - Filter by the id of the scheduler configuration rotating the key.
      type: str
    cckm_policy_template_id:
      description:
        - Filter by the id of the policy template applied to the key.
      type: str
    tags:
      description:
        - 'Filter by tag, as a JSON object -- for example: {"environment": "production"}.'
      type: str
    import_state:
      description:
        - Filter rotations by import state.
        - Only used when I(op_type=rotations).
      type: str
    key_material_state:
      description:
        - Filter rotations by key material state.
        - Only used when I(op_type=rotations).
      type: list
      elements: str
    rotation_type:
      description:
        - Filter rotations by rotation type.
        - Only used when I(op_type=rotations).
      type: str
    key_material_id:
      description:
        - Filter rotations by key material id.
        - Only used when I(op_type=rotations).
      type: str
    skip:
      description:
        - Number of results to skip, for paging through a long list.
      type: int
    limit:
      description:
        - Maximum number of results to return.
        - CipherTrust Manager applies its own default and maximum.
      type: int
    sort:
      description:
        - Comma-separated fields to sort by. Prefix a field with C(-) to sort descending.
      type: str
"""

EXAMPLES = """
- name: "List every AWS key CCKM knows about"
  thalesgroup.ciphertrust.cckm_aws_key_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: list
  register: _keys

- name: "Find the enabled keys in two regions of one account"
  thalesgroup.ciphertrust.cckm_aws_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    kms:
      - aws-production
    region:
      - us-east-1
      - eu-west-1
    enabled: true

- name: "Look up a key by its alias"
  thalesgroup.ciphertrust.cckm_aws_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    alias: payments-encryption
  register: _key

- name: "Read one key in full"
  thalesgroup.ciphertrust.cckm_aws_key_info:
    localNode: "{{ cm_connection }}"
    op_type: get
    key_id: "{{ _key.response.resources[0].id }}"

- name: "Find keys scheduled for deletion"
  thalesgroup.ciphertrust.cckm_aws_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    keystate:
      - PendingDeletion

- name: "Read a key's rotation history"
  thalesgroup.ciphertrust.cckm_aws_key_info:
    localNode: "{{ cm_connection }}"
    op_type: rotations
    key_id: "{{ _key.response.resources[0].id }}"
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
response:
    description:
      - For I(op_type=get), the key. For every other operation, a page of
        results under C(resources).
    returned: on success
    type: dict
    contains:
        total:
            description: Number of records matching the filters.
            type: int
            returned: for list-style operations
        skip:
            description: Number of records skipped.
            type: int
            returned: for list-style operations
        limit:
            description: Maximum number of records this page holds.
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
    op_type=dict(type="str", choices=["list", "get", "versions", "rotations"],
                 default="list"),
    key_id=dict(type="str", no_log=False),
    id=dict(type="str"),
    keyid=dict(type="str", no_log=False),
    arn=dict(type="str"),
    alias=dict(type="str"),
    kms=dict(type="list", elements="str"),
    kms_id=dict(type="list", elements="str"),
    region=dict(type="list", elements="str"),
    cloud_name=dict(type="list", elements="str"),
    origin=dict(type="list", elements="str"),
    keystate=dict(type="list", elements="str", no_log=False),
    keyusage=dict(type="list", elements="str"),
    keymanager=dict(type="list", elements="str", no_log=False),
    customer_master_key_spec=dict(type="list", elements="str", no_log=False),
    key_material_origin=dict(type="list", elements="str", no_log=False),
    key_source=dict(type="list", elements="str", no_log=False),
    multi_region=dict(type="list", elements="bool"),
    multi_region_key_type=dict(type="list", elements="str", no_log=False),
    custom_key_store_id=dict(type="list", elements="str"),
    custom_key_store_name=dict(type="list", elements="str"),
    enabled=dict(type="bool"),
    gone=dict(type="bool"),
    blocked=dict(type="bool"),
    rotation_job_enabled=dict(type="bool"),
    job_config_id=dict(type="str"),
    cckm_policy_template_id=dict(type="str"),
    tags=dict(type="str"),
    import_state=dict(type="str"),
    key_material_state=dict(type="list", elements="str", no_log=False),
    rotation_type=dict(type="str"),
    key_material_id=dict(type="str", no_log=False),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["key_id"]],
            ["op_type", "versions", ["key_id"]],
            ["op_type", "rotations", ["key_id"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


# The list filters, and the query parameter each is sent as. The API spells a
# few of them differently from the way this collection spells options
# elsewhere, so the mapping is explicit rather than derived.
_LIST_FILTERS = {
    "id": "id",
    "keyid": "keyid",
    "arn": "arn",
    "alias": "alias",
    "kms": "kms",
    "kms_id": "kms_id",
    "region": "region",
    "cloud_name": "cloud_name",
    "origin": "origin",
    "keystate": "keystate",
    "keyusage": "keyusage",
    "keymanager": "keymanager",
    "customer_master_key_spec": "CustomerMasterKeySpec",
    "key_material_origin": "key_material_origin",
    "key_source": "key_source",
    "multi_region": "multi_region",
    "multi_region_key_type": "multi_region_key_type",
    "custom_key_store_id": "custom_key_store_id",
    "custom_key_store_name": "custom_key_store_name",
    "enabled": "enabled",
    "gone": "gone",
    "blocked": "blocked",
    "rotation_job_enabled": "rotation_job_enabled",
    "job_config_id": "job_config_id",
    "cckm_policy_template_id": "cckm_policy_template_id",
    "tags": "tags",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}

_ROTATION_FILTERS = {
    "key_source": "key_source",
    "key_material_origin": "key_material_origin",
    "import_state": "ImportState",
    "key_material_state": "KeyMaterialState",
    "rotation_type": "RotationType",
    "key_material_id": "KeyMaterialId",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}

_PAGING_FILTERS = {"skip": "skip", "limit": "limit", "sort": "sort"}


def _filters(params, mapping):
    return {query: params.get(name) for name, query in mapping.items()
            if params.get(name) is not None}


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    node = module.params.get("localNode")
    op_type = module.params.get("op_type")
    params = module.params

    # Reading changes nothing, so every operation runs unchanged under --check.
    with ciphertrust_operation(module):
        if op_type == "list":
            result["response"] = cckm_aws.key_list(
                node=node, filters=_filters(params, _LIST_FILTERS))

        elif op_type == "get":
            result["response"] = cckm_aws.key_get(
                node=node, key_id=params.get("key_id"))

        elif op_type == "versions":
            result["response"] = cckm_aws.key_versions(
                node=node, key_id=params.get("key_id"),
                filters=_filters(params, _PAGING_FILTERS))

        elif op_type == "rotations":
            result["response"] = cckm_aws.key_rotations(
                node=node, key_id=params.get("key_id"),
                filters=_filters(params, _ROTATION_FILTERS))

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
