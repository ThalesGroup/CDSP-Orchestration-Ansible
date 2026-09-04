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
module: cckm_gcp_key_info
short_description: Read Cloud KMS keys, their versions and their IAM policy from CCKM
description:
    - Lists or reads the Cloud KMS keys CCKM manages, lists and reads their versions,
      and reads a key's IAM policy.
    - Google Cloud puts key material in versions, so a key's state is largely the state
      of its versions.
    - Create or act on a key with M(thalesgroup.ciphertrust.cckm_gcp_key).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description:
        - Which read to perform.
        - C(list) and C(get) read keys.
        - C(list_versions) and C(get_version) read the versions of one key.
        - C(get_policy) reads the key's IAM policy.
      choices: [list, get, list_versions, get_version, get_policy]
      default: list
      type: str
    key_id:
      description:
        - Identifier of the key in CCKM.
      type: str
    version_id:
      description:
        - Identifier of the key version.
      type: str
    id:
      description:
        - Filter by CCKM resource id.
      type: str
    name:
      description:
        - Filter by key name.
      type: str
    key_ring_id:
      description:
        - Filter by key ring.
      type: str
    location_id:
      description:
        - Filter by Cloud KMS location.
      type: str
    project_id:
      description:
        - Filter by Google Cloud project id.
      type: str
    create_status:
      description:
        - Filter by creation status.
      type: str
    organization_name:
      description:
        - Filter by organisation name.
      type: str
    organization_display_name:
      description:
        - Filter by organisation display name.
      type: str
    purpose:
      description:
        - Filter by key purpose.
      type: str
    algorithm:
      description:
        - Filter by key algorithm.
      type: str
    protection_level:
      description:
        - Filter by protection level.
      type: str
    job_config_id:
      description:
        - Filter by rotation job configuration id.
      type: str
    state:
      description:
        - Filter by key state.
      type: str
    rotation_job_enabled:
      description:
        - Filter by rotation job state.
      type: bool
    labels:
      description:
        - Filter by label.
      type: list
      elements: str
    version:
      description:
        - Filter versions by version number.
      type: str
    is_primary:
      description:
        - Filter versions by whether they are primary.
      type: bool
    deleted:
      description:
        - Filter versions by whether they are deleted.
      type: bool
    gone:
      description:
        - Filter versions no longer present in Google Cloud.
      type: bool
    key_material_origin:
      description:
        - Filter versions by where the material came from.
      type: str
    skip:
      description:
        - Number of records to skip.
      type: int
    limit:
      description:
        - Maximum number of records to return.
      type: int
    sort:
      description:
        - Comma-separated fields to sort by.
      type: str
"""

EXAMPLES = """
- name: "List the keys in one key ring"
  thalesgroup.ciphertrust.cckm_gcp_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list
    key_ring_id: "{{ _ring.response.id }}"

- name: "List the versions of a key"
  thalesgroup.ciphertrust.cckm_gcp_key_info:
    localNode: "{{ cm_connection }}"
    op_type: list_versions
    key_id: "{{ _key.response.id }}"

- name: "Read a key's IAM policy"
  thalesgroup.ciphertrust.cckm_gcp_key_info:
    localNode: "{{ cm_connection }}"
    op_type: get_policy
    key_id: "{{ _key.response.id }}"
"""

RETURN = r"""
changed:
    description: Always C(false). These operations only read.
    returned: always
    type: bool
    sample: false
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API.
      - A list operation returns a C(resources) array with C(skip), C(limit)
        and C(total); a get returns the resource itself.
    returned: always
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_gcp,
)

_VERSION_FILTERS = {
    "version_id": "version_id",
    "version": "version",
    "name": "name",
    "state": "state",
    "algorithm": "algorithm",
    "is_primary": "is_primary",
    "deleted": "deleted",
    "gone": "gone",
    "key_material_origin": "key_material_origin",
    "skip": "skip",
    "limit": "limit",
}

argument_spec = dict(
    op_type=dict(type="str", choices=["list", "get", "list_versions", "get_version", "get_policy"], default="list"),
    key_id=dict(type="str", no_log=False),
    version_id=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="str"),
    key_ring_id=dict(type="str", no_log=False),
    location_id=dict(type="str"),
    project_id=dict(type="str"),
    create_status=dict(type="str"),
    organization_name=dict(type="str"),
    organization_display_name=dict(type="str"),
    purpose=dict(type="str"),
    algorithm=dict(type="str"),
    protection_level=dict(type="str"),
    job_config_id=dict(type="str"),
    state=dict(type="str"),
    rotation_job_enabled=dict(type="bool"),
    labels=dict(type="list", elements="str"),
    version=dict(type="str"),
    is_primary=dict(type="bool"),
    deleted=dict(type="bool"),
    gone=dict(type="bool"),
    key_material_origin=dict(type="str", no_log=False),
    skip=dict(type="int"),
    limit=dict(type="int"),
    sort=dict(type="str"),
)

_LIST_FILTERS = {
    "id": "id",
    "name": "name",
    "key_id": "key_id",
    "key_ring_id": "key_ring_id",
    "location_id": "location_id",
    "project_id": "project_id",
    "create_status": "create_status",
    "organization_name": "organization_name",
    "organization_display_name": "organization_display_name",
    "purpose": "purpose",
    "algorithm": "algorithm",
    "protection_level": "protection_level",
    "job_config_id": "job_config_id",
    "state": "state",
    "rotation_job_enabled": "rotation_job_enabled",
    "labels": "labels",
    "skip": "skip",
    "limit": "limit",
    "sort": "sort",
}


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "get", ["key_id"]],
            ["op_type", "list_versions", ["key_id"]],
            ["op_type", "get_version", ["key_id", "version_id"]],
            ["op_type", "get_policy", ["key_id"]],
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

    # Reading changes nothing, so every operation runs unchanged under --check.
    with ciphertrust_operation(module):
        if op_type == "list":
            result["response"] = cckm_gcp.key_list(
                node=node,
                filters={api: module.params.get(name)
                         for name, api in _LIST_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get":
            result["response"] = cckm_gcp.key_get(
                node=node,
                key_id=module.params.get("key_id"),
            )
        elif op_type == "list_versions":
            result["response"] = cckm_gcp.key_version_list(
                node=node,
                key_id=module.params.get("key_id"),
                filters={api: module.params.get(name)
                         for name, api in _VERSION_FILTERS.items()
                         if module.params.get(name) is not None},
            )
        elif op_type == "get_version":
            result["response"] = cckm_gcp.key_version_get(
                node=node,
                key_id=module.params.get("key_id"),
                version_id=module.params.get("version_id"),
            )
        elif op_type == "get_policy":
            result["response"] = cckm_gcp.key_policy_get(
                node=node,
                key_id=module.params.get("key_id"),
            )
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
