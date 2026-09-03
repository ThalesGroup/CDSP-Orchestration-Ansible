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
module: cckm_aws_cloudhsm_cluster_info
short_description: List AWS CloudHSM clusters available to back a custom key store
description:
    - List the active AWS CloudHSM clusters in a region that are not already backing a
      custom key store.
    - A CloudHSM cluster can back only one custom key store, so this is the set of
      clusters a new C(AWS_CLOUDHSM) store may be created against. Pass one of the ids
      returned here as I(aws_param.cloud_hsm_cluster_id) to
      M(thalesgroup.ciphertrust.cckm_aws_custom_key_store).
    - This module only reads. Nothing is created or changed, in CipherTrust Manager or in
      AWS.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    The lookup reaches AWS from the CipherTrust Manager itself, so it needs
    the manager to have network egress and the account container's credentials
    to be valid.
options:
    kms:
      description:
        - Name or id of the AWS account container to look through.
      required: true
      type: str
    region:
      description:
        - AWS region to list CloudHSM clusters from.
      required: true
      type: str
"""

EXAMPLES = """
- name: "Find a CloudHSM cluster to back a new key store"
  thalesgroup.ciphertrust.cckm_aws_cloudhsm_cluster_info:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    kms: aws-production
    region: us-east-1
  register: _clusters

- name: "Create the key store against it"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: cloudhsm-production
    kms: aws-production
    region: us-east-1
    aws_param:
      custom_key_store_type: AWS_CLOUDHSM
      cloud_hsm_cluster_id: "{{ _clusters.response.clusters[0].ClusterId }}"
      key_store_password: "{{ vault_kmsuser_password }}"
      trust_anchor_certificate: "{{ lookup('file', 'customerCA.crt') }}"
  when: _clusters.response.clusters | default([]) | length > 0
"""

RETURN = r"""
changed:
    description: Always C(false). This module only reads.
    returned: always
    type: bool
    sample: false
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, holding
        the CloudHSM clusters as AWS describes them.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws

argument_spec = dict(
    kms=dict(type="str", required=True),
    region=dict(type="str", required=True),
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

    # Listing clusters reads AWS and changes nothing, so it runs unchanged
    # under --check.
    with ciphertrust_operation(module):
        result["response"] = cckm_aws.unused_cloudhsm_clusters(
            node=module.params.get("localNode"),
            kms=module.params.get("kms"),
            region=module.params.get("region"),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
