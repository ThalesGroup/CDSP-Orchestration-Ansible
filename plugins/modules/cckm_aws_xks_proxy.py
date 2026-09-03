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
module: cckm_aws_xks_proxy
short_description: Exercise the XKS proxy endpoints of a local custom key store
description:
    - Call the AWS External Key Store (XKS) proxy API that CipherTrust Manager serves for
      a locally-hosted custom key store.
    - AWS KMS is the intended caller of these endpoints. This module exists so an operator
      can exercise them directly -- to confirm the endpoint is reachable and the backing
      key usable before pointing AWS at it, or to diagnose a store AWS reports as
      unhealthy.
    - Create the store with M(thalesgroup.ciphertrust.cckm_aws_custom_key_store) and read
      its state with M(thalesgroup.ciphertrust.cckm_aws_custom_key_store_info).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    This is a diagnostic interface, not a general-purpose encryption module.
    For ordinary cryptographic work against CipherTrust Manager keys, use
    M(thalesgroup.ciphertrust.vault_keys2_op).
  - >-
    C(encrypt) returns ciphertext and C(decrypt) returns plaintext, both
    base64-encoded. Ansible cannot redact part of a return value, so set
    C(no_log: true) on a C(decrypt) task, or the plaintext is written to job
    output, callback plugins and any configured log or fact cache.
  - >-
    Every operation is a read in the sense that matters here -- none of them
    changes CipherTrust Manager or AWS state -- so all four run unchanged
    under C(--check) and report C(changed=false).
options:
    op_type:
      description:
        - Which XKS endpoint to call.
        - C(health) reports whether the store can serve requests; C(metadata) describes
          one key; C(encrypt) and C(decrypt) perform the operation AWS KMS would.
      choices: [health, metadata, encrypt, decrypt]
      required: true
      type: str
    keystore_id:
      description:
        - Id of the locally-hosted custom key store serving the proxy.
      required: true
      type: str
    xks_key_id:
      description:
        - Id of the key within the store, as AWS refers to it.
        - Required for every operation except I(op_type=health).
      type: str
    request_metadata:
      description:
        - The request metadata AWS KMS sends with every XKS call. CipherTrust Manager
          records it and may make access decisions on it.
      required: true
      type: dict
      suboptions:
        kms_request_id:
          description:
            - Unique id for the request. Required by the XKS specification.
          required: true
          type: str
        kms_operation:
          description:
            - The KMS operation on whose behalf the call is made, such as C(Encrypt).
          type: str
        kms_key_arn:
          description:
            - ARN of the KMS key the call relates to.
          type: str
        aws_principal_arn:
          description:
            - ARN of the AWS principal the call is made for.
          type: str
        aws_source_vpc:
          description:
            - VPC the call originates from.
          type: str
        aws_source_vpce:
          description:
            - VPC endpoint the call originates from.
          type: str
        kms_via_service:
          description:
            - AWS service making the call on a customer's behalf, such as C(ebs).
          type: str
    plaintext:
      description:
        - Base64-encoded data to encrypt.
        - Required when I(op_type=encrypt).
      type: str
    ciphertext:
      description:
        - Base64-encoded data to decrypt.
        - Required when I(op_type=decrypt).
      type: str
    encryption_algorithm:
      description:
        - Algorithm to use, as named by the XKS specification -- for example
          C(AES_GCM_256).
        - Required when I(op_type=encrypt) or I(op_type=decrypt).
      type: str
    additional_authenticated_data:
      description:
        - Base64-encoded additional authenticated data (AAD).
        - Must match between the encrypt and the decrypt.
      type: str
    initialization_vector:
      description:
        - Base64-encoded initialization vector, as returned by the encrypt.
        - Required when I(op_type=decrypt).
      type: str
    authentication_tag:
      description:
        - Base64-encoded authentication tag, as returned by the encrypt.
        - Required when I(op_type=decrypt).
      type: str
    ciphertext_data_integrity_value_algorithm:
      description:
        - Algorithm for the ciphertext data integrity value, such as C(SHA_256).
        - Only used when I(op_type=encrypt).
      type: str
"""

EXAMPLES = """
- name: "Check the XKS proxy is healthy"
  thalesgroup.ciphertrust.cckm_aws_xks_proxy:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: health
    keystore_id: "{{ keystore_id }}"
    request_metadata:
      kms_request_id: "{{ 999999999999 | random | to_uuid }}"
      kms_operation: CreateCustomKeyStore

- name: "Describe a key in the store"
  thalesgroup.ciphertrust.cckm_aws_xks_proxy:
    localNode: "{{ cm_connection }}"
    op_type: metadata
    keystore_id: "{{ keystore_id }}"
    xks_key_id: "{{ xks_key_id }}"
    request_metadata:
      kms_request_id: "{{ 999999999999 | random | to_uuid }}"
      kms_operation: DescribeKey

- name: "Encrypt through the proxy, as AWS KMS would"
  thalesgroup.ciphertrust.cckm_aws_xks_proxy:
    localNode: "{{ cm_connection }}"
    op_type: encrypt
    keystore_id: "{{ keystore_id }}"
    xks_key_id: "{{ xks_key_id }}"
    plaintext: "ZW5jcnlwdA=="
    encryption_algorithm: AES_GCM_256
    request_metadata:
      kms_request_id: "{{ 999999999999 | random | to_uuid }}"
      kms_operation: Encrypt
  register: _encrypted

- name: "Decrypt it again"
  thalesgroup.ciphertrust.cckm_aws_xks_proxy:
    localNode: "{{ cm_connection }}"
    op_type: decrypt
    keystore_id: "{{ keystore_id }}"
    xks_key_id: "{{ xks_key_id }}"
    ciphertext: "{{ _encrypted.response.ciphertext }}"
    encryption_algorithm: AES_GCM_256
    initialization_vector: "{{ _encrypted.response.initializationVector }}"
    authentication_tag: "{{ _encrypted.response.authenticationTag }}"
    request_metadata:
      kms_request_id: "{{ 999999999999 | random | to_uuid }}"
      kms_operation: Decrypt
  no_log: true
"""

RETURN = r"""
changed:
    description: Always C(false). None of these operations changes state.
    returned: always
    type: bool
    sample: false
response:
    description:
      - The raw response dictionary from the XKS proxy endpoint. For
        I(op_type=encrypt) it holds the ciphertext, initialization vector and
        authentication tag; for I(op_type=decrypt), the plaintext.
      - A C(decrypt) response contains plaintext. Set C(no_log) to C(true) on
        the task, or it is written to job output and any configured log.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws

_request_metadata = dict(
    kms_request_id=dict(type="str", required=True),
    kms_operation=dict(type="str"),
    kms_key_arn=dict(type="str", no_log=False),
    aws_principal_arn=dict(type="str"),
    aws_source_vpc=dict(type="str"),
    aws_source_vpce=dict(type="str"),
    kms_via_service=dict(type="str"),
)

# The XKS specification names these fields in camelCase, and the endpoint
# accepts nothing else. The module spells them snake_case, as every other
# option in this collection is spelled.
_METADATA_MAP = {
    "kms_request_id": "kmsRequestId",
    "kms_operation": "kmsOperation",
    "kms_key_arn": "kmsKeyArn",
    "aws_principal_arn": "awsPrincipalArn",
    "aws_source_vpc": "awsSourceVpc",
    "aws_source_vpce": "awsSourceVpce",
    "kms_via_service": "kmsViaService",
}

argument_spec = dict(
    op_type=dict(type="str",
                 choices=["health", "metadata", "encrypt", "decrypt"],
                 required=True),
    keystore_id=dict(type="str", required=True),
    xks_key_id=dict(type="str", no_log=False),
    request_metadata=dict(type="dict", options=_request_metadata, required=True),
    plaintext=dict(type="str", no_log=True),
    ciphertext=dict(type="str"),
    encryption_algorithm=dict(type="str"),
    additional_authenticated_data=dict(type="str"),
    initialization_vector=dict(type="str"),
    authentication_tag=dict(type="str", no_log=False),
    ciphertext_data_integrity_value_algorithm=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "metadata", ["xks_key_id"]],
            ["op_type", "encrypt",
             ["xks_key_id", "plaintext", "encryption_algorithm"]],
            ["op_type", "decrypt",
             ["xks_key_id", "ciphertext", "encryption_algorithm",
              "initialization_vector", "authentication_tag"]],
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

    metadata = cckm_aws.prune(
        cckm_aws.remap_keys(params.get("request_metadata"), _METADATA_MAP)
    )

    # None of these changes CipherTrust Manager or AWS state, so all four run
    # unchanged under --check.
    with ciphertrust_operation(module):
        if op_type == "health":
            result["response"] = cckm_aws.xks_health(
                node=node,
                keystore_id=params.get("keystore_id"),
                request_metadata=metadata,
            )

        elif op_type == "metadata":
            result["response"] = cckm_aws.xks_key_metadata(
                node=node,
                keystore_id=params.get("keystore_id"),
                xks_key_id=params.get("xks_key_id"),
                request_metadata=metadata,
            )

        elif op_type == "encrypt":
            result["response"] = cckm_aws.xks_encrypt(
                node=node,
                keystore_id=params.get("keystore_id"),
                xks_key_id=params.get("xks_key_id"),
                plaintext=params.get("plaintext"),
                encryption_algorithm=params.get("encryption_algorithm"),
                request_metadata=metadata,
                additional_authenticated_data=params.get(
                    "additional_authenticated_data"),
                ciphertext_data_integrity_value_algorithm=params.get(
                    "ciphertext_data_integrity_value_algorithm"),
            )

        elif op_type == "decrypt":
            result["response"] = cckm_aws.xks_decrypt(
                node=node,
                keystore_id=params.get("keystore_id"),
                xks_key_id=params.get("xks_key_id"),
                ciphertext=params.get("ciphertext"),
                encryption_algorithm=params.get("encryption_algorithm"),
                initialization_vector=params.get("initialization_vector"),
                authentication_tag=params.get("authentication_tag"),
                request_metadata=metadata,
                additional_authenticated_data=params.get(
                    "additional_authenticated_data"),
            )

        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
