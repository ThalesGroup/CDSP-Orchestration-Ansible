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
module: cckm_aws_custom_key_store
short_description: Manage AWS custom key stores in CCKM
description:
    - Create, update and operate the AWS custom key stores that CipherTrust Cloud Key
      Manager (CCKM) manages.
    - A custom key store holds AWS KMS keys whose material lives outside AWS. Two kinds
      exist. An C(AWS_CLOUDHSM) store is backed by an AWS CloudHSM cluster. An
      C(EXTERNAL_KEY_STORE) (XKS) is backed by CipherTrust Manager itself or by a Luna
      HSM, with AWS KMS reaching it over the XKS proxy interface CipherTrust Manager
      serves.
    - Create keys inside a CloudHSM store with M(thalesgroup.ciphertrust.cckm_aws_key)
      using I(op_type=create_in_custom_key_store), and inside a local store using
      I(op_type=create_hyok).
    - Read state with M(thalesgroup.ciphertrust.cckm_aws_custom_key_store_info), and
      delete a store with M(thalesgroup.ciphertrust.cm_resource_delete) using
      I(resource_type=aws-custom-key-store).
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.partial_diff
notes:
  - >-
    Only C(create) and C(patch) converge on a desired state. The rest act on a
    store that already exists and report C(changed) on every run.
  - >-
    C(connect) can take several minutes on a CloudHSM-backed store, and AWS
    reports the outcome asynchronously. A successful task means AWS accepted
    the request; poll the store's C(connection_state) with
    M(thalesgroup.ciphertrust.cckm_aws_custom_key_store_info) to see the
    result.
  - >-
    C(disconnect) makes every key in the store unusable until it is
    reconnected. C(block) has the same effect for a locally-hosted store, but
    is served by CipherTrust Manager rather than AWS.
options:
    op_type:
      description:
        - Operation to perform.
        - C(create) and C(patch) manage the store's definition.
        - C(connect) and C(disconnect) control whether AWS KMS can reach the store's
          backing key material; C(block) and C(unblock) do the same at the CipherTrust
          Manager end for a locally-hosted store.
        - C(link) links a locally-hosted store with AWS, creating it in AWS KMS.
        - C(rotate_credential) issues a new credential for the store, and
          C(enable_credential_rotation_job) and C(disable_credential_rotation_job) put
          that on a schedule.
        - C(delete_credential) removes one previously-rotated credential.
      choices:
        - create
        - patch
        - block
        - unblock
        - connect
        - disconnect
        - link
        - rotate_credential
        - enable_credential_rotation_job
        - disable_credential_rotation_job
        - delete_credential
      required: true
      type: str
    custom_key_store_id:
      description:
        - Name or id of the custom key store to act on.
        - Required for every operation except I(op_type=create).
      type: str
    name:
      description:
        - Unique name for the custom key store.
        - Required when I(op_type=create). Unlike most CCKM resources, a custom key store
          can be renamed with I(op_type=patch).
      type: str
    kms:
      description:
        - Name or id of the AWS account container to create the store in.
        - Required when I(op_type=create).
      type: str
    region:
      description:
        - AWS region to create the store in.
        - Required when I(op_type=create).
      type: str
    linked_state:
      description:
        - Whether the store is linked with AWS on creation.
        - Only applies to an external key store. When C(false), the store is created in
          CipherTrust Manager only and can be linked later with I(op_type=link).
      type: bool
    enable_success_audit_event:
      description:
        - Record successful operations in the external key store's audit log, as well as
          failed ones.
        - Logging every success is costly on a busy store; AWS's own default is off.
      type: bool
    aws_param:
      description:
        - How AWS reaches the store.
        - Required when I(op_type=create). Which suboptions apply depends on the kind of
          store being created.
      type: dict
      suboptions:
        custom_key_store_type:
          description:
            - Kind of store to create. Defaults to C(EXTERNAL_KEY_STORE).
            - Cannot be changed after the store is created.
          choices: [EXTERNAL_KEY_STORE, AWS_CLOUDHSM]
          type: str
        cloud_hsm_cluster_id:
          description:
            - Id of the CloudHSM cluster backing the store.
            - Required for an C(AWS_CLOUDHSM) store. List the clusters not yet in use with
              M(thalesgroup.ciphertrust.cckm_aws_cloudhsm_cluster_info).
          type: str
        key_store_password:
          description:
            - Password of the C(kmsuser) crypto user in the CloudHSM cluster.
            - CipherTrust Manager never returns this value, so supplying it on a patch
              makes the task report C(changed) on every run.
          type: str
        trust_anchor_certificate:
          description:
            - Contents of the CA certificate created when the CloudHSM cluster was
              initialised.
          type: str
        xks_proxy_uri_endpoint:
          description:
            - HTTPS endpoint AWS KMS sends XKS requests to.
            - Required for an C(EXTERNAL_KEY_STORE).
          type: str
        xks_proxy_connectivity:
          description:
            - How AWS KMS reaches the endpoint.
            - Required for an C(EXTERNAL_KEY_STORE).
          choices: [VPC_ENDPOINT_SERVICE, PUBLIC_ENDPOINT]
          type: str
        xks_proxy_vpc_endpoint_service_name:
          description:
            - Name of the VPC endpoint service AWS KMS reaches the store through.
            - Required when I(xks_proxy_connectivity=VPC_ENDPOINT_SERVICE).
          type: str
    local_hosted_params:
      description:
        - Settings for a store whose key material CipherTrust Manager or a Luna HSM holds.
      type: dict
      suboptions:
        source_key_tier:
          description:
            - Whether the backing keys live in CipherTrust Manager (C(local)) or in a Luna
              HSM (C(luna-hsm)).
          choices: [local, luna-hsm]
          type: str
        partition_id:
          description:
            - Id of the Luna HSM partition holding the keys.
            - Required when I(source_key_tier=luna-hsm).
          type: str
        health_check_key_id:
          description:
            - Id of an existing key AWS's health check exercises.
            - Required for an external key store.
          type: str
        blocked:
          description:
            - Create the store already blocked, serving no cryptographic operations until
              I(op_type=unblock).
          type: bool
        mtls_enabled:
          description:
            - Require AWS KMS to present a client certificate when it calls the XKS
              endpoint.
          type: bool
        max_credentials:
          description:
            - How many credentials may exist for the store at once, between 2 and 20.
            - Rotation needs room for both the old and the new credential.
          type: str
    key_store_password:
      description:
        - Password of the C(kmsuser) crypto user, for I(op_type=connect).
        - Only needed for a CloudHSM-backed store whose password has changed since it was
          created.
      type: str
    xks_proxy_uri_endpoint:
      description:
        - HTTPS endpoint AWS KMS will send XKS requests to.
        - Required when I(op_type=link).
      type: str
    xks_proxy_vpc_endpoint_service_name:
      description:
        - Name of the VPC endpoint service, for I(op_type=link) when the store uses
          C(VPC_ENDPOINT_SERVICE) connectivity.
      type: str
    job_config_id:
      description:
        - Id of the scheduler configuration that will rotate the store's credentials.
        - Required when I(op_type=enable_credential_rotation_job).
      type: str
    credential_id:
      description:
        - Id of the credential to delete.
        - Required when I(op_type=delete_credential). List them with
          M(thalesgroup.ciphertrust.cckm_aws_custom_key_store_info) using
          I(op_type=list_credentials).
      type: str
"""

EXAMPLES = """
- name: "Create an external key store backed by CipherTrust Manager"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: xks-production
    kms: aws-production
    region: us-east-1
    linked_state: false
    aws_param:
      custom_key_store_type: EXTERNAL_KEY_STORE
      xks_proxy_connectivity: PUBLIC_ENDPOINT
      xks_proxy_uri_endpoint: "https://xks.example.com"
    local_hosted_params:
      source_key_tier: local
      health_check_key_id: "{{ health_check_key_id }}"
      max_credentials: "10"
  register: _cks

- name: "Link the store with AWS"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store:
    localNode: "{{ cm_connection }}"
    op_type: link
    custom_key_store_id: "{{ _cks.response.id }}"
    xks_proxy_uri_endpoint: "https://xks.example.com"

- name: "Connect the store so AWS can use its keys"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store:
    localNode: "{{ cm_connection }}"
    op_type: connect
    custom_key_store_id: "{{ _cks.response.id }}"

- name: "Create a CloudHSM-backed store"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store:
    localNode: "{{ cm_connection }}"
    op_type: create
    name: cloudhsm-production
    kms: aws-production
    region: us-east-1
    aws_param:
      custom_key_store_type: AWS_CLOUDHSM
      cloud_hsm_cluster_id: "cluster-abcd1234"
      key_store_password: "{{ vault_kmsuser_password }}"
      trust_anchor_certificate: "{{ lookup('file', 'customerCA.crt') }}"

- name: "Rotate the store's credentials every night"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store:
    localNode: "{{ cm_connection }}"
    op_type: enable_credential_rotation_job
    custom_key_store_id: "{{ _cks.response.id }}"
    job_config_id: "{{ nightly_job_id }}"

- name: "Stop serving cryptographic operations from the store"
  thalesgroup.ciphertrust.cckm_aws_custom_key_store:
    localNode: "{{ cm_connection }}"
    op_type: block
    custom_key_store_id: "{{ _cks.response.id }}"
"""

RETURN = r"""
changed:
    description: Whether the module made a change.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing store when one was found during the GET-before-write
        idempotency check.
      - The CloudHSM password is never returned by CipherTrust Manager, so it
        does not appear here.
    returned: when a request was made or an existing store matched
    type: dict
    contains:
        id:
            description: Unique identifier of the custom key store.
            type: str
            returned: when applicable
        name:
            description: Name of the custom key store.
            type: str
            returned: when applicable
        type:
            description: CCKM's view of the store, C(LOCAL), C(REMOTE) or C(CloudHSM).
            type: str
            returned: when applicable
        region:
            description: AWS region the store lives in.
            type: str
            returned: when applicable
        aws_param:
            description:
              - How AWS reaches the store, including C(connection_state) and the
                XKS proxy endpoint and URI path.
            type: dict
            returned: when applicable
        local_hosted_params:
            description:
              - Settings of a locally-hosted store, including the source key
                tier, whether it is blocked, and its health check key.
            type: dict
            returned: for a locally-hosted store
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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import cckm_aws
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
    idempotent_create,
    idempotent_patch,
)

_aws_param = dict(
    custom_key_store_type=dict(type="str",
                               choices=["EXTERNAL_KEY_STORE", "AWS_CLOUDHSM"]),
    cloud_hsm_cluster_id=dict(type="str"),
    key_store_password=dict(type="str", no_log=True),
    trust_anchor_certificate=dict(type="str"),
    xks_proxy_uri_endpoint=dict(type="str"),
    xks_proxy_connectivity=dict(type="str",
                                choices=["VPC_ENDPOINT_SERVICE", "PUBLIC_ENDPOINT"]),
    xks_proxy_vpc_endpoint_service_name=dict(type="str"),
)

_local_hosted_params = dict(
    source_key_tier=dict(type="str", choices=["local", "luna-hsm"], no_log=False),
    partition_id=dict(type="str"),
    health_check_key_id=dict(type="str", no_log=False),
    blocked=dict(type="bool"),
    mtls_enabled=dict(type="bool"),
    max_credentials=dict(type="str"),
)

_OP_TYPES = [
    "create",
    "patch",
    "block",
    "unblock",
    "connect",
    "disconnect",
    "link",
    "rotate_credential",
    "enable_credential_rotation_job",
    "disable_credential_rotation_job",
    "delete_credential",
]

argument_spec = dict(
    op_type=dict(type="str", choices=_OP_TYPES, required=True),
    custom_key_store_id=dict(type="str"),
    name=dict(type="str"),
    kms=dict(type="str"),
    region=dict(type="str"),
    linked_state=dict(type="bool"),
    enable_success_audit_event=dict(type="bool"),
    aws_param=dict(type="dict", options=_aws_param),
    local_hosted_params=dict(type="dict", options=_local_hosted_params),
    key_store_password=dict(type="str", no_log=True),
    xks_proxy_uri_endpoint=dict(type="str"),
    xks_proxy_vpc_endpoint_service_name=dict(type="str"),
    job_config_id=dict(type="str"),
    credential_id=dict(type="str", no_log=False),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["name", "kms", "region", "aws_param"]],
            ["op_type", "patch", ["custom_key_store_id"]],
            ["op_type", "block", ["custom_key_store_id"]],
            ["op_type", "unblock", ["custom_key_store_id"]],
            ["op_type", "connect", ["custom_key_store_id"]],
            ["op_type", "disconnect", ["custom_key_store_id"]],
            ["op_type", "link", ["custom_key_store_id", "xks_proxy_uri_endpoint"]],
            ["op_type", "rotate_credential", ["custom_key_store_id"]],
            ["op_type", "enable_credential_rotation_job",
             ["custom_key_store_id", "job_config_id"]],
            ["op_type", "disable_credential_rotation_job", ["custom_key_store_id"]],
            ["op_type", "delete_credential",
             ["custom_key_store_id", "credential_id"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


# Operations that are a bare POST with no request body.
_BARE_ACTIONS = {
    "block": "block",
    "unblock": "unblock",
    "disconnect": "disconnect",
    "rotate_credential": "rotate-credential",
    "disable_credential_rotation_job": "disable-credential-rotation-job",
}


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    node = module.params.get("localNode")
    client = CipherTrustClient(node)
    op_type = module.params.get("op_type")
    params = module.params

    with ciphertrust_operation(module):
        if op_type == "create":
            changed, response, diff = idempotent_create(
                module, client,
                endpoint=cckm_aws.CUSTOM_KEY_STORES,
                lookup_param="name",
                lookup_value=params.get("name"),
                create_fn=cckm_aws.custom_key_store_create,
                create_kwargs=dict(
                    node=node,
                    name=params.get("name"),
                    kms=params.get("kms"),
                    region=params.get("region"),
                    aws_param=params.get("aws_param"),
                    local_hosted_params=params.get("local_hosted_params"),
                    linked_state=params.get("linked_state"),
                    enable_success_audit_event=params.get("enable_success_audit_event"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif op_type == "patch":
            changed, response, diff = idempotent_patch(
                module, client,
                endpoint=cckm_aws.CUSTOM_KEY_STORES,
                resource_id=params.get("custom_key_store_id"),
                ignore_fields=("custom_key_store_id",),
                # A PATCH merges into aws_param and local_hosted_params rather
                # than replacing them, and CM reports far more in each than a
                # playbook sets -- connection_state, the health check
                # ciphertext, the XKS URI path. Comparing whole would report a
                # change on every run.
                subset_fields=("aws_param", "local_hosted_params"),
                patch_fn=cckm_aws.custom_key_store_patch,
                patch_kwargs=dict(
                    node=node,
                    custom_key_store_id=params.get("custom_key_store_id"),
                    name=params.get("name"),
                    aws_param=params.get("aws_param"),
                    local_hosted_params=params.get("local_hosted_params"),
                    enable_success_audit_event=params.get("enable_success_audit_event"),
                ),
            )
            result["changed"] = changed
            result["response"] = response
            if diff:
                result["diff"] = diff

        elif op_type == "delete_credential":
            check_mode_action(module)
            result["response"] = cckm_aws.custom_key_store_credential_delete(
                node=node,
                custom_key_store_id=params.get("custom_key_store_id"),
                credential_id=params.get("credential_id"),
            )
            result["changed"] = True

        else:
            check_mode_action(module)

            if op_type == "connect":
                action = "connect"
                fields = dict(key_store_password=params.get("key_store_password"))
            elif op_type == "link":
                action = "link"
                fields = dict(aws_param=dict(
                    xks_proxy_uri_endpoint=params.get("xks_proxy_uri_endpoint"),
                    xks_proxy_vpc_endpoint_service_name=params.get(
                        "xks_proxy_vpc_endpoint_service_name"),
                ))
            elif op_type == "enable_credential_rotation_job":
                action = "enable-credential-rotation-job"
                fields = dict(job_config_id=params.get("job_config_id"))
            elif op_type in _BARE_ACTIONS:
                action = _BARE_ACTIONS[op_type]
                fields = None
            else:
                module.fail_json(msg="invalid op_type")
                return

            result["response"] = cckm_aws.custom_key_store_action(
                node=node,
                custom_key_store_id=params.get("custom_key_store_id"),
                action=action,
                fields=fields,
            )
            result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
