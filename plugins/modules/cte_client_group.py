#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: cte_client_group
short_description: Manage CTE client groups
description:
    - This module lets administrator create r manage client groups so that group level policies can be applied to multiple clients
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
options:
    localNode:
      description:
        - this holds the connection parameters required to communicate with an instance of CipherTrust Manager (CM)
        - holds IP/FQDN of the server, username, password, and port
      required: true
      type: dict
      suboptions:
        server_ip:
          description: CM Server IP or FQDN
          type: str
          required: true
        server_private_ip:
          description: internal or private IP of the CM Server, if different from the server_ip
          type: str
          required: true
        server_port:
          description: Port on which CM server is listening
          type: int
          required: true
        user:
          description: admin username of CM
          type: str
          required: true
        password:
          description: admin password of CM
          type: str
          required: true
        verify:
          description: if SSL verification is required
          type: bool
          required: true
        auth_domain_path:
          description: user's domain path
          type: str
          required: true
    op_type:
      description: Operation to be performed
      choices: ['create', 'patch', 'add_client', 'add_guard_point', 'update_guardpoint', 'unguard_guardpoints', 'auth-binaries', 'remove_client', 'ldt_pause']
      required: true
      type: str
    id:
      description: Identifier of the Client Group to be acted upon
      type: str
    client_id:
      description: Identifier of the client within the group that needs to be acted upon
      type: str
    cluster_type:
      description: Cluster type of the ClientGroup, valid values are NON-CLUSTER and HDFS.
      choices: ['NON-CLUSTER', 'HDFS']
      type: str
    name:
      description: Name of the ClientGroup
      type: str
    description:
      description: Description of the ClientGroup
      type: str
    communication_enabled:
      description: Whether the File System communication is enabled
      type: bool
    password:
      description:
        - User supplied password if password_creation_method is MANUAL
        - The password MUST be minimum 8 characters and MUST contain one alphabet, one number, and one special characters
      type: str
    password_creation_method:
      description: Password creation method, GENERATE or MANUAL
      choices: ['GENERATE', 'MANUAL']
      type: str
    profile_id:
      description:
        - ID of the client group profile that is used to schedule custom configuration for logger, logging, and Quality of Service (QoS)
      type: str
    client_locked:
      description:
        - Is FS Agent locked?
        - Enables locking the configuration of the File System Agent on the client
        - This will prevent updates to any policies on the client
        - Default value is false
      type: bool
      default: false
    enable_domain_sharing:
      description: Whether to enable domain sharing for ClientGroup
      type: bool
    enabled_capabilities:
      description:
        - Comma separated agent capabilities which are enabled
        - Currently only RESIGN for re-signing client settings can be enabled
      type: str
    shared_domain_list:
      description: List of domains with which ClientGroup needs to be shared
      type: list
      elements: str
    system_locked:
      description:
        - Whether the system is locked
        - The default value is false
        - Enable this option to lock the important operating system files of the client
        - When enabled, patches to the operating system of the client will fail due to the protection of these files
      type: bool
    client_list:
      description:
        - List of Client identifier which are to be associated with clientgroup
        - This identifier can be the Name, ID, URI, or slug of the client
      type: list
      elements: str
    inherit_attributes:
      description: Whether the client should inherit attributes from the ClientGroup
      type: bool
    guard_paths:
      description: List of GuardPaths to be created
      type: list
      elements: str
    guard_point_params:
      description: Parameters for creating a GuardPoint
      type: dict
      suboptions:
        guard_point_type:
          description: Type of the GuardPoint.
          type: str
          choices:
            - directory_auto
            - directory_manual
            - rawdevice_manual
            - rawdevice_auto
            - cloudstorage_auto
            - cloudstorage_manual
        policy_id:
          description:
            - ID of the policy applied with this GuardPoint
            - This parameter is not valid for Ransomware GuardPoints as they will not be associated with any CTE policy
          type: str
        automount_enabled:
          description:
            - Whether automount is enabled with the GuardPoint
            - Supported for Standard and LDT policies
          type: bool
        cifs_enabled:
          description:
            - Whether to enable CIFS
            - Available on LDT enabled windows clients only
            - The default value is false
            - If you enable the setting, it cannot be disabled
            - Supported for only LDT policies.
          type: bool
        data_classification_enabled:
          description:
            - Whether data classification (tagging) is enabled
            - Enabled by default if the aligned policy contains ClassificationTags
            - Supported for Standard and LDT policies.
          type: bool
        data_lineage_enabled:
          description:
            - Whether data lineage (tracking) is enabled
            - Enabled only if data classification is enabled
            - Supported for Standard and LDT policies.
          type: bool
        disk_name:
          description:
            - Name of the disk if the selected raw partition is a member of an Oracle ASM disk group
          type: str
        diskgroup_name:
          description:
            - Name of the disk group if the selected raw partition is a member of an Oracle ASM disk group
          type: str
        dps_id:
          description:
            - ID/name of the Designated Primary Set.
          type: str
        early_access:
          description:
            - Whether secure start (early access) is turned on
            - Secure start is applicable to Windows clients only
            - Supported for Standard and LDT policies
            - The default value is false
          type: bool
        intelligent_protection:
          description:
            - Flag to enable intelligent protection for this GuardPoint
            - This flag is valid for GuardPoints with classification based policy only
            - Can only be set during GuardPoint creation
          type: bool
        is_idt_capable_device:
          description:
            - Whether the device where GuardPoint is applied is IDT capable or not
            - Supported for IDT policies.
          type: bool
        mfa_enabled:
          description: Whether MFA is enabled
          type: bool
        network_share_credentials_id:
          description:
            - ID/Name of the credentials if the GuardPoint is applied to a network share
            - Supported for only LDT policies.
          type: str
        preserve_sparse_regions:
          description:
            - Whether to preserve sparse file regions
            - Available on LDT enabled clients only
            - The default value is true
            - If you disable the setting, it cannot be enabled again
            - Supported for only LDT policies.
          type: bool
    auth_binaries:
      description: Array of authorized binaries in the privilege-filename pair JSON format
      type: str
    re_sign:
      description: Whether to re-sign the client settings
      type: bool
    paused:
      description: Mouse over a property in the schema to view its details
      type: bool
    dps_id:
      description:
        - ID/name of the Designated Primary Set.
      type: str
    guard_enabled:
      description: Whether the GuardPoint is enabled.
      type: bool
    mfa_enabled:
      description: Whether MFA is enabled
      type: bool
    network_share_credentials_id:
      description:
        - ID/Name of the credentials if the GuardPoint is applied to a network share
        - Supported for only LDT policies.
      type: str
    guard_point_id:
      description: Unique identifier for the guardpoint to be updated
      type: str
    guard_point_id_list:
      description:
        - Comma-separated IDs of GuardPoints to be dissociated from a ClientGroup. The IDs can be the Name, ID (a UUIDv4), URI, or slug of the ClientGroup.
      type: list
      elements: str
"""

EXAMPLES = """
- name: "Create CTE Client Group"
  thalesgroup.ciphertrust.cte_client_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    cluster_type: NON-CLUSTER
    name: ClientGroup1

- name: "Add client to CTE client group"
  thalesgroup.ciphertrust.cte_client_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_client
    client_list:
      - Client1
      - Client2
    inherit_attributes: true

- name: "Add guard point to CTE client group"
  thalesgroup.ciphertrust.cte_client_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_guard_point
    guard_paths:
      - "/opt/path1/"
      - "/opt/path2/"
    guard_point_params:
      guard_point_type: directory_auto
      policy_id: TestPolicy
      data_classification_enabled: false
      data_lineage_enabled: false
      early_access: true
      preserve_sparse_regions: true
"""

RETURN = """
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import (
    createClientGroup,
    updateClientGroup,
    clientGroupAddClients,
    clientGroupAddGuardPoint,
    clientGroupUpdateGuardPoint,
    clientGroupAuthBinaries,
    clientGroupDeleteClient,
    clientGroupLDTPause,
    clientGroupUnguardGuardPoint,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

_guard_point_params = dict(
    guard_point_type=dict(
        type="str",
        choices=[
            "directory_auto",
            "directory_manual",
            "rawdevice_manual",
            "rawdevice_auto",
            "cloudstorage_auto",
            "cloudstorage_manual",
        ],
    ),
    policy_id=dict(type="str"),
    automount_enabled=dict(type="bool"),
    cifs_enabled=dict(type="bool"),
    data_classification_enabled=dict(type="bool"),
    data_lineage_enabled=dict(type="bool"),
    disk_name=dict(type="str"),
    diskgroup_name=dict(type="str"),
    dps_id=dict(type="str"),
    early_access=dict(type="bool"),
    intelligent_protection=dict(type="bool"),
    # is_esg_capable_device=dict(type="bool"),
    is_idt_capable_device=dict(type="bool"),
    mfa_enabled=dict(type="bool"),
    network_share_credentials_id=dict(type="str"),
    preserve_sparse_regions=dict(type="bool"),
)

argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "create",
            "patch",
            "add_client",
            "add_guard_point",
            "update_guardpoint",
            "unguard_guardpoints",
            "auth-binaries",
            "remove_client",
            "ldt_pause",
        ],
        required=True,
    ),
    id=dict(type="str"),
    client_id=dict(type="str"),
    cluster_type=dict(type="str", choices=["NON-CLUSTER", "HDFS"]),
    name=dict(type="str"),
    description=dict(type="str"),
    communication_enabled=dict(type="bool"),
    password=dict(type="str"),
    password_creation_method=dict(type="str", choices=["GENERATE", "MANUAL"]),
    profile_id=dict(type="str"),
    client_locked=dict(type="bool", default=False),
    enable_domain_sharing=dict(type="bool"),
    enabled_capabilities=dict(type="str"),
    shared_domain_list=dict(type="list", elements="str"),
    system_locked=dict(type="bool"),
    client_list=dict(type="list", elements="str"),
    inherit_attributes=dict(type="bool"),
    guard_paths=dict(type="list", elements="str"),
    guard_point_params=dict(type="dict", options=_guard_point_params),
    auth_binaries=dict(type="str"),
    re_sign=dict(type="bool"),
    paused=dict(type="bool"),
    dps_id=dict(type="str"),
    guard_enabled=dict(type="bool"),
    mfa_enabled=dict(type="bool"),
    network_share_credentials_id=dict(type="str"),
    guard_point_id=dict(type="str"),
    guard_point_id_list=dict(type="list", elements="str"),
)


def validate_parameters(cte_client_group_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["cluster_type", "name"]],
            ["op_type", "patch", ["id"]],
            ["op_type", "add_client", ["id", "client_list", "inherit_attributes"]],
            ["op_type", "add_guard_point", ["id", "guard_paths", "guard_point_params"]],
            ["op_type", "unguard_guardpoints", ["guard_point_id_list"]],
            ["op_type", "auth-binaries", ["id"]],
            ["op_type", "remove_client", ["id", "client_id"]],
            ["op_type", "ldt_pause", ["id", "paused"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        cte_client_group_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get("op_type") == "create":
        try:
            response = createClientGroup(
                node=module.params.get("localNode"),
                name=module.params.get("name"),
                description=module.params.get("description"),
                cluster_type=module.params.get("cluster_type"),
                communication_enabled=module.params.get("communication_enabled"),
                password=module.params.get("password"),
                password_creation_method=module.params.get("password_creation_method"),
                profile_id=module.params.get("profile_id"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "patch":
        try:
            response = updateClientGroup(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_locked=module.params.get("client_locked"),
                communication_enabled=module.params.get("communication_enabled"),
                description=module.params.get("description"),
                enable_domain_sharing=module.params.get("enable_domain_sharing"),
                enabled_capabilities=module.params.get("enabled_capabilities"),
                password=module.params.get("password"),
                password_creation_method=module.params.get("password_creation_method"),
                profile_id=module.params.get("profile_id"),
                shared_domain_list=module.params.get("shared_domain_list"),
                system_locked=module.params.get("system_locked"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "add_client":
        try:
            response = clientGroupAddClients(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_list=module.params.get("client_list"),
                inherit_attributes=module.params.get("inherit_attributes"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "add_guard_point":
        try:
            response = clientGroupAddGuardPoint(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                guard_paths=module.params.get("guard_paths"),
                guard_point_params=module.params.get("guard_point_params"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "update_guardpoint":
        try:
            response = clientGroupUpdateGuardPoint(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                guardpoint_id=module.params.get("guard_point_id"),
                dps_id=module.params.get("dps_id"),
                guard_enabled=module.params.get("guard_enabled"),
                mfa_enabled=module.params.get("mfa_enabled"),
                network_share_credentials_id=module.params.get("network_share_credentials_id"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "unguard_guardpoints":
        try:
            response = clientGroupUnguardGuardPoint(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                guard_point_id_list=module.params.get("guard_point_id_list"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "auth-binaries":
        try:
            response = clientGroupAuthBinaries(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                auth_binaries=module.params.get("auth_binaries"),
                re_sign=module.params.get("re_sign"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "remove_client":
        try:
            response = clientGroupDeleteClient(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                client_id=module.params.get("client_id"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    elif module.params.get("op_type") == "ldt_pause":
        try:
            response = clientGroupLDTPause(
                node=module.params.get("localNode"),
                id=module.params.get("id"),
                paused=module.params.get("paused"),
            )
            result["response"] = response
        except CMApiException as api_e:
            if api_e.api_error_code:
                module.fail_json(
                    msg="status code: "
                    + str(api_e.api_error_code)
                    + " message: "
                    + api_e.message
                )
        except AnsibleCMException as custom_e:
            module.fail_json(msg=custom_e.message)

    else:
        module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
