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
module: interface_save
short_description: Create or update an interface or service CipherTrust Manager is hosting
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs
    - For the interface management API
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
        choices: [create, patch]
        required: true
        type: str
    allow_unregistered:
        description: Flag to allow unregistered clients
        type: bool
    interface_id:
        description:
            - Identifier of the interface to be patched
        required: false
        type: str
    port:
        description:
            - The new interface will listen on the specified port
            - The port number should not be negative, 0 or the one already in-use.
        required: true
        type: int
    auto_gen_ca_id:
        description:
            - Auto-generate a new server certificate on server startup using the identifier (URI) of a Local CA resource
            - This is especially useful when a new node joins the cluster
            - In this case, the existing data of the joining node is overwritten by the data in the cluster
            - A new server certificate is generated on the joining node using the existing Local CA of the cluster.
            - Auto-generation of the server certificate can be disabled by setting auto_gen_ca_id to an empty string
        required: false
        type: str
    auto_registration:
        description:
            - Set auto registration to allow auto registration of KMIP clients.
        required: false
        default: null
        type: bool
    cert_user_field:
        description:
            - Specifies how the user name is extracted from the client certificate.
        required: false
        choices:
            - CN
            - SN
            - E
            - E_ND
            - UID
            - OU
        type: str
    custom_uid_size:
        description: This flag is used to define the custom uid size of managed object over the KMIP interface.
        required: false
        default: null
        type: int
    custom_uid_v2:
        description:
          - This flag specifies which version of custom uid feature is to be used for KMIP interface
          - If it is set to true, new implementation i.e. Custom uid version 2 will be used.
        required: false
        default: null
        type: bool
    default_connection:
        description:
          - The default connection may be "local_account" for local authentication or the LDAP domain for LDAP authentication
          - This value is applied when the username does not embed the connection name (e.g. "jdoe" effectively becomes "local_account|jdoe")
          - This value only applies to NAE only and is ignored if set for web and KMIP interfaces.
        required: false
        type: str
    interface_type:
        description: This parameter is used to identify the type of interface, what service to run on the interface.
        required: false
        default: nae
        choices:
            - web
            - kmip
            - nae
            - snmp
        type: str
    kmip_enable_hard_delete:
        description:
          - Enables hard delete of keys on KMIP Destroy operation
          - By default, only key material is removed and meta-data is preserved with the updated key state.
          - This setting applies only to KMIP interface.
          - Should be set to 1 for enabling the feature or 0 for returning to default behavior.
        required: false
        default: 0
        choices:
            - 0
            - 1
        type: int
    maximum_tls_version:
        description: Maximum TLS version to be configured for NAE or KMIP interface, default is latest maximum supported protocol.
        required: false
        choices:
            - tls_1_0
            - tls_1_1
            - tls_1_2
            - tls_1_3
        type: str
    meta:
        description: Meta information related to interface
        required: false
        type: dict
        suboptions:
          nae:
            description: Meta information related to NAE interface
            type: dict
            required: false
            suboptions:
              mask_system_groups:
                description: Flag for masking system groups in NAE requests
                type: bool
                required: false
    minimum_tls_version:
        description: Minimum TLS version to be configured for NAE or KMIP interface, default is v1.2 (tls_1_2).
        required: false
        default: tls_1_2
        choices:
            - tls_1_0
            - tls_1_1
            - tls_1_2
            - tls_1_3
        type: str
    mode:
        description:
          - Interface mode
        required: false
        default: no-tls-pw-opt
        choices:
            - no-tls-pw-opt
            - no-tls-pw-req
            - unauth-tls-pw-opt
            - unauth-tls-pw-req
            - tls-cert-opt-pw-opt
            - tls-pw-opt
            - tls-pw-req
            - tls-cert-pw-opt
            - tls-cert-and-pw
        type: str
    name:
        description: The name of the interface. Not valid for interface_type nae.
        required: false
        type: str
    network_interface:
        description: Defines what ethernet adapter the interface should listen to, use "all" for all.
        required: false
        type: str
    registration_token:
        description: Registration token in case auto registration is true.
        required: false
        type: str
    trusted_cas:
        description:
          - Collection of local and external CA IDs to trust for client authentication
          - See section "Certificate Authority" for more details.
        type: dict
        suboptions:
          external:
            description: A list of External CA IDs
            type: list
            elements: str
          local:
            description: A list of Local CA IDs
            type: list
            elements: str
    local_auto_gen_attributes:
      description:
        - Local CSR parameters for interface's certificate
        - These are for the local node itself, and they do not affect other nodes in the cluster
        - This gives user a convenient way to supply custom fields for automatic interface certification generation
        - Without them, the system defaults are used.
      type: dict
      required: false
      default: null
      suboptions:
        cn:
          description: Common name
          type: str
          required: true
        dns_names:
          description: Subject Alternative Names (SAN) DNS names
          type: list
          elements: str
          required: false
        email_addresses:
          description: Subject Alternative Names (SAN) Email addresses
          type: list
          elements: str
          required: false
        ip_addresses:
          description: Subject Alternative Names (SAN) IP addresses
          type: list
          elements: str
          required: false
        names:
          description: Name fields like O, OU, L, ST, C
          type: list
          elements: dict
          suboptions:
            C:
              description:
                - Country, for example "US"
              type: str
            L:
              description:
                - Location, for example "Belcamp"
              type: str
            O:
              description:
                - Organization, for example "Thales Group"
              type: str
            OU:
              description:
                - Organizational Unit, for example "RnD"
              type: str
            ST:
              description:
                - State/province, for example "MD"
              type: str
        uid:
          description: User ID
          type: str
          required: false
    tls_ciphers:
      description:
        - TLS Ciphers contain the list of cipher suites available in the system for TLS handshake.
      type: dict
      required: false
      default: null
      suboptions:
        cipher_suite:
          description: TLS cipher suite name.
          type: str
          required: true
        enabled:
          description: TLS cipher suite enabled flag. If set to true, cipher suite will be available for TLS handshake.
          type: bool
          default: null
          required: true
"""

EXAMPLES = """
- name: "Create Interface"
  thalesgroup.ciphertrust.interface_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
    port: 9005
    auto_registration: false
    interface_type: nae
    mode: no-tls-pw-opt
    network_interface: all
"""

RETURN = """

"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.interfaces import (
    create,
    patch,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

_nae_mask_system_groups = dict(
    mask_system_groups=dict(type="bool", required=False),
)
_meta = dict(
    nae=dict(type="dict", options=_nae_mask_system_groups, required=False),
)
_trusted_cas = dict(
    external=dict(type="list", elements="str", required=False),
    local=dict(type="list", elements="str", required=False),
)
_name = dict(
    C=dict(type="str", required=False),
    L=dict(type="str", required=False),
    O=dict(type="str", required=False),
    OU=dict(type="str", required=False),
    ST=dict(type="str", required=False),
)
_local_auto_gen_attribute = dict(
    cn=dict(type="str", required=True),
    dns_names=dict(type="list", elements="str", required=False),
    email_addresses=dict(type="list", elements="str", required=False),
    ip_addresses=dict(type="list", elements="str", required=False),
    names=dict(type="list", elements="dict", options=_name, required=False),
    uid=dict(type="str", required=False),
)
_tls_cipher = dict(
    cipher_suite=dict(type="str", required=True),
    enabled=dict(type="bool", required=True),
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    interface_id=dict(type="str"),
    port=dict(type="int", required=True),
    auto_gen_ca_id=dict(type="str", required=False),
    auto_registration=dict(type="bool", required=False),
    allow_unregistered=dict(type="bool", required=False),
    cert_user_field=dict(
        type="str", choices=["CN", "SN", "E", "E_ND", "UID", "OU"], required=False
    ),
    custom_uid_size=dict(type="int", required=False),
    custom_uid_v2=dict(type="bool", required=False),
    default_connection=dict(type="str", required=False),
    interface_type=dict(
        type="str",
        required=False,
        choices=["web", "kmip", "nae", "snmp"],
        default="nae",
    ),
    kmip_enable_hard_delete=dict(type="int", choices=[0, 1], default=0, required=False),
    maximum_tls_version=dict(
        type="str", required=False, choices=["tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"]
    ),
    meta=dict(type="dict", options=_meta, required=False),
    minimum_tls_version=dict(
        type="str",
        required=False,
        choices=["tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"],
        default="tls_1_2",
    ),
    mode=dict(
        type="str",
        choices=[
            "no-tls-pw-opt",
            "no-tls-pw-req",
            "unauth-tls-pw-opt",
            "unauth-tls-pw-req",
            "tls-cert-opt-pw-opt",
            "tls-pw-opt",
            "tls-pw-req",
            "tls-cert-pw-opt",
            "tls-cert-and-pw",
        ],
        required=False,
        default="no-tls-pw-opt",
    ),
    name=dict(type="str", required=False),
    network_interface=dict(type="str", required=False),
    registration_token=dict(type="str", required=False),
    trusted_cas=dict(type="dict", options=_trusted_cas, required=False),
    local_auto_gen_attributes=dict(
        type="dict", options=_local_auto_gen_attribute, required=False
    ),
    tls_ciphers=dict(type="dict", options=_tls_cipher, required=False),
)


def validate_parameters(user_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(["op_type", "patch", ["interface_id"]],),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        user_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get("op_type") == "create":
        try:
            response = create(
                node=module.params.get("localNode"),
                port=module.params.get("port"),
                auto_gen_ca_id=module.params.get("auto_gen_ca_id"),
                auto_registration=module.params.get("auto_registration"),
                allow_unregistered=module.params.get("allow_unregistered"),
                cert_user_field=module.params.get("cert_user_field"),
                custom_uid_size=module.params.get("custom_uid_size"),
                custom_uid_v2=module.params.get("custom_uid_v2"),
                default_connection=module.params.get("default_connection"),
                interface_type=module.params.get("interface_type"),
                kmip_enable_hard_delete=module.params.get("kmip_enable_hard_delete"),
                maximum_tls_version=module.params.get("maximum_tls_version"),
                meta=module.params.get("meta"),
                minimum_tls_version=module.params.get("minimum_tls_version"),
                mode=module.params.get("mode"),
                name=module.params.get("name"),
                network_interface=module.params.get("network_interface"),
                registration_token=module.params.get("registration_token"),
                trusted_cas=module.params.get("trusted_cas"),
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
            response = patch(
                node=module.params.get("localNode"),
                interface_id=module.params.get("interface_id"),
                port=module.params.get("port"),
                auto_gen_ca_id=module.params.get("auto_gen_ca_id"),
                auto_registration=module.params.get("auto_registration"),
                allow_unregistered=module.params.get("allow_unregistered"),
                cert_user_field=module.params.get("cert_user_field"),
                custom_uid_size=module.params.get("custom_uid_size"),
                custom_uid_v2=module.params.get("custom_uid_v2"),
                default_connection=module.params.get("default_connection"),
                kmip_enable_hard_delete=module.params.get("kmip_enable_hard_delete"),
                maximum_tls_version=module.params.get("maximum_tls_version"),
                meta=module.params.get("meta"),
                minimum_tls_version=module.params.get("minimum_tls_version"),
                mode=module.params.get("mode"),
                registration_token=module.params.get("registration_token"),
                trusted_cas=module.params.get("trusted_cas"),
                local_auto_gen_attributes=module.params.get(
                    "local_auto_gen_attributes"
                ),
                tls_ciphers=module.params.get("tls_ciphers"),
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
