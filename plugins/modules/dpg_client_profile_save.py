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
module: dpg_client_profile_save
short_description: Manage DPG client profile
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with DPG Client Profile API
    - Refer https://thalesdocs.com/ctp/con/dpg/latest/admin/index.html for API documentation
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
      choices: ['create', 'patch']
      required: true
      type: str
    profile_id:
      description:
        - Identifier of the client profile to be patched
      type: str
    name:
      description: Unique name for the client profile.
      type: str
    app_connector_type:
      description: App connector type for which the client profile is created
      choices: ['DPG', 'CADP For Java', 'CRDP']
      type: str
    ca_id:
      description: Local CA mapped with client profile
      type: str
    cert_duration:
      description: Duration for which client credentials are valid
      type: int
    configurations:
      description: Parameters required to initialize connector
      type: dict
      suboptions:
        symmetric_key_cache_enabled:
          description: Whether the symmetric key cache is enabled
          type: bool
          default: True
        symmetric_key_cache_expiry:
          description: Time after which the symmetric key cache will expire
          type: int
          default: 43200
        size_of_connection_pool:
          description: The maximum number of connections that can persist in connection pool
          type: int
          default: 300
        load_balancing_algorithm:
          description: Determines how the client selects a Key Manager from a load balancing group
          type: str
          choices: ['round-robin', 'random']
          default: round-robin
        connection_idle_timeout:
          description: The time a connection is allowed to be idle in the connection pool before it gets automatically closed
          type: int
          default: 600000
        connection_retry_interval:
          description: The amount of time to wait before trying to reconnect to a disabled server
          type: int
          default: 600000
        log_level:
          description: The level of logging to determine verbosity of clients logs
          type: str
          choices: ['ERROR', 'WARN', 'INFO', 'DEBUG']
          default: WARN
        log_rotation:
          description: Specifies how frequently the log file is rotated
          type: str
          choices: ['None', 'Daily', 'Weekly', 'Monthly', 'Size']
          default: Daily
        log_size_limit:
          description: Determines how the client selects a Key Manager from a load balancing group
          type: str
          default: 100k
        log_type:
          description: Type of the log
          type: str
          choices: ['Console', 'File', 'Multi']
          default: Console
        log_gmt:
          description: This value specifies if timestamp in logs should be formatted in GMT or not. Default disabled
          type: bool
        log_file_path:
          description: This value specifies the path where log file will be created
          type: str
        connection_timeout:
          description: Connection timeout value for clients
          type: int
          default: 60000
        connection_read_timeout:
          description: Read timeout value for clients
          type: int
          default: 7000
        heartbeat_interval:
          description: Frequency interval for sending heartbeat by connectors
          type: int
          default: 300
        heartbeat_timeout_count:
          description: heartbeat timeout missed communication counts with CM for connectors to decide on cleanup profile cache
          type: int
          default: -1
        tls_to_appserver:
          description: TLS to app server configuration
          type: dict
          suboptions:
            tls_skip_verify:
              description: skip verification flag
              type: bool
            tls_enabled:
              description: TLS enabled flag
              type: bool
        dial_timeout:
          description: Specifies the maximum duration (in seconds) the DPG server will wait for a connection with the Application Server to succeed
          type: int
        dial_keep_alive:
          description: Specifies the interval (in seconds) between keep-alive probes for an active network connection.
          type: int
        auth_method_used:
          description: used to define how and from where to validate the application user
          type: dict
          suboptions:
            scheme_name:
              description: the type of authentication scheme to be used to fetch the suer Options
              type: str
              choices:
                - Basic
                - Bearer
              default: Basic
            token_field:
              description: the json field which have the user information. Required when scheme_name is Bearer.
              type: str
        jwt_details:
          description: Information about the the JWT validation
          type: dict
          suboptions:
            issuer:
              description:
                - String that identifies the principal that issued the JWT
                - If empty, the iss (issuer) field in the JWT won't be checked.
              type: str
        enable_performance_metrics:
          description:
            - Flag used to enable clients to create a performance metrics
            - Default is true
          type: bool
    csr_parameters:
      description: Client certificate parameters to be updated
      type: dict
      suboptions:
        csr_cn:
          description: Common Name
          type: str
        csr_country:
          description: Country Name
          type: str
        csr_state:
          description: State Name
          type: str
        csr_city:
          description: City Name
          type: str
        csr_org_name:
          description: Organization Name
          type: str
        csr_org_unit:
          description: Organizational Unit Name
          type: str
        csr_email:
          description: Email
          type: str
    heartbeat_threshold:
      description: The Threshold by which client's connectivity_status will be moved to Error if not heartbeat is received
      type: int
    lifetime:
      description: Validity of registration token
      type: str
    max_clients:
      description: Number of clients that can register using a registration token
      type: int
    nae_iface_port:
      description: Nae interface mapped with client profile
      type: int
    policy_id:
      description: Policy mapped with client profile.
      type: str
    enable_client_autorenewal:
      description:
        - Flag used to check client autorenewal is enabled or not
        - Default value is false
      type: str
    groups:
      description: List of the groups in which client will be added during registration
      type: list
      elements: str
    jwt_verification_key:
      description: PEM encoded PKCS#1 or PKCS#8 Public key used to validate a JWT
      type: str
"""

EXAMPLES = """
- name: "Create DPG Client Profile"
  thalesgroup.ciphertrust.dpg_client_profile_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    name: DPGClientProfile
    op_type: create
    app_connector_type: DPG
    lifetime: 30d
    cert_duration: 730
    max_clients: 200
    ca_id: <CA_UUID>
    nae_iface_port: 9005
    csr_parameters:
      csr_cn: admin
    policy_id: <DPGPolicyID>

- name: "Patch DPG Client Profile"
  thalesgroup.ciphertrust.dpg_client_profile_save:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
        auth_domain_path:
    op_type: patch
    profile_id: <DPGClientProfileID>
    lifetime: 180d
"""

RETURN = """

"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import (
    createClientProfile,
    updateClientProfile,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

_schema_less = dict()

_tls_to_appserver = dict(
    tls_skip_verify=dict(type="bool"),
    tls_enabled=dict(type="bool"),
)
_jwt_details = dict(
    issuer=dict(type="str"),
)
_auth_method_used = dict(
    scheme_name=dict(type="str", choices=["Basic", "Bearer"], default="Basic"),
    token_field=dict(type="str"),
)
_configuration = dict(
    symmetric_key_cache_enabled=dict(type="bool", default=True),
    symmetric_key_cache_expiry=dict(type="int", default=43200),
    size_of_connection_pool=dict(type="int", default=300),
    load_balancing_algorithm=dict(
        type="str", choices=["round-robin", "random"], default="round-robin"
    ),
    connection_idle_timeout=dict(type="int", default=600000),
    connection_retry_interval=dict(type="int", default=600000),
    log_level=dict(
        type="str", choices=["ERROR", "WARN", "INFO", "DEBUG"], default="WARN"
    ),
    log_rotation=dict(
        type="str",
        choices=["None", "Daily", "Weekly", "Monthly", "Size"],
        default="Daily",
    ),
    log_size_limit=dict(type="str", default="100k"),
    log_type=dict(
        type="str", choices=["Console", "File", "Multi"], default="Console"
    ),
    log_gmt=dict(type="bool"),
    log_file_path=dict(type="str"),
    connection_timeout=dict(type="int", default=60000),
    connection_read_timeout=dict(type="int", default=7000),
    heartbeat_interval=dict(type="int", default=300),
    heartbeat_timeout_count=dict(type="int", default=-1),
    tls_to_appserver=dict(type="dict", options=_tls_to_appserver),
    dial_timeout=dict(type="int"),
    dial_keep_alive=dict(type="int"),
    auth_method_used=dict(type="dict", options=_auth_method_used),
    jwt_details=dict(type="dict", options=_jwt_details),
    enable_performance_metrics=dict(type="bool"),
)

_csr_param = dict(
    csr_cn=dict(type="str"),
    csr_country=dict(type="str"),
    csr_state=dict(type="str"),
    csr_city=dict(type="str"),
    csr_org_name=dict(type="str"),
    csr_org_unit=dict(type="str"),
    csr_email=dict(type="str"),
)

argument_spec = dict(
    op_type=dict(type="str", choices=["create", "patch"], required=True),
    profile_id=dict(type="str"),
    app_connector_type=dict(type="str", choices=["DPG", "CADP For Java", "CRDP"]),
    name=dict(type="str"),
    ca_id=dict(type="str"),
    cert_duration=dict(type="int"),
    configurations=dict(type="dict", options=_configuration, required=False),
    csr_parameters=dict(type="dict", options=_csr_param, required=False),
    heartbeat_threshold=dict(type="int"),
    lifetime=dict(type="str"),
    max_clients=dict(type="int"),
    nae_iface_port=dict(type="int"),
    policy_id=dict(type="str"),
    enable_client_autorenewal=dict(type="str"),
    groups=dict(type="list", elements="str"),
    jwt_verification_key=dict(type="str"),
)


def validate_parameters(dpg_client_profile_module):
    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "patch", ["profile_id"]],
            ["op_type", "create", ["app_connector_type", "name"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
    global module

    module = setup_module_object()
    validate_parameters(
        dpg_client_profile_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get("op_type") == "create":
        try:
            response = createClientProfile(
                node=module.params.get("localNode"),
                name=module.params.get("name"),
                app_connector_type=module.params.get("app_connector_type"),
                ca_id=module.params.get("ca_id"),
                cert_duration=module.params.get("cert_duration"),
                configurations=module.params.get("configurations"),
                csr_parameters=module.params.get("csr_parameters"),
                heartbeat_threshold=module.params.get("heartbeat_threshold"),
                lifetime=module.params.get("lifetime"),
                max_clients=module.params.get("max_clients"),
                nae_iface_port=module.params.get("nae_iface_port"),
                policy_id=module.params.get("policy_id"),
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
            response = updateClientProfile(
                node=module.params.get("localNode"),
                profile_id=module.params.get("profile_id"),
                name=module.params.get("name"),
                app_connector_type=module.params.get("app_connector_type"),
                ca_id=module.params.get("ca_id"),
                configurations=module.params.get("configurations"),
                csr_parameters=module.params.get("csr_parameters"),
                heartbeat_threshold=module.params.get("heartbeat_threshold"),
                lifetime=module.params.get("lifetime"),
                max_clients=module.params.get("max_clients"),
                nae_iface_port=module.params.get("nae_iface_port"),
                policy_id=module.params.get("policy_id"),
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
