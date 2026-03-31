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
module: usermgmt_users_save
short_description: Create and manage users in CipherTrust Manager
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with user management API
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
          required: false
          default: 10.10.10.10
        server_port:
          description: Port on which CM server is listening
          type: int
          required: false
          default: 5432
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
          required: false
          default: false
        auth_domain_path:
          description: user's domain path
          type: str
          required: false
          default: ''
    op_type:
        description: Operation to be performed
        choices: [create, patch, changepw, patch_self]
        required: true
        type: str
    cm_user_id:
        description: CM user ID of the user that needs to be patched. Only required if the op_type is patch
        type: str
    allowed_auth_methods:
        description:
          - List of login authentication methods allowed to the user.
          - Default value - password i.e. Password Authentication is allowed by default.
          - Setting it to empty, i.e [], means no authentication method is allowed to the user.
          - If both enable_cert_auth and allowed_auth_methods are provided in the request, enable_cert_auth is ignored.
        type: list
        elements: str
        default: password
    app_metadata:
        description:
            - A schema-less object, which can be used by applications to store information about the resource
            - app_metadata is typically used by applications to store end-user information like group membership
        required: false
        type: dict
        default: null
    certificate_subject_dn:
        description: The Distinguished Name of the user in certificate
        required: false
        type: str
    connection:
        description:
            - This attribute is required to create a user, but is not included in user resource responses.
            - Can be the name of a connection or ''local_account'' for a local user, defaults to ''local_account''.
        type: str
        default: local_account
    email:
        description: E-mail of the user
        required: false
        type: str
    enable_cert_auth:
        description:
          - Deprecated
          - Use allowed_auth_methods instead.
          - If both enable_cert_auth and allowed_auth_methods are provided in the request, enable_cert_auth is ignored.
          - Enable certificate based authentication flag. If set to true, the user will be able to login using certificate.
        required: false
        type: bool
    is_domain_user:
        description: This flag can be used to create the user in a non-root domain where user management is allowed.
        required: false
        type: bool
    login_flags:
        description: Flags for controlling user''s login behavior.
        required: false
        type: dict
        suboptions:
          prevent_ui_login:
            description:
              - If true, user is not allowed to login from Web UI.
              - Default - false
            required: false
            type: bool
            default: false
    name:
        description: Full name of the user.
        required: false
        type: str
    password:
        description:
          - The password used to secure the users account. Allowed passwords are defined by the password policy.
          - Password is optional when ''certificate_subject_dn'' is set and ''user_certificate'' is in allowed_auth_methods.
          - In all other cases, password is required
          - It is not included in user resource responses.
        required: false
        type: str
    password_change_required:
        description:
            - Password change required flag.
            - If set to true, user will be required to change their password on next successful login.
        required: false
        type: bool
    user_id:
        description:
            - The user_id is the ID of an existing root domain user.
            - This field is used only when adding an existing root domain user to a different domain.
        required: false
        type: str
    user_metadata:
        description:
          - A schema-less object, which can be used by applications to store information about the resource
          - user_metadata is typically used by applications to store end-user information such as user preferences.
        required: false
        type: dict
        default: null
    username:
        description:
          - The login name of the user. This is the identifier used to login.
          - This attribute is required to create a user, but is omitted when getting or listing user resources. It cannot be updated.
          - This attribute may also be used (instead of the user_id) when adding an existing root domain user to a different domain.
          - Mandatory for create operation
        type: str
    failed_logins_count:
        description: Set it to 0 to unlock a locked user account.
        required: false
        type: int
    new_password:
        description:
          - the new password
          - mandatory for changepw op_type
        type: str
    auth_domain:
        description:
          - The domain where user needs to be authenticated. This is the domain where user is created. Defaults to the root domain.
          - required only for changepw op_type, not mandatory though
        type: str

requirements:
    - CipherTrust Manager API >= 1.0.0
    - Python >= 3.6
    - Ansible >= 2.9

validation:
    - username: Must be a valid email format (e.g., user@example.com) for create operation
    - password: Must meet the password policy requirements (minimum 8 characters, mix of upper/lower case, numbers, special characters) for create and changepw operations
    - new_password: Must meet the password policy requirements for changepw operation
    - cm_user_id: Must be a valid UUID format (e.g., local|UUID) for patch operation
    - email: Must be a valid email format (e.g., user@example.com) for patch and patch_self operations
    - name: Must be a non-empty string for patch and patch_self operations
    - allowed_auth_methods: Must be a list of valid authentication methods (password, certificate, sso) for create and patch operations
    - login_flags.prevent_ui_login: Must be a boolean value for create and patch operations
    - user_metadata: Must be a valid JSON object for create and patch operations
    - app_metadata: Must be a valid JSON object for create operation

documentation_links:
    create_operation: https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html
    patch_operation: https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html
    changepw_operation: https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html
    patch_self_operation: https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html
"""

EXAMPLES = """
- name: "Create new user"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: "create"
    username: "john.doe"
    password: "oldPassword12!"
    email: "john.doe@example.com"
    name: "John Doe"

- name: "Update user info"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: "patch"
    cm_user_id: "local|UUID"
    username: "john.doe"
    email: "aj@example.com"
    name: "New Name"

- name: "Change user password"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: "changepw"
    username: "john.doe"
    password: "oldPassword12!"
    new_password: "newPassword12!"

- name: "Update self"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: "patch_self"
    name: "CM Admin"
    email: "admin@example.com"

- name: "Create user with validation examples"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: "create"
    username: "john.doe@example.com"
    password: "YourPassword123!"
    email: "john.doe@example.com"
    name: "John Doe"
    allowed_auth_methods:
      - password
      - certificate
    login_flags:
      prevent_ui_login: false
    user_metadata:
      department: "Engineering"
      team: "Security"

- name: "Patch user with validation examples"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: "patch"
    cm_user_id: "local|12345678-1234-1234-1234-123456789012"
    username: "john.doe@example.com"
    email: "john.doe.new@example.com"
    name: "John Doe Updated"
    allowed_auth_methods:
      - password
    login_flags:
      prevent_ui_login: true
    user_metadata:
      department: "Engineering"
      team: "Security"

- name: "Change password with validation examples"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: "changepw"
    username: "john.doe@example.com"
    password: "YourCurrentPassword123!"
    new_password: "YourNewPassword456!"
    auth_domain: "root"

- name: "Update self with validation examples"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    op_type: "patch_self"
    name: "John Doe"
    email: "john.doe@example.com"
    user_metadata:
      phone: "123-456-7890"
      department: "Engineering"
"""

RETURN = """
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.users import (
    create,
    patch,
    changepw,
    patch_self,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
    AnsibleCMValidationException,
    AnsibleCMParameterException,
    AnsibleCMFormatException,
    AnsibleCMResponseException,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.validation import (
    validate_required_parameters,
    validate_parameter_types,
    validate_parameter_formats,
    validate_api_response,
    validate_choice,
    validate_list_elements,
    validate_dict_keys,
    DOCUMENTATION_LINKS,
)

_metadata = dict()
_login_flags = dict(
    prevent_ui_login=dict(type="bool", required=False, default=False),
)

argument_spec = dict(
    op_type=dict(
        type="str", choices=["create", "patch", "changepw", "patch_self"], required=True
    ),
    cm_user_id=dict(type="str"),
    allowed_auth_methods=dict(
        type="list", elements="str", required=False, default=["password"]
    ),
    app_metadata=dict(type="dict", options=_metadata, required=False),
    certificate_subject_dn=dict(type="str", required=False),
    connection=dict(type="str", required=False, default="local_account"),
    email=dict(type="str", required=False),
    enable_cert_auth=dict(type="bool", required=False),
    is_domain_user=dict(type="bool", required=False),
    login_flags=dict(type="dict", options=_login_flags, required=False),
    name=dict(type="str", required=False),
    password=dict(type="str", required=False),
    password_change_required=dict(type="bool", required=False),
    user_id=dict(type="str", required=False),
    user_metadata=dict(type="dict", options=_metadata, required=False),
    username=dict(type="str"),  # Not needed in self update, else needed
    failed_logins_count=dict(type="int"),  # Needed only for patch operation
    new_password=dict(type="str"),  # Needed only for change pwd operation
    auth_domain=dict(type="str"),  # Needed only for change pwd operation
)


def validate_parameters(user_module):
    # Get parameters from module
    op_type = user_module.params.get("op_type")
    username = user_module.params.get("username")
    password = user_module.params.get("password")
    new_password = user_module.params.get("new_password")
    email = user_module.params.get("email")
    name = user_module.params.get("name")
    cm_user_id = user_module.params.get("cm_user_id")
    allowed_auth_methods = user_module.params.get("allowed_auth_methods")
    connection = user_module.params.get("connection")
    enable_cert_auth = user_module.params.get("enable_cert_auth")
    certificate_subject_dn = user_module.params.get("certificate_subject_dn")
    login_flags = user_module.params.get("login_flags")
    user_metadata = user_module.params.get("user_metadata")
    app_metadata = user_module.params.get("app_metadata")
    is_domain_user = user_module.params.get("is_domain_user")
    user_id = user_module.params.get("user_id")
    password_change_required = user_module.params.get("password_change_required")
    failed_logins_count = user_module.params.get("failed_logins_count")
    auth_domain = user_module.params.get("auth_domain")

    # Validate required parameters based on op_type
    if op_type == "create":
        validate_required_parameters(
            parameters={"username": username},
            required_parameters=["username"],
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )
    elif op_type == "patch":
        validate_required_parameters(
            parameters={"cm_user_id": cm_user_id, "username": username},
            required_parameters=["cm_user_id", "username"],
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )
    elif op_type == "changepw":
        validate_required_parameters(
            parameters={
                "username": username,
                "password": password,
                "new_password": new_password,
            },
            required_parameters=["username", "password", "new_password"],
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    # Validate parameter types
    if username is not None:
        validate_parameter_types(
            parameters={"username": username},
            expected_types={"username": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if password is not None:
        validate_parameter_types(
            parameters={"password": password},
            expected_types={"password": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if new_password is not None:
        validate_parameter_types(
            parameters={"new_password": new_password},
            expected_types={"new_password": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if email is not None:
        validate_parameter_types(
            parameters={"email": email},
            expected_types={"email": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if name is not None:
        validate_parameter_types(
            parameters={"name": name},
            expected_types={"name": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if cm_user_id is not None:
        validate_parameter_types(
            parameters={"cm_user_id": cm_user_id},
            expected_types={"cm_user_id": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if allowed_auth_methods is not None:
        validate_parameter_types(
            parameters={"allowed_auth_methods": allowed_auth_methods},
            expected_types={"allowed_auth_methods": list},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if connection is not None:
        validate_parameter_types(
            parameters={"connection": connection},
            expected_types={"connection": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if enable_cert_auth is not None:
        validate_parameter_types(
            parameters={"enable_cert_auth": enable_cert_auth},
            expected_types={"enable_cert_auth": bool},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if certificate_subject_dn is not None:
        validate_parameter_types(
            parameters={"certificate_subject_dn": certificate_subject_dn},
            expected_types={"certificate_subject_dn": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if login_flags is not None:
        validate_parameter_types(
            parameters={"login_flags": login_flags},
            expected_types={"login_flags": dict},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if user_metadata is not None:
        validate_parameter_types(
            parameters={"user_metadata": user_metadata},
            expected_types={"user_metadata": dict},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if app_metadata is not None:
        validate_parameter_types(
            parameters={"app_metadata": app_metadata},
            expected_types={"app_metadata": dict},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if is_domain_user is not None:
        validate_parameter_types(
            parameters={"is_domain_user": is_domain_user},
            expected_types={"is_domain_user": bool},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if user_id is not None:
        validate_parameter_types(
            parameters={"user_id": user_id},
            expected_types={"user_id": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if password_change_required is not None:
        validate_parameter_types(
            parameters={"password_change_required": password_change_required},
            expected_types={"password_change_required": bool},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if failed_logins_count is not None:
        validate_parameter_types(
            parameters={"failed_logins_count": failed_logins_count},
            expected_types={"failed_logins_count": int},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if auth_domain is not None:
        validate_parameter_types(
            parameters={"auth_domain": auth_domain},
            expected_types={"auth_domain": str},
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    # Validate parameter formats
    if username is not None:
        validate_parameter_formats(
            parameters={"username": username},
            format_rules={
                "username": {
                    "type": "string",
                    "pattern": "^[a-zA-Z0-9._-]+$",
                    "min_length": 1,
                    "max_length": 255,
                }
            },
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if email is not None:
        validate_parameter_formats(
            parameters={"email": email},
            format_rules={
                "email": {
                    "type": "string",
                    "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
                    "min_length": 5,
                    "max_length": 254,
                }
            },
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if name is not None:
        validate_parameter_formats(
            parameters={"name": name},
            format_rules={
                "name": {
                    "type": "string",
                    "min_length": 1,
                    "max_length": 255,
                }
            },
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if cm_user_id is not None:
        validate_parameter_formats(
            parameters={"cm_user_id": cm_user_id},
            format_rules={
                "cm_user_id": {
                    "type": "string",
                    "pattern": "^(local|external)\|[a-fA-F0-9-]+$",
                    "min_length": 1,
                    "max_length": 255,
                }
            },
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if allowed_auth_methods is not None:
        validate_list_elements(
            value=allowed_auth_methods,
            parameter_name="allowed_auth_methods",
            element_type=str,
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

        # Validate allowed_auth_methods choices
        valid_auth_methods = [
            "password",
            "certificate",
            "sso",
            "mfa",
            "api_key",
        ]
        validate_choice(
            value=allowed_auth_methods,
            parameter_name="allowed_auth_methods",
            choices=valid_auth_methods,
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if connection is not None:
        validate_parameter_formats(
            parameters={"connection": connection},
            format_rules={
                "connection": {
                    "type": "string",
                    "pattern": "^[a-zA-Z0-9._-]+$",
                    "min_length": 1,
                    "max_length": 255,
                }
            },
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if certificate_subject_dn is not None:
        validate_parameter_formats(
            parameters={"certificate_subject_dn": certificate_subject_dn},
            format_rules={
                "certificate_subject_dn": {
                    "type": "string",
                    "min_length": 1,
                    "max_length": 1024,
                }
            },
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if login_flags is not None:
        validate_dict_keys(
            dictionary=login_flags,
            parameter_name="login_flags",
            valid_keys=["prevent_ui_login"],
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

        if "prevent_ui_login" in login_flags:
            validate_parameter_types(
                parameters={"prevent_ui_login": login_flags["prevent_ui_login"]},
                expected_types={"prevent_ui_login": bool},
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )

    if user_metadata is not None:
        if not isinstance(user_metadata, dict):
            raise AnsibleCMFormatException(
                parameter="user_metadata",
                expected_format="dictionary (schema-less object)",
                example="user_metadata:\n  preferences:\n    theme: dark\n  group_membership:\n    - admin\n    - users",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )

    if app_metadata is not None:
        if not isinstance(app_metadata, dict):
            raise AnsibleCMFormatException(
                parameter="app_metadata",
                expected_format="dictionary (schema-less object)",
                example="app_metadata:\n  roles:\n    - admin\n  permissions:\n    read: true\n    write: false",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )

    if is_domain_user is not None:
        if not isinstance(is_domain_user, bool):
            raise AnsibleCMFormatException(
                parameter="is_domain_user",
                expected_format="boolean (true or false)",
                example="is_domain_user: true",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )

    if user_id is not None:
        validate_parameter_formats(
            parameters={"user_id": user_id},
            format_rules={
                "user_id": {
                    "type": "string",
                    "pattern": "^[a-fA-F0-9-]+$",
                    "min_length": 1,
                    "max_length": 255,
                }
            },
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    if password_change_required is not None:
        if not isinstance(password_change_required, bool):
            raise AnsibleCMFormatException(
                parameter="password_change_required",
                expected_format="boolean (true or false)",
                example="password_change_required: true",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )

    if failed_logins_count is not None:
        if not isinstance(failed_logins_count, int):
            raise AnsibleCMFormatException(
                parameter="failed_logins_count",
                expected_format="integer (0 to unlock a locked user account)",
                example="failed_logins_count: 0",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )

    if auth_domain is not None:
        validate_parameter_formats(
            parameters={"auth_domain": auth_domain},
            format_rules={
                "auth_domain": {
                    "type": "string",
                    "pattern": "^[a-zA-Z0-9._-]+$",
                    "min_length": 1,
                    "max_length": 255,
                }
            },
            documentation_link=DOCUMENTATION_LINKS.get(
                "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
            ),
        )

    return True


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "create", ["username"]],
            ["op_type", "patch", ["cm_user_id", "username"]],
            ["op_type", "changepw", ["password", "new_password", "username"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():
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
                allowed_auth_methods=module.params.get("allowed_auth_methods"),
                app_metadata=module.params.get("app_metadata"),
                certificate_subject_dn=module.params.get("certificate_subject_dn"),
                connection=module.params.get("connection"),
                email=module.params.get("email"),
                enable_cert_auth=module.params.get("enable_cert_auth"),
                login_flags=module.params.get("login_flags"),
                prevent_ui_login_bool=module.params.get("prevent_ui_login"),
                name=module.params.get("name"),
                password=module.params.get("password"),
                password_change_required=module.params.get("password_change_required"),
                user_id=module.params.get("user_id"),
                user_metadata=module.params.get("user_metadata"),
                username=module.params.get("username"),
            )
            result["response"] = response
        except CMApiException as api_e:
            error_msg = build_error_message(
                exception=api_e,
                parameter="create operation",
                expected_format="successful user creation response",
                example="response:\n  id: user123\n  username: john.doe@example.com",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMValidationException as validation_e:
            error_msg = build_error_message(
                exception=validation_e,
                parameter="create operation",
                expected_format="valid user data",
                example="username: john.doe@example.com\npassword: 'YourPassword123!'",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMParameterException as param_e:
            error_msg = build_error_message(
                exception=param_e,
                parameter="create operation",
                expected_format="valid user parameters",
                example="username: john.doe@example.com\npassword: 'YourPassword123!'",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMFormatException as format_e:
            error_msg = build_error_message(
                exception=format_e,
                parameter="create operation",
                expected_format="valid user data format",
                example="username: john.doe@example.com\npassword: 'YourPassword123!'",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMResponseException as response_e:
            error_msg = build_error_message(
                exception=response_e,
                parameter="create operation",
                expected_format="valid user creation response",
                example="response:\n  id: user123\n  username: john.doe@example.com",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMException as custom_e:
            error_msg = build_error_message(
                exception=custom_e,
                parameter="create operation",
                expected_format="successful user creation",
                example="username: john.doe@example.com\npassword: 'YourPassword123!'",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
    elif module.params.get("op_type") == "patch":
        try:
            response = patch(
                node=module.params.get("localNode"),
                cm_user_id=module.params.get("cm_user_id"),
                allowed_auth_methods=module.params.get("allowed_auth_methods"),
                certificate_subject_dn=module.params.get("certificate_subject_dn"),
                email=module.params.get("email"),
                enable_cert_auth_bool=module.params.get("enable_cert_auth"),
                failed_logins_count=module.params.get("failed_logins_count"),
                login_flags=module.params.get("login_flags"),
                name=module.params.get("name"),
                password=module.params.get("password"),
                password_change_required=module.params.get("password_change_required"),
                user_metadata=module.params.get("user_metadata"),
                username=module.params.get("username"),
            )
            result["response"] = response
        except CMApiException as api_e:
            error_msg = build_error_message(
                exception=api_e,
                parameter="patch operation",
                expected_format="successful user update response",
                example="response:\n  id: user123\n  username: john.doe@example.com",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMValidationException as validation_e:
            error_msg = build_error_message(
                exception=validation_e,
                parameter="patch operation",
                expected_format="valid user data",
                example="cm_user_id: user123\nusername: john.doe@example.com",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMParameterException as param_e:
            error_msg = build_error_message(
                exception=param_e,
                parameter="patch operation",
                expected_format="valid user parameters",
                example="cm_user_id: user123\nusername: john.doe@example.com",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMFormatException as format_e:
            error_msg = build_error_message(
                exception=format_e,
                parameter="patch operation",
                expected_format="valid user data format",
                example="cm_user_id: user123\nusername: john.doe@example.com",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMResponseException as response_e:
            error_msg = build_error_message(
                exception=response_e,
                parameter="patch operation",
                expected_format="valid user update response",
                example="response:\n  id: user123\n  username: john.doe@example.com",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMException as custom_e:
            error_msg = build_error_message(
                exception=custom_e,
                parameter="patch operation",
                expected_format="successful user update",
                example="cm_user_id: user123\nusername: john.doe@example.com",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
    elif module.params.get("op_type") == "changepw":
        try:
            response = changepw(
                node=module.params.get("localNode"),
                password=module.params.get("password"),
                username=module.params.get("username"),
                new_password=module.params.get("new_password"),
                auth_domain=module.params.get("auth_domain"),
            )
            result["response"] = response
        except CMApiException as api_e:
            error_msg = build_error_message(
                exception=api_e,
                parameter="changepw operation",
                expected_format="successful password change response",
                example="response:\n  message: Password changed successfully",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMValidationException as validation_e:
            error_msg = build_error_message(
                exception=validation_e,
                parameter="changepw operation",
                expected_format="valid password change parameters",
                example="username: john.doe@example.com\npassword: 'YourCurrentPassword123!'\nnew_password: 'YourNewPassword456!'",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMParameterException as param_e:
            error_msg = build_error_message(
                exception=param_e,
                parameter="changepw operation",
                expected_format="valid password change parameters",
                example="username: john.doe@example.com\npassword: 'YourCurrentPassword123!'\nnew_password: 'YourNewPassword456!'",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMFormatException as format_e:
            error_msg = build_error_message(
                exception=format_e,
                parameter="changepw operation",
                expected_format="valid password format",
                example="username: john.doe@example.com\npassword: 'YourCurrentPassword123!'\nnew_password: 'YourNewPassword456!'",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMResponseException as response_e:
            error_msg = build_error_message(
                exception=response_e,
                parameter="changepw operation",
                expected_format="valid password change response",
                example="response:\n  message: Password changed successfully",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMException as custom_e:
            error_msg = build_error_message(
                exception=custom_e,
                parameter="changepw operation",
                expected_format="successful password change",
                example="username: john.doe@example.com\npassword: 'YourCurrentPassword123!'\nnew_password: 'YourNewPassword456!'",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
    elif module.params.get("op_type") == "patch_self":
        try:
            response = patch_self(
                node=module.params.get("localNode"),
                email=module.params.get("email"),
                name=module.params.get("name"),
                user_metadata=module.params.get("user_metadata"),
            )
            result["response"] = response
        except CMApiException as api_e:
            error_msg = build_error_message(
                exception=api_e,
                parameter="patch_self operation",
                expected_format="successful self-user update response",
                example="response:\n  message: User updated successfully",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMValidationException as validation_e:
            error_msg = build_error_message(
                exception=validation_e,
                parameter="patch_self operation",
                expected_format="valid self-user update parameters",
                example="email: john.doe@example.com\nname: John Doe",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMParameterException as param_e:
            error_msg = build_error_message(
                exception=param_e,
                parameter="patch_self operation",
                expected_format="valid self-user update parameters",
                example="email: john.doe@example.com\nname: John Doe",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMFormatException as format_e:
            error_msg = build_error_message(
                exception=format_e,
                parameter="patch_self operation",
                expected_format="valid user data format",
                example="email: john.doe@example.com\nname: John Doe",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMResponseException as response_e:
            error_msg = build_error_message(
                exception=response_e,
                parameter="patch_self operation",
                expected_format="valid self-user update response",
                example="response:\n  message: User updated successfully",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)
        except AnsibleCMException as custom_e:
            error_msg = build_error_message(
                exception=custom_e,
                parameter="patch_self operation",
                expected_format="successful self-user update",
                example="email: john.doe@example.com\nname: John Doe",
                documentation_link=DOCUMENTATION_LINKS.get(
                    "usermgmt_users_save", "https://thalesdocs.com/ctp/con/cm/latest/admin/user-management.html"
                ),
            )
            module.fail_json(msg=error_msg)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
