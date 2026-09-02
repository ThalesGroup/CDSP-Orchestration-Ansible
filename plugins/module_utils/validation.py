# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""This module adds validation functions for Thales CipherTrust modules.

In order to use this module, include it as part of a custom
module as shown below.
  from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.validation import (
      validate_required_parameters,
      validate_parameter_types,
      validate_parameter_formats,
  )
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from datetime import datetime
from .exceptions import (
    AnsibleCMValidationException,
    AnsibleCMFormatException,
    AnsibleCMParameterException,
)

# Documentation links for common parameters
DOCUMENTATION_LINKS = {
    "vault_keys2_save": "https://docs.thalesgroup.com/ciphertrust/key-management/vault-keys2-save",
    "dpg_policy_save": "https://docs.thalesgroup.com/ciphertrust/dpg-policy-save",
    "interface_save": "https://docs.thalesgroup.com/ciphertrust/interface-save",
    "usermgmt_users_save": "https://docs.thalesgroup.com/ciphertrust/usermgmt-users-save",
    "cm_cluster": "https://docs.thalesgroup.com/ciphertrust/cm-cluster",
    "cm_certificate_authority": "https://docs.thalesgroup.com/ciphertrust/cm-certificate-authority",
    "default": "https://docs.thalesgroup.com/ciphertrust/ansible-collection",
}


def _as_params(source):
    """Accept either a parameter dict or a module-like object carrying one.

    Callers pass a module (``user_module``/``dpg_policy_module``) in some
    places and a plain dict in others; both are supported, but the argument
    is always named ``parameters``.
    """
    if source is None:
        return {}
    if hasattr(source, "params"):
        source = source.params
    return source if source is not None else {}


def validate_required_parameters(parameters, required, module_name=None,
                                 documentation_link=None):
    """Raise unless every name in *required* is present and non-empty."""
    actual_params = _as_params(parameters)
    missing_params = []

    for param in required or []:
        if (param not in actual_params
                or actual_params[param] is None
                or actual_params[param] == ""):
            missing_params.append(param)

    if missing_params:
        module_prefix = f"[{module_name}] " if module_name else ""
        raise AnsibleCMValidationException(
            message=f"{module_prefix}Missing required parameter(s)",
            parameter=", ".join(missing_params),
            expected_format="string or value",
            example=f"Example: {missing_params[0]}: 'value'",
            documentation_link=documentation_link,
        )

    return actual_params


def validate_parameter_types(parameters, expected_types, module_name=None,
                             documentation_link=None):
    """Raise unless each named parameter has the expected Python type."""
    actual_params = _as_params(parameters)
    types = expected_types or {}

    module_prefix = f"[{module_name}] " if module_name else ""

    for param, expected_type in types.items():
        if param not in actual_params or actual_params[param] is None:
            continue

        actual_value = actual_params[param]

        # Handle type checking
        type_match = False
        if expected_type in ("str", str) and isinstance(actual_value, str):
            type_match = True
        elif expected_type in ("int", int) and isinstance(actual_value, int) and not isinstance(actual_value, bool):
            type_match = True
        elif expected_type in ("float", float) and isinstance(actual_value, (int, float)) and not isinstance(actual_value, bool):
            type_match = True
        elif expected_type in ("bool", bool) and isinstance(actual_value, bool):
            type_match = True
        elif expected_type in ("list", list) and isinstance(actual_value, list):
            type_match = True
        elif expected_type in ("dict", dict) and isinstance(actual_value, dict):
            type_match = True
        elif expected_type in ("None", type(None)) and actual_value is None:
            type_match = True
        elif expected_type == "any":
            type_match = True

        if not type_match:
            error_msg = f"{module_prefix}Invalid type for parameter"
            raise AnsibleCMValidationException(
                message=error_msg,
                parameter=param,
                expected_format=str(expected_type),
                example=f"Example: {param}: {get_type_example(str(expected_type))}",
            )

    return actual_params


def validate_parameter_formats(parameters, format_rules, module_name=None,
                               documentation_link=None):
    """Raise unless each named parameter matches its format rule."""
    actual_params = _as_params(parameters)
    formats = format_rules or {}

    module_prefix = f"[{module_name}] " if module_name else ""

    for param, rules in formats.items():
        if param not in actual_params or actual_params[param] is None or actual_params[param] == "":
            continue

        value = actual_params[param]

        # Check for direct regex string
        if isinstance(rules, str):
            pattern = rules
            if not re.match(pattern, str(value)):
                error_msg = f"{module_prefix}Parameter does not match expected format"
                raise AnsibleCMFormatException(
                    message=error_msg,
                    parameter=param,
                    expected_format=f"Pattern: {pattern}",
                    example=f"Example: {param}: '{get_pattern_example(pattern)}'",
                    regex_pattern=pattern,
                )
            continue

        # Check regex pattern in rules dict
        if "pattern" in rules:
            pattern = rules["pattern"]
            if not re.match(pattern, str(value)):
                error_msg = f"{module_prefix}Parameter does not match expected format"
                raise AnsibleCMFormatException(
                    message=error_msg,
                    parameter=param,
                    expected_format=f"Pattern: {pattern}",
                    example=f"Example: {param}: '{get_pattern_example(pattern)}'",
                    regex_pattern=pattern,
                )

        # Check min_length
        if "min_length" in rules:
            if len(str(value)) < rules["min_length"]:
                error_msg = f"{module_prefix}Parameter is too short"
                raise AnsibleCMFormatException(
                    message=error_msg,
                    parameter=param,
                    expected_format=f"Minimum length: {rules['min_length']}",
                    example=f"Example: {param}: '{value}' (at least {rules['min_length']} characters)",
                )

        # Check max_length
        if "max_length" in rules:
            if len(str(value)) > rules["max_length"]:
                error_msg = f"{module_prefix}Parameter is too long"
                raise AnsibleCMFormatException(
                    message=error_msg,
                    parameter=param,
                    expected_format=f"Maximum length: {rules['max_length']}",
                    example=f"Example: {param}: '{value}' (max {rules['max_length']} characters)",
                )

        # Check specific format types
        format_type = rules.get("format")
        if format_type:
            if not validate_format_type(value, format_type, param, module_prefix):
                raise AnsibleCMFormatException(
                    message=f"{module_prefix}Invalid format for parameter",
                    parameter=param,
                    expected_format=format_type,
                    example=f"Example: {param}: '{get_format_example(format_type)}'",
                )

    return actual_params


def validate_format_type(value, format_type, param, module_prefix=""):
    """
    Validate a value against a specific format type.

    Args:
        value: The value to validate
        format_type (str): The format type to validate against
        param (str): Parameter name for error messages
        module_prefix (str): Module prefix for error messages

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        if format_type == "email":
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(email_pattern, str(value)))

        elif format_type == "url":
            url_pattern = r'^https?://[a-zA-Z0-9.-]+(:\d+)?(/.*)?$'
            return bool(re.match(url_pattern, str(value)))

        elif format_type == "date":
            datetime.strptime(str(value), "%Y-%m-%d")
            return True

        elif format_type == "datetime":
            datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ")
            return True

        elif format_type == "uuid":
            uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            return bool(re.match(uuid_pattern, str(value).lower()))

        elif format_type == "name":
            # Name should not contain special characters like <, >, \
            name_pattern = r'^[a-zA-Z0-9 _-]+$'
            return bool(re.match(name_pattern, str(value)))

        elif format_type == "id":
            # ID should be alphanumeric with possible hyphens
            id_pattern = r'^[a-zA-Z0-9_-]+$'
            return bool(re.match(id_pattern, str(value)))

        elif format_type == "api_url":
            # API URL format
            api_url_pattern = r'^https?://[a-zA-Z0-9.-]+(:\d+)?(/api/v\d+)?(/.*)?$'
            return bool(re.match(api_url_pattern, str(value)))

        else:
            # Unknown format type, assume valid
            return True

    except (ValueError, TypeError):
        return False


def validate_choice(parameter_name, value, choices, module_name=None,
                    documentation_link=None):
    """Raise unless *value* is one of *choices*. ``None`` is allowed."""
    p_name = parameter_name
    p_value = value
    p_choices = choices or []

    module_prefix = f"[{module_name}] " if module_name else ""

    if p_value is None:
        return None

    if p_value not in p_choices:
        error_msg = f"{module_prefix}Invalid value for parameter"
        raise AnsibleCMParameterException(
            message=error_msg,
            parameter=p_name,
            expected_format=f"One of: {', '.join(map(str, p_choices))}",
            example=f"Example: {p_name}: {p_choices[0] if p_choices else 'value'}",
        )

    return p_value


def validate_dict_keys(params, dict_rules, module_name=None):
    """
    Validate dictionary parameters and their keys.

    Args:
        params (dict): Dictionary of parameters to validate
        dict_rules (dict): Rules for dictionary parameters
            Expected format: {
                param_name: {
                    'required_keys': ['key1', 'key2'],
                    'optional_keys': ['key3', 'key4'],
                    'key_types': {'key1': 'str', 'key2': 'int'}
                }
            }
        module_name (str, optional): Name of the module for error messages

    Returns:
        dict: Validated parameters dictionary

    Raises:
        AnsibleCMValidationException: If dict validation fails
    """
    module_prefix = f"[{module_name}] " if module_name else ""

    for param, rules in dict_rules.items():
        if param not in params or params[param] is None:
            continue

        value = params[param]

        if not isinstance(value, dict):
            error_msg = f"{module_prefix}Parameter must be a dictionary"
            raise AnsibleCMValidationException(
                message=error_msg,
                parameter=param,
                expected_format="dictionary",
                example=f"Example: {param}: {{'key': 'value'}}",
            )

        # Check required keys
        if "required_keys" in rules and rules["required_keys"]:
            required_keys = rules["required_keys"]
            missing_keys = [key for key in required_keys if key not in value]
            if missing_keys:
                error_msg = f"{module_prefix}Dictionary missing required key(s)"
                raise AnsibleCMValidationException(
                    message=error_msg,
                    parameter=param,
                    expected_format=f"dict with keys: {required_keys}",
                    example=f"Example: {param}: {{'{required_keys[0]}': 'value'}}",
                )

        # Check key types
        if "key_types" in rules and rules["key_types"]:
            key_types = rules["key_types"]
            for key, expected_type in key_types.items():
                if key in value:
                    actual_type = type(value[key]).__name__
                    type_match = False

                    if expected_type == "str" and isinstance(value[key], str):
                        type_match = True
                    elif expected_type == "int" and isinstance(value[key], int) and not isinstance(value[key], bool):
                        type_match = True
                    elif expected_type == "bool" and isinstance(value[key], bool):
                        type_match = True
                    elif expected_type == "dict" and isinstance(value[key], dict):
                        type_match = True
                    elif expected_type == "list" and isinstance(value[key], list):
                        type_match = True

                    if not type_match:
                        error_msg = f"{module_prefix}Dictionary key '{key}' has invalid type"
                        raise AnsibleCMValidationException(
                            message=error_msg,
                            parameter=f"{param}.{key}",
                            expected_format=str(expected_type),
                            example=f"Example: {param}: {{'{key}': {get_type_example(expected_type)}}}",
                        )

    return params


def get_type_example(type_name):
    """Get an example value for a given type."""
    examples = {
        "str": "'example'",
        "int": "123",
        "float": "123.45",
        "bool": "true",
        "list": "[item1, item2]",
        "dict": "{'key': 'value'}",
        "None": "null",
    }
    return examples.get(type_name, "value")


def get_pattern_example(pattern):
    """Get an example value for a given regex pattern."""
    examples = {
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$': 'user@example.com',
        r'^https?://[a-zA-Z0-9.-]+(:\d+)?(/.*)?$': 'https://example.com',
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$': '123e4567-e89b-12d3-a456-426614174000',
        r'^[a-zA-Z0-9 _-]+$': 'example_name-123',
    }
    return examples.get(pattern, 'valid_value')


def get_format_example(format_type):
    """Get an example value for a given format type."""
    examples = {
        "email": "user@example.com",
        "url": "https://example.com",
        "date": "2023-12-31",
        "datetime": "2023-12-31T23:59:59Z",
        "uuid": "123e4567-e89b-12d3-a456-426614174000",
        "name": "example_name",
        "id": "example-id-123",
        "api_url": "https://example.com/api/v1",
    }
    return examples.get(format_type, "valid_value")
