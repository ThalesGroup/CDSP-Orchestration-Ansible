# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
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
      validate_api_response,
  )
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from datetime import datetime

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


def validate_required_parameters(params, required_params, module_name=None):
    """
    Validate that all required parameters are present and not None/empty.

    Args:
        params (dict): Dictionary of parameters to validate
        required_params (list): List of required parameter names
        module_name (str, optional): Name of the module for error messages

    Returns:
        dict: Validated parameters dictionary

    Raises:
        AnsibleCMValidationException: If required parameters are missing
    """
    missing_params = []

    for param in required_params:
        if param not in params or params[param] is None or params[param] == "":
            missing_params.append(param)

    if missing_params:
        module_prefix = f"[{module_name}] " if module_name else ""
        error_msg = f"{module_prefix}Missing required parameter(s)"
        param_list = ", ".join(missing_params)
        raise AnsibleCMValidationException(
            message=error_msg,
            parameter=param_list,
            expected_format="string or value",
            example=f"Example: {missing_params[0]}: 'value'",
        )

    return params


def validate_parameter_types(params, type_definitions, module_name=None):
    """
    Validate parameter types against expected types.

    Args:
        params (dict): Dictionary of parameters to validate
        type_definitions (dict): Dictionary mapping parameter names to expected types
            Expected format: {param_name: expected_type, ...}
            Supported types: str, int, float, bool, list, dict, None
        module_name (str, optional): Name of the module for error messages

    Returns:
        dict: Validated parameters dictionary

    Raises:
        AnsibleCMValidationException: If parameter types don't match
    """
    module_prefix = f"[{module_name}] " if module_name else ""

    for param, expected_type in type_definitions.items():
        if param not in params or params[param] is None:
            continue

        actual_value = params[param]
        actual_type = type(actual_value).__name__

        # Handle type checking
        type_match = False
        if expected_type == "str" and isinstance(actual_value, str):
            type_match = True
        elif expected_type == "int" and isinstance(actual_value, int) and not isinstance(actual_value, bool):
            type_match = True
        elif expected_type == "float" and isinstance(actual_value, (int, float)) and not isinstance(actual_value, bool):
            type_match = True
        elif expected_type == "bool" and isinstance(actual_value, bool):
            type_match = True
        elif expected_type == "list" and isinstance(actual_value, list):
            type_match = True
        elif expected_type == "dict" and isinstance(actual_value, dict):
            type_match = True
        elif expected_type == "None" and actual_value is None:
            type_match = True
        elif expected_type == "any":
            type_match = True

        if not type_match:
            error_msg = f"{module_prefix}Invalid type for parameter"
            raise AnsibleCMValidationException(
                message=error_msg,
                parameter=param,
                expected_format=str(expected_type),
                example=f"Example: {param}: {get_type_example(expected_type)}",
            )

    return params


def validate_parameter_formats(params, format_definitions, module_name=None):
    """
    Validate parameter formats against regex patterns and format rules.

    Args:
        params (dict): Dictionary of parameters to validate
        format_definitions (dict): Dictionary mapping parameter names to format rules
            Expected format: {
                param_name: {
                    'pattern': regex_pattern,
                    'min_length': min_length,
                    'max_length': max_length,
                    'format': 'email'|'url'|'date'|'datetime'|'uuid'|'custom'
                }
            }
        module_name (str, optional): Name of the module for error messages

    Returns:
        dict: Validated parameters dictionary

    Raises:
        AnsibleCMValidationException: If parameter formats don't match
    """
    module_prefix = f"[{module_name}] " if module_name else ""

    for param, rules in format_definitions.items():
        if param not in params or params[param] is None or params[param] == "":
            continue

        value = params[param]

        # Check regex pattern
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

    return params


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


def validate_api_response(response, expected_fields=None, module_name=None):
    """
    Validate API response structure and content.

    Args:
        response (dict): The API response to validate
        expected_fields (list, optional): List of expected field names
        module_name (str, optional): Name of the module for error messages

    Returns:
        dict: Validated response dictionary

    Raises:
        AnsibleCMResponseException: If response validation fails
    """
    module_prefix = f"[{module_name}] " if module_name else ""

    # Check if response is a dictionary
    if not isinstance(response, dict):
        error_msg = f"{module_prefix}API response is not a valid JSON object"
        raise AnsibleCMResponseException(
            message=error_msg,
            response=str(response)[:200],
            expected_fields="dict",
            actual_fields=type(response).__name__,
        )

    # Check for error indicators in response
    error_indicators = ["error", "Error", "ERROR", "codeDesc", "errorCode"]
    for indicator in error_indicators:
        if indicator in response:
            error_msg = f"{module_prefix}API returned error response"
            raise AnsibleCMResponseException(
                message=error_msg,
                response=str(response)[:200],
                expected_fields=["success", "data", "message"],
                actual_fields=list(response.keys()),
            )

    # Check for expected fields if provided
    if expected_fields:
        missing_fields = []
        for field in expected_fields:
            if field not in response:
                missing_fields.append(field)

        if missing_fields:
            error_msg = f"{module_prefix}API response missing expected field(s)"
            raise AnsibleCMResponseException(
                message=error_msg,
                response=str(response)[:200],
                expected_fields=missing_fields,
                actual_fields=list(response.keys()),
            )

    return response


def validate_choice(param_name, param_value, choices, module_name=None):
    """
    Validate that a parameter value is one of the allowed choices.

    Args:
        param_name (str): Name of the parameter
        param_value: The value to validate
        choices (list): List of allowed values
        module_name (str, optional): Name of the module for error messages

    Returns:
        str: The validated parameter value

    Raises:
        AnsibleCMParameterException: If value is not in allowed choices
    """
    module_prefix = f"[{module_name}] " if module_name else ""

    if param_value is None:
        return param_value

    if param_value not in choices:
        error_msg = f"{module_prefix}Invalid value for parameter"
        raise AnsibleCMParameterException(
            message=error_msg,
            parameter=param_name,
            valid_values=choices,
            example=f"Example: {param_name}: '{choices[0]}'",
        )

    return param_value


def validate_list_elements(params, list_rules, module_name=None):
    """
    Validate list parameters and their elements.

    Args:
        params (dict): Dictionary of parameters to validate
        list_rules (dict): Rules for list parameters
            Expected format: {
                param_name: {
                    'min_items': min_items,
                    'max_items': max_items,
                    'element_type': 'str'|'dict'|'int',
                    'required_keys': ['key1', 'key2']  # for dict elements
                }
            }
        module_name (str, optional): Name of the module for error messages

    Returns:
        dict: Validated parameters dictionary

    Raises:
        AnsibleCMValidationException: If list validation fails
    """
    module_prefix = f"[{module_name}] " if module_name else ""

    for param, rules in list_rules.items():
        if param not in params or params[param] is None:
            continue

        value = params[param]

        if not isinstance(value, list):
            error_msg = f"{module_prefix}Parameter must be a list"
            raise AnsibleCMValidationException(
                message=error_msg,
                parameter=param,
                expected_format="list",
                example=f"Example: {param}: [{{'key': 'value'}}]",
            )

        # Check min_items
        if "min_items" in rules:
            if len(value) < rules["min_items"]:
                error_msg = f"{module_prefix}Parameter must have at least {rules['min_items']} items"
                raise AnsibleCMValidationException(
                    message=error_msg,
                    parameter=param,
                    expected_format=f"list with {rules['min_items']}+ items",
                    example=f"Example: {param}: [{{'item1'}}, {{'item2'}}]",
                )

        # Check max_items
        if "max_items" in rules:
            if len(value) > rules["max_items"]:
                error_msg = f"{module_prefix}Parameter must have at most {rules['max_items']} items"
                raise AnsibleCMValidationException(
                    message=error_msg,
                    parameter=param,
                    expected_format=f"list with {rules['max_items']} items",
                    example=f"Example: {param}: [{{'item1'}}]",
                )

        # Check element type
        if "element_type" in rules:
            element_type = rules["element_type"]
            for i, item in enumerate(value):
                if element_type == "str" and not isinstance(item, str):
                    error_msg = f"{module_prefix}List item {i} must be a string"
                    raise AnsibleCMValidationException(
                        message=error_msg,
                        parameter=param,
                        expected_format="list of strings",
                        example=f"Example: {param}: ['item1', 'item2']",
                    )
                elif element_type == "dict" and not isinstance(item, dict):
                    error_msg = f"{module_prefix}List item {i} must be a dictionary"
                    raise AnsibleCMValidationException(
                        message=error_msg,
                        parameter=param,
                        expected_format="list of dictionaries",
                        example=f"Example: {param}: [{{'key': 'value'}}]",
                    )

        # Check required keys for dict elements
        if "required_keys" in rules and rules["required_keys"]:
            required_keys = rules["required_keys"]
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    missing_keys = [key for key in required_keys if key not in item]
                    if missing_keys:
                        error_msg = f"{module_prefix}List item {i} missing required key(s)"
                        raise AnsibleCMValidationException(
                            message=error_msg,
                            parameter=param,
                            expected_format=f"list of dicts with keys: {required_keys}",
                            example=f"Example: {param}: [{{'{required_keys[0]}': 'value'}}]",
                        )

    return params


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
