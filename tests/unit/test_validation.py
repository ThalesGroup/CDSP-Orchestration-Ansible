#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""Unit tests for validation functions."""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.validation import (
    validate_required_parameters,
    validate_parameter_types,
    validate_parameter_formats,
    validate_api_response,
    validate_choice,
    validate_list_elements,
    validate_dict_keys,
    AnsibleCMValidationException,
    AnsibleCMParameterException,
    AnsibleCMFormatException,
    AnsibleCMResponseException,
)


class TestValidateRequiredParameters:
    """Tests for validate_required_parameters function."""

    def test_all_required_params_present(self):
        """Test when all required parameters are present."""
        params = {"name": "test", "value": "123"}
        required_params = ["name", "value"]
        result = validate_required_parameters(params, required_params)
        assert result == params

    def test_missing_required_param(self):
        """Test when a required parameter is missing."""
        params = {"name": "test"}
        required_params = ["name", "value"]

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_required_parameters(params, required_params)

        assert "Missing required parameter(s)" in str(exc_info.value)
        assert "value" in str(exc_info.value)

    def test_none_value(self):
        """Test when a required parameter has None value."""
        params = {"name": "test", "value": None}
        required_params = ["name", "value"]

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_required_parameters(params, required_params)

        assert "Missing required parameter(s)" in str(exc_info.value)

    def test_empty_string(self):
        """Test when a required parameter has empty string value."""
        params = {"name": "test", "value": ""}
        required_params = ["name", "value"]

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_required_parameters(params, required_params)

        assert "Missing required parameter(s)" in str(exc_info.value)

    def test_with_module_name(self):
        """Test with module name in error message."""
        params = {"name": "test"}
        required_params = ["name", "value"]

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_required_parameters(params, required_params, module_name="test_module")

        assert "[test_module]" in str(exc_info.value)


class TestValidateParameterTypes:
    """Tests for validate_parameter_types function."""

    def test_all_types_valid(self):
        """Test when all parameter types are valid."""
        params = {
            "name": "test",
            "count": 42,
            "price": 19.99,
            "active": True,
            "tags": ["a", "b"],
            "metadata": {"key": "value"},
        }
        type_definitions = {
            "name": "str",
            "count": "int",
            "price": "float",
            "active": "bool",
            "tags": "list",
            "metadata": "dict",
        }
        result = validate_parameter_types(params, type_definitions)
        assert result == params

    def test_invalid_type(self):
        """Test when a parameter has invalid type."""
        params = {"name": 123, "count": "42"}
        type_definitions = {"name": "str", "count": "int"}

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_parameter_types(params, type_definitions)

        assert "Invalid type" in str(exc_info.value)

    def test_bool_as_int(self):
        """Test that bool is not accepted as int."""
        params = {"count": True}
        type_definitions = {"count": "int"}

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_parameter_types(params, type_definitions)

        assert "Invalid type" in str(exc_info.value)

    def test_with_module_name(self):
        """Test with module name in error message."""
        params = {"name": 123}
        type_definitions = {"name": "str"}

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_parameter_types(params, type_definitions, module_name="test_module")

        assert "[test_module]" in str(exc_info.value)


class TestValidateParameterFormats:
    """Tests for validate_parameter_formats function."""

    def test_valid_email(self):
        """Test valid email format."""
        params = {"email": "user@example.com"}
        format_definitions = {
            "email": {"format": "email"}
        }
        result = validate_parameter_formats(params, format_definitions)
        assert result == params

    def test_invalid_email(self):
        """Test invalid email format."""
        params = {"email": "invalid-email"}
        format_definitions = {
            "email": {"format": "email"}
        }

        with pytest.raises(AnsibleCMFormatException) as exc_info:
            validate_parameter_formats(params, format_definitions)

        assert "Invalid format" in str(exc_info.value)

    def test_valid_url(self):
        """Test valid URL format."""
        params = {"url": "https://example.com"}
        format_definitions = {
            "url": {"format": "url"}
        }
        result = validate_parameter_formats(params, format_definitions)
        assert result == params

    def test_valid_date(self):
        """Test valid date format."""
        params = {"date": "2023-12-31"}
        format_definitions = {
            "date": {"format": "date"}
        }
        result = validate_parameter_formats(params, format_definitions)
        assert result == params

    def test_valid_uuid(self):
        """Test valid UUID format."""
        params = {"uuid": "123e4567-e89b-12d3-a456-426614174000"}
        format_definitions = {
            "uuid": {"format": "uuid"}
        }
        result = validate_parameter_formats(params, format_definitions)
        assert result == params

    def test_regex_pattern(self):
        """Test regex pattern validation."""
        params = {"name": "test_name"}
        format_definitions = {
            "name": {"pattern": r"^[a-zA-Z0-9_-]+$"}
        }
        result = validate_parameter_formats(params, format_definitions)
        assert result == params

    def test_invalid_regex_pattern(self):
        """Test invalid regex pattern."""
        params = {"name": "test@name"}
        format_definitions = {
            "name": {"pattern": r"^[a-zA-Z0-9_-]+$"}
        }

        with pytest.raises(AnsibleCMFormatException) as exc_info:
            validate_parameter_formats(params, format_definitions)

        assert "does not match expected format" in str(exc_info.value)

    def test_min_length(self):
        """Test minimum length validation."""
        params = {"name": "ab"}
        format_definitions = {
            "name": {"min_length": 3}
        }

        with pytest.raises(AnsibleCMFormatException) as exc_info:
            validate_parameter_formats(params, format_definitions)

        assert "too short" in str(exc_info.value)

    def test_max_length(self):
        """Test maximum length validation."""
        params = {"name": "this_is_a_very_long_name"}
        format_definitions = {
            "name": {"max_length": 10}
        }

        with pytest.raises(AnsibleCMFormatException) as exc_info:
            validate_parameter_formats(params, format_definitions)

        assert "too long" in str(exc_info.value)

    def test_with_module_name(self):
        """Test with module name in error message."""
        params = {"email": "invalid"}
        format_definitions = {
            "email": {"format": "email"}
        }

        with pytest.raises(AnsibleCMFormatException) as exc_info:
            validate_parameter_formats(params, format_definitions, module_name="test_module")

        assert "[test_module]" in str(exc_info.value)


class TestValidateAPIResponse:
    """Tests for validate_api_response function."""

    def test_valid_response(self):
        """Test valid API response."""
        response = {"id": "123", "name": "test", "status": "active"}
        result = validate_api_response(response)
        assert result == response

    def test_error_response(self):
        """Test error response from API."""
        response = {"error": "Something went wrong", "code": 500}

        with pytest.raises(AnsibleCMResponseException) as exc_info:
            validate_api_response(response)

        assert "API returned error response" in str(exc_info.value)

    def test_missing_expected_fields(self):
        """Test when expected fields are missing."""
        response = {"id": "123"}
        expected_fields = ["id", "name", "status"]

        with pytest.raises(AnsibleCMResponseException) as exc_info:
            validate_api_response(response, expected_fields)

        assert "missing expected field(s)" in str(exc_info.value)

    def test_non_dict_response(self):
        """Test when response is not a dictionary."""
        response = "not a dict"

        with pytest.raises(AnsibleCMResponseException) as exc_info:
            validate_api_response(response)

        assert "not a valid JSON object" in str(exc_info.value)

    def test_with_module_name(self):
        """Test with module name in error message."""
        response = {"error": "Error occurred"}

        with pytest.raises(AnsibleCMResponseException) as exc_info:
            validate_api_response(response, module_name="test_module")

        assert "[test_module]" in str(exc_info.value)


class TestValidateChoice:
    """Tests for validate_choice function."""

    def test_valid_choice(self):
        """Test valid choice value."""
        result = validate_choice("status", "active", ["active", "inactive", "pending"])
        assert result == "active"

    def test_invalid_choice(self):
        """Test invalid choice value."""
        with pytest.raises(AnsibleCMParameterException) as exc_info:
            validate_choice("status", "unknown", ["active", "inactive"])

        assert "Invalid value" in str(exc_info.value)
        assert "active" in str(exc_info.value) or "inactive" in str(exc_info.value)

    def test_none_value(self):
        """Test None value is allowed."""
        result = validate_choice("status", None, ["active", "inactive"])
        assert result is None

    def test_with_module_name(self):
        """Test with module name in error message."""
        with pytest.raises(AnsibleCMParameterException) as exc_info:
            validate_choice("status", "unknown", ["active", "inactive"], module_name="test_module")

        assert "[test_module]" in str(exc_info.value)


class TestValidateListElements:
    """Tests for validate_list_elements function."""

    def test_valid_list(self):
        """Test valid list."""
        params = {"tags": ["a", "b", "c"]}
        list_rules = {
            "tags": {"element_type": "str"}
        }
        result = validate_list_elements(params, list_rules)
        assert result == params

    def test_list_too_short(self):
        """Test when list has fewer items than required."""
        params = {"tags": ["a"]}
        list_rules = {
            "tags": {"min_items": 2}
        }

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_list_elements(params, list_rules)

        assert "at least" in str(exc_info.value)

    def test_list_too_long(self):
        """Test when list has more items than allowed."""
        params = {"tags": ["a", "b", "c"]}
        list_rules = {
            "tags": {"max_items": 2}
        }

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_list_elements(params, list_rules)

        assert "at most" in str(exc_info.value)

    def test_invalid_element_type(self):
        """Test when list elements have invalid type."""
        params = {"tags": ["a", 123, "c"]}
        list_rules = {
            "tags": {"element_type": "str"}
        }

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_list_elements(params, list_rules)

        assert "must be a string" in str(exc_info.value)

    def test_dict_elements_with_required_keys(self):
        """Test dict elements with required keys."""
        params = {"items": [{"name": "test", "value": "123"}]}
        list_rules = {
            "items": {
                "element_type": "dict",
                "required_keys": ["name", "value"]
            }
        }
        result = validate_list_elements(params, list_rules)
        assert result == params

    def test_dict_elements_missing_keys(self):
        """Test dict elements missing required keys."""
        params = {"items": [{"name": "test"}]}
        list_rules = {
            "items": {
                "element_type": "dict",
                "required_keys": ["name", "value"]
            }
        }

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_list_elements(params, list_rules)

        assert "missing required key" in str(exc_info.value)


class TestValidateDictKeys:
    """Tests for validate_dict_keys function."""

    def test_valid_dict(self):
        """Test valid dictionary."""
        params = {"metadata": {"name": "test", "count": 42}}
        dict_rules = {
            "metadata": {
                "required_keys": ["name", "count"],
                "key_types": {"name": "str", "count": "int"}
            }
        }
        result = validate_dict_keys(params, dict_rules)
        assert result == params

    def test_missing_required_keys(self):
        """Test when required keys are missing."""
        params = {"metadata": {"name": "test"}}
        dict_rules = {
            "metadata": {
                "required_keys": ["name", "count"]
            }
        }

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_dict_keys(params, dict_rules)

        assert "missing required key" in str(exc_info.value)

    def test_invalid_key_type(self):
        """Test when key has invalid type."""
        params = {"metadata": {"name": "test", "count": "42"}}
        dict_rules = {
            "metadata": {
                "required_keys": ["name", "count"],
                "key_types": {"count": "int"}
            }
        }

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_dict_keys(params, dict_rules)

        assert "has invalid type" in str(exc_info.value)

    def test_non_dict_parameter(self):
        """Test when parameter is not a dictionary."""
        params = {"metadata": "not a dict"}
        dict_rules = {
            "metadata": {"required_keys": ["key"]}
        }

        with pytest.raises(AnsibleCMValidationException) as exc_info:
            validate_dict_keys(params, dict_rules)

        assert "must be a dictionary" in str(exc_info.value)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
