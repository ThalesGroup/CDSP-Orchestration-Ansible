#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Simple test runner for validation tests."""

import sys
import os

# Add the plugins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "plugins", "module_utils"))

try:
    from validation import (
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
    print("SUCCESS: All imports from validation module successful")
except Exception as e:
    print(f"ERROR: Import failed - {e}")
    sys.exit(1)

# Test validate_required_parameters
print("\n=== Testing validate_required_parameters ===")
try:
    # Test 1: All required params present
    params = {"name": "test", "value": "123"}
    required_params = ["name", "value"]
    result = validate_required_parameters(params, required_params)
    assert result == params
    print("TEST 1 PASSED: All required params present")
    
    # Test 2: Missing required param
    try:
        params = {"name": "test"}
        required_params = ["name", "value"]
        validate_required_parameters(params, required_params)
        print("TEST 2 FAILED: Should have raised exception")
    except AnsibleCMValidationException as e:
        print(f"TEST 2 PASSED: Missing required param - {e}")
    
    # Test 3: None value
    try:
        params = {"name": "test", "value": None}
        required_params = ["name", "value"]
        validate_required_parameters(params, required_params)
        print("TEST 3 FAILED: Should have raised exception")
    except AnsibleCMValidationException as e:
        print(f"TEST 3 PASSED: None value - {e}")
    
    # Test 4: Empty string
    try:
        params = {"name": "test", "value": ""}
        required_params = ["name", "value"]
        validate_required_parameters(params, required_params)
        print("TEST 4 FAILED: Should have raised exception")
    except AnsibleCMValidationException as e:
        print(f"TEST 4 PASSED: Empty string - {e}")
    
    # Test 5: With module name
    try:
        params = {"name": "test"}
        required_params = ["name", "value"]
        validate_required_parameters(params, required_params, module_name="test_module")
        print("TEST 5 FAILED: Should have raised exception")
    except AnsibleCMValidationException as e:
        print(f"TEST 5 PASSED: With module name - {e}")
        
except Exception as e:
    print(f"ERROR in validate_required_parameters tests: {e}")

# Test validate_parameter_types
print("\n=== Testing validate_parameter_types ===")
try:
    # Test 1: All types valid
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
    print("TEST 1 PASSED: All types valid")
    
    # Test 2: Invalid type
    try:
        params = {"name": 123}
        type_definitions = {"name": "str"}
        validate_parameter_types(params, type_definitions)
        print("TEST 2 FAILED: Should have raised exception")
    except AnsibleCMParameterException as e:
        print(f"TEST 2 PASSED: Invalid type - {e}")
        
except Exception as e:
    print(f"ERROR in validate_parameter_types tests: {e}")

# Test validate_parameter_formats
print("\n=== Testing validate_parameter_formats ===")
try:
    # Test 1: Valid email format
    params = {"email": "test@example.com"}
    format_definitions = {"email": "email"}
    result = validate_parameter_formats(params, format_definitions)
    assert result == params
    print("TEST 1 PASSED: Valid email format")
    
    # Test 2: Invalid email format
    try:
        params = {"email": "invalid-email"}
        format_definitions = {"email": "email"}
        validate_parameter_formats(params, format_definitions)
        print("TEST 2 FAILED: Should have raised exception")
    except AnsibleCMFormatException as e:
        print(f"TEST 2 PASSED: Invalid email format - {e}")
    
    # Test 3: Valid UUID format
    params = {"id": "123e4567-e89b-12d3-a456-426614174000"}
    format_definitions = {"id": "uuid"}
    result = validate_parameter_formats(params, format_definitions)
    assert result == params
    print("TEST 3 PASSED: Valid UUID format")
    
    # Test 4: Invalid UUID format
    try:
        params = {"id": "invalid-uuid"}
        format_definitions = {"id": "uuid"}
        validate_parameter_formats(params, format_definitions)
        print("TEST 4 FAILED: Should have raised exception")
    except AnsibleCMFormatException as e:
        print(f"TEST 4 PASSED: Invalid UUID format - {e}")
        
except Exception as e:
    print(f"ERROR in validate_parameter_formats tests: {e}")

# Test validate_choice
print("\n=== Testing validate_choice ===")
try:
    # Test 1: Valid choice
    result = validate_choice("create", ["create", "patch", "delete"])
    assert result == "create"
    print("TEST 1 PASSED: Valid choice")
    
    # Test 2: Invalid choice
    try:
        validate_choice("invalid", ["create", "patch", "delete"])
        print("TEST 2 FAILED: Should have raised exception")
    except AnsibleCMValidationException as e:
        print(f"TEST 2 PASSED: Invalid choice - {e}")
        
except Exception as e:
    print(f"ERROR in validate_choice tests: {e}")

# Test validate_list_elements
print("\n=== Testing validate_list_elements ===")
try:
    # Test 1: All elements valid
    result = validate_list_elements(["create", "patch"], ["create", "patch", "delete"], "op_type")
    assert result == ["create", "patch"]
    print("TEST 1 PASSED: All elements valid")
    
    # Test 2: Invalid element
    try:
        validate_list_elements(["create", "invalid"], ["create", "patch", "delete"], "op_type")
        print("TEST 2 FAILED: Should have raised exception")
    except AnsibleCMValidationException as e:
        print(f"TEST 2 PASSED: Invalid element - {e}")
        
except Exception as e:
    print(f"ERROR in validate_list_elements tests: {e}")

# Test validate_dict_keys
print("\n=== Testing validate_dict_keys ===")
try:
    # Test 1: All keys valid
    result = validate_dict_keys({"name": "test", "value": "123"}, ["name", "value", "extra"])
    assert result == {"name": "test", "value": "123"}
    print("TEST 1 PASSED: All keys valid")
    
    # Test 2: Invalid key
    try:
        validate_dict_keys({"name": "test", "invalid_key": "value"}, ["name", "value"])
        print("TEST 2 FAILED: Should have raised exception")
    except AnsibleCMValidationException as e:
        print(f"TEST 2 PASSED: Invalid key - {e}")
        
except Exception as e:
    print(f"ERROR in validate_dict_keys tests: {e}")

print("\n=== All tests completed ===")
