# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""This module adds custom exceptions for Thales CipherTrust modules.

In order to use this module, include it as part of a custom
module as shown below.
  from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
      CMApiException,
      AnsibleCMValidationException,
      AnsibleCMParameterException,
      AnsibleCMFormatException,
      AnsibleCMResponseException,
  )
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class AnsibleCMException(Exception):
    """General-purpose exception for CipherTrust Ansible modules."""

    def __str__(self):
        return self.message if self.message else super().__str__()

    def __init__(self, message=""):
        super().__init__(message)
        self.message = message


class CMApiException(Exception):
    """Exception for CM API errors"""

    def __str__(self):
        if self.api_error_code and self.message:
            return "{0}: {1}".format(self.api_error_code, self.message)

        return super().__str__()

    def __init__(self, message, api_error_code):
        if not message and not api_error_code:
            super().__init__()
        elif not message:
            super().__init__(api_error_code)
        else:
            super().__init__(message)

        self.message = message
        self.api_error_code = api_error_code
        # super().__init__(self.api_error_code + ": " + self.message)


class AnsibleCMValidationException(Exception):
    """Exception for validation errors - parameter validation issues"""

    def __str__(self):
        return self.message

    def __init__(self, message, parameter=None, expected_format=None, example=None):
        self.message = message
        self.parameter = parameter
        self.expected_format = expected_format
        self.example = example

        # Build enhanced error message
        error_parts = [message]
        if parameter:
            error_parts.append(f"Parameter: '{parameter}'")
        if expected_format:
            error_parts.append(f"Expected: {expected_format}")
        if example:
            error_parts.append(f"Example: {example}")

        error_parts.append("Documentation: https://docs.ansible.com/ansible/latest/collections/thalesgroup/ciphertrust/")

        self.message = " | ".join(error_parts)

        # Store individual components for programmatic access
        self.parameter = parameter
        self.expected_format = expected_format
        self.example = example


class AnsibleCMParameterException(Exception):
    """Exception for parameter-related errors - missing required params, invalid values"""

    def __str__(self):
        return self.message

    def __init__(self, message, parameter=None, valid_values=None, example=None):
        self.message = message
        self.parameter = parameter
        self.valid_values = valid_values
        self.example = example

        # Build enhanced error message
        error_parts = [message]
        if parameter:
            error_parts.append(f"Parameter: '{parameter}'")
        if valid_values:
            error_parts.append(f"Valid values: {valid_values}")
        if example:
            error_parts.append(f"Example: {example}")

        error_parts.append("Documentation: https://docs.ansible.com/ansible/latest/collections/thalesgroup/ciphertrust/")

        self.message = " | ".join(error_parts)

        # Store individual components for programmatic access
        self.parameter = parameter
        self.valid_values = valid_values
        self.example = example


class AnsibleCMFormatException(Exception):
    """Exception for format validation errors - regex pattern mismatches, invalid formats"""

    def __str__(self):
        return self.message

    def __init__(self, message, parameter=None, expected_format=None, example=None, regex_pattern=None):
        self.message = message
        self.parameter = parameter
        self.expected_format = expected_format
        self.example = example
        self.regex_pattern = regex_pattern

        # Build enhanced error message
        error_parts = [message]
        if parameter:
            error_parts.append(f"Parameter: '{parameter}'")
        if expected_format:
            error_parts.append(f"Expected format: {expected_format}")
        if regex_pattern:
            error_parts.append(f"Pattern: {regex_pattern}")
        if example:
            error_parts.append(f"Example: {example}")

        error_parts.append("Documentation: https://docs.ansible.com/ansible/latest/collections/thalesgroup/ciphertrust/")

        self.message = " | ".join(error_parts)

        # Store individual components for programmatic access
        self.parameter = parameter
        self.expected_format = expected_format
        self.example = example
        self.regex_pattern = regex_pattern


class AnsibleCMResponseException(Exception):
    """Exception for API response validation errors"""

    def __str__(self):
        return self.message

    def __init__(self, message, response=None, expected_fields=None, actual_fields=None):
        self.message = message
        self.response = response
        self.expected_fields = expected_fields
        self.actual_fields = actual_fields

        # Build enhanced error message
        error_parts = [message]
        if expected_fields:
            error_parts.append(f"Expected fields: {expected_fields}")
        if actual_fields:
            error_parts.append(f"Actual fields: {actual_fields}")
        if response:
            error_parts.append(f"Response: {response}")

        error_parts.append("Documentation: https://docs.ansible.com/ansible/latest/collections/thalesgroup/ciphertrust/")

        self.message = " | ".join(error_parts)

        # Store individual components for programmatic access
        self.response = response
        self.expected_fields = expected_fields
        self.actual_fields = actual_fields
