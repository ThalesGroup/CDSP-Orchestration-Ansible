# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""Custom exception hierarchy for Thales CipherTrust Ansible modules.

All exceptions inherit from :class:`CipherTrustError` so modules can catch
them uniformly with a single ``except CipherTrustError:``.  The
module-level context manager ``ciphertrust_operation`` in
``modules.py`` uses this to convert any collection-specific error into a
clean ``module.fail_json`` call.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


_DOCS_LINK = (
    "https://docs.ansible.com/ansible/latest/collections/thalesgroup/ciphertrust/"
)


class CipherTrustError(Exception):
    """Common base class for every exception raised by this collection.

    Carries a ``message`` attribute plus any number of structured
    keyword attributes (e.g. ``parameter``, ``api_error_code``) that
    subclasses set for richer error reporting.
    """

    def __init__(self, message="", **kwargs):
        self.message = message or ""
        for k, v in kwargs.items():
            setattr(self, k, v)
        super().__init__(self.message)

    def __str__(self):
        return self.message if self.message else super().__str__()


class AnsibleCMException(CipherTrustError):
    """General-purpose CipherTrust Ansible error.

    Used when a module_util needs to signal a module failure that isn't
    an API error and isn't a parameter-validation error.
    """

    def __init__(self, message=""):
        super().__init__(message=message)


class CMApiException(CipherTrustError):
    """Raised when the CipherTrust Manager REST API returns an error.

    ``api_error_code`` is the HTTP status code (or application-level
    code from ``codeDesc``) reported by CM.
    """

    def __init__(self, message="", api_error_code=None):
        super().__init__(message=message, api_error_code=api_error_code)

    def __str__(self):
        if self.api_error_code and self.message:
            return "{0}: {1}".format(self.api_error_code, self.message)
        return super().__str__()


def _compose(message, **fields):
    """Internal helper: build ``message | Key: val | ... | Documentation: …``."""
    parts = [message]
    for key, val in fields.items():
        if val:
            parts.append("{0}: {1}".format(key, val))
    parts.append("Documentation: " + _DOCS_LINK)
    return " | ".join(parts)


class AnsibleCMValidationException(CipherTrustError):
    """Parameter validation failure (required/missing/invalid combination)."""

    def __init__(self, message="", parameter=None, expected_format=None, example=None,
                 documentation_link=None):
        composed = _compose(
            message, Parameter=parameter, Expected=expected_format, Example=example,
        )
        super().__init__(
            message=composed,
            parameter=parameter,
            expected_format=expected_format,
            example=example,
            documentation_link=documentation_link or _DOCS_LINK,
        )


class AnsibleCMParameterException(CipherTrustError):
    """Parameter usage error (wrong value, not allowed for op_type, etc.)."""

    def __init__(self, message="", parameter=None, valid_values=None, example=None,
                 expected_format=None, documentation_link=None):
        composed = _compose(
            message, Parameter=parameter,
            **{"Valid values": valid_values, "Expected": expected_format,
               "Example": example},
        )
        super().__init__(
            message=composed,
            parameter=parameter,
            valid_values=valid_values,
            expected_format=expected_format,
            example=example,
            documentation_link=documentation_link or _DOCS_LINK,
        )


class AnsibleCMFormatException(CipherTrustError):
    """Format/regex mismatch in a parameter value."""

    def __init__(self, message="", parameter=None, expected_format=None, example=None,
                 regex_pattern=None, documentation_link=None):
        composed = _compose(
            message, Parameter=parameter,
            **{"Expected format": expected_format, "Pattern": regex_pattern,
               "Example": example},
        )
        super().__init__(
            message=composed,
            parameter=parameter,
            expected_format=expected_format,
            example=example,
            regex_pattern=regex_pattern,
            documentation_link=documentation_link or _DOCS_LINK,
        )


class AnsibleCMResponseException(CipherTrustError):
    """Unexpected or malformed API response body."""

    def __init__(self, message, response=None, expected_fields=None,
                 actual_fields=None, parameter=None, expected_format=None,
                 example=None, documentation_link=None):
        composed = _compose(
            message,
            **{"Expected fields": expected_fields, "Actual fields": actual_fields,
               "Response": response},
        )
        super().__init__(
            message=composed,
            response=response,
            expected_fields=expected_fields,
            actual_fields=actual_fields,
            parameter=parameter,
            expected_format=expected_format,
            example=example,
            documentation_link=documentation_link or _DOCS_LINK,
        )
