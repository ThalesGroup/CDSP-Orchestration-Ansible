#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/exceptions.py"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CipherTrustError,
    AnsibleCMException,
    CMApiException,
    AnsibleCMValidationException,
    AnsibleCMParameterException,
    AnsibleCMFormatException,
    AnsibleCMResponseException,
    _compose,
    _DOCS_LINK,
)


# ---------------------------------------------------------------------------
# CipherTrustError (base class)
# ---------------------------------------------------------------------------

class TestCipherTrustError:
    def test_basic_message(self):
        err = CipherTrustError(message="something broke")
        assert str(err) == "something broke"
        assert err.message == "something broke"

    def test_empty_message(self):
        err = CipherTrustError()
        assert err.message == ""

    def test_extra_kwargs_stored_as_attributes(self):
        err = CipherTrustError(message="oops", foo="bar", count=42)
        assert err.foo == "bar"
        assert err.count == 42

    def test_inheritance(self):
        err = CipherTrustError(message="x")
        assert isinstance(err, Exception)

    def test_str_falls_back_to_super(self):
        err = CipherTrustError(message="")
        # Empty message → falls through to super().__str__()
        result = str(err)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# AnsibleCMException
# ---------------------------------------------------------------------------

class TestAnsibleCMException:
    def test_message(self):
        err = AnsibleCMException(message="general failure")
        assert str(err) == "general failure"
        assert err.message == "general failure"

    def test_inherits_ciphertrust_error(self):
        err = AnsibleCMException(message="x")
        assert isinstance(err, CipherTrustError)


# ---------------------------------------------------------------------------
# CMApiException
# ---------------------------------------------------------------------------

class TestCMApiException:
    def test_message_with_code(self):
        err = CMApiException(message="Not Found", api_error_code=404)
        assert "404" in str(err)
        assert "Not Found" in str(err)
        assert err.api_error_code == 404

    def test_message_without_code(self):
        err = CMApiException(message="Something")
        assert str(err) == "Something"

    def test_empty(self):
        err = CMApiException()
        assert err.message == ""
        assert err.api_error_code is None

    def test_inherits_ciphertrust_error(self):
        err = CMApiException(message="x", api_error_code=500)
        assert isinstance(err, CipherTrustError)

    def test_str_format_code_message(self):
        err = CMApiException(message="Forbidden", api_error_code=403)
        assert str(err) == "403: Forbidden"


# ---------------------------------------------------------------------------
# _compose helper
# ---------------------------------------------------------------------------

class TestCompose:
    def test_basic(self):
        result = _compose("Error occurred")
        assert "Error occurred" in result
        assert "Documentation:" in result
        assert _DOCS_LINK in result

    def test_with_fields(self):
        result = _compose("Bad param", Parameter="name", Expected="string")
        assert "Parameter: name" in result
        assert "Expected: string" in result

    def test_none_fields_omitted(self):
        result = _compose("msg", Parameter="x", Expected=None)
        assert "Parameter: x" in result
        assert "Expected" not in result

    def test_empty_fields_omitted(self):
        result = _compose("msg", Parameter="x", Expected="")
        assert "Expected" not in result


# ---------------------------------------------------------------------------
# AnsibleCMValidationException
# ---------------------------------------------------------------------------

class TestAnsibleCMValidationException:
    def test_composed_message(self):
        err = AnsibleCMValidationException(
            message="Missing required field",
            parameter="name",
            expected_format="string",
            example="my_key",
        )
        assert "Missing required field" in str(err)
        assert "Parameter: name" in str(err)
        assert "Expected: string" in str(err)
        assert _DOCS_LINK in str(err)
        assert err.parameter == "name"
        assert err.expected_format == "string"
        assert err.example == "my_key"

    def test_inherits_ciphertrust_error(self):
        err = AnsibleCMValidationException(message="x")
        assert isinstance(err, CipherTrustError)

    def test_default_documentation_link(self):
        err = AnsibleCMValidationException(message="x")
        assert err.documentation_link == _DOCS_LINK

    def test_custom_documentation_link(self):
        err = AnsibleCMValidationException(
            message="x", documentation_link="https://custom.docs"
        )
        assert err.documentation_link == "https://custom.docs"


# ---------------------------------------------------------------------------
# AnsibleCMParameterException
# ---------------------------------------------------------------------------

class TestAnsibleCMParameterException:
    def test_composed_message(self):
        err = AnsibleCMParameterException(
            message="Invalid value",
            parameter="op_type",
            valid_values="create, patch",
        )
        assert "Invalid value" in str(err)
        assert "Parameter: op_type" in str(err)
        assert "Valid values: create, patch" in str(err)
        assert err.parameter == "op_type"
        assert err.valid_values == "create, patch"

    def test_inherits_ciphertrust_error(self):
        err = AnsibleCMParameterException(message="x")
        assert isinstance(err, CipherTrustError)


# ---------------------------------------------------------------------------
# AnsibleCMFormatException
# ---------------------------------------------------------------------------

class TestAnsibleCMFormatException:
    def test_composed_message(self):
        err = AnsibleCMFormatException(
            message="Bad format",
            parameter="email",
            expected_format="email",
            regex_pattern=r"^.+@.+$",
        )
        assert "Bad format" in str(err)
        assert "Parameter: email" in str(err)
        assert "Expected format: email" in str(err)
        assert err.regex_pattern == r"^.+@.+$"

    def test_inherits_ciphertrust_error(self):
        err = AnsibleCMFormatException(message="x")
        assert isinstance(err, CipherTrustError)


# ---------------------------------------------------------------------------
# AnsibleCMResponseException
# ---------------------------------------------------------------------------

class TestAnsibleCMResponseException:
    def test_composed_message(self):
        err = AnsibleCMResponseException(
            message="Unexpected response",
            expected_fields="id, name",
            actual_fields="id",
            response='{"id": "x"}',
        )
        assert "Unexpected response" in str(err)
        assert "Expected fields: id, name" in str(err)
        assert err.expected_fields == "id, name"
        assert err.actual_fields == "id"

    def test_inherits_ciphertrust_error(self):
        err = AnsibleCMResponseException(message="x")
        assert isinstance(err, CipherTrustError)


# ---------------------------------------------------------------------------
# Cross-cutting: all exception types can be caught by CipherTrustError
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    @pytest.mark.parametrize(
        "exc_cls,kwargs",
        [
            (AnsibleCMException, {"message": "a"}),
            (CMApiException, {"message": "b", "api_error_code": 400}),
            (AnsibleCMValidationException, {"message": "c"}),
            (AnsibleCMParameterException, {"message": "d"}),
            (AnsibleCMFormatException, {"message": "e"}),
            (AnsibleCMResponseException, {"message": "f"}),
        ],
    )
    def test_all_subtypes_caught_by_base(self, exc_cls, kwargs):
        with pytest.raises(CipherTrustError):
            raise exc_cls(**kwargs)
