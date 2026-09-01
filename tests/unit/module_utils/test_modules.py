#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/modules.py"""

import pytest
from unittest.mock import MagicMock, patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    _ciphertrust_common_argument_spec,
    ciphertrust_argument_spec,
    handle_module_error,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from test_helpers import MockFailJsonException

DEFAULT_SETTINGS_PATH = (
    "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils"
    ".modules.ThalesCipherTrustModule.default_settings"
)


# ---------------------------------------------------------------------------
# ciphertrust_argument_spec
# ---------------------------------------------------------------------------

class TestArgumentSpec:
    def test_common_spec_has_local_node(self):
        spec = _ciphertrust_common_argument_spec()
        assert "localNode" in spec
        assert spec["localNode"]["type"] == "dict"
        assert spec["localNode"]["required"] is True

    def test_local_node_has_required_fields(self):
        spec = _ciphertrust_common_argument_spec()
        options = spec["localNode"]["options"]
        assert options["server_ip"]["required"] is True
        assert options["user"]["required"] is True
        assert options["password"]["required"] is True
        assert options["password"]["no_log"] is True

    def test_local_node_defaults(self):
        spec = _ciphertrust_common_argument_spec()
        options = spec["localNode"]["options"]
        assert options["verify"]["default"] is False
        assert options["server_port"]["default"] == 5432
        assert options["auth_domain_path"]["default"] == ""

    def test_ciphertrust_argument_spec_returns_common(self):
        spec = ciphertrust_argument_spec()
        assert "localNode" in spec


# ---------------------------------------------------------------------------
# ThalesCipherTrustModule
# ---------------------------------------------------------------------------

class TestThalesCipherTrustModule:
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules.AnsibleModule")
    def test_init_merges_argument_spec(self, MockAnsibleModule):
        mock_instance = MockAnsibleModule.return_value
        mock_instance.check_mode = False
        mock_instance._diff = False
        mock_instance._name = "test"
        mock_instance.params = {}

        with patch.dict(DEFAULT_SETTINGS_PATH, {"module_class": MockAnsibleModule}):
            module = ThalesCipherTrustModule(
                argument_spec={"op_type": {"type": "str", "required": True}},
                supports_check_mode=True,
            )

        call_kwargs = MockAnsibleModule.call_args[1]
        assert "local_node" in call_kwargs["argument_spec"]
        assert "localNode" in call_kwargs["argument_spec"]["local_node"]["aliases"]
        assert "op_type" in call_kwargs["argument_spec"]

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules.AnsibleModule")
    def test_camelcase_param_gets_snake_case_alias_and_deprecation(self, MockAnsibleModule):
        mock_instance = MockAnsibleModule.return_value
        mock_instance.check_mode = False
        mock_instance._diff = False
        mock_instance._name = "test"
        mock_instance.params = {}

        with patch.dict(DEFAULT_SETTINGS_PATH, {"module_class": MockAnsibleModule}):
            ThalesCipherTrustModule(
                argument_spec={"wrapKeyName": {"type": "str"}},
                supports_check_mode=True,
            )

        call_kwargs = MockAnsibleModule.call_args[1]
        entry = call_kwargs["argument_spec"]["wrap_key_name"]
        assert "wrapKeyName" in entry["aliases"]
        assert any(alias["name"] == "wrapKeyName" for alias in entry["deprecated_aliases"])

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules.AnsibleModule")
    def test_rewrites_required_if_to_snake_case(self, MockAnsibleModule):
        mock_instance = MockAnsibleModule.return_value
        mock_instance.check_mode = False
        mock_instance._diff = False
        mock_instance._name = "test"
        mock_instance.params = {}

        with patch.dict(DEFAULT_SETTINGS_PATH, {"module_class": MockAnsibleModule}):
            ThalesCipherTrustModule(
                argument_spec={
                    "opType": {"type": "str"},
                    "wrapKeyName": {"type": "str"},
                },
                required_if=[["opType", "create", ["wrapKeyName"]]],
            )

        call_kwargs = MockAnsibleModule.call_args[1]
        assert call_kwargs["required_if"] == [["op_type", "create", ["wrap_key_name"]]]

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules.AnsibleModule")
    def test_delegates_to_ansible_module(self, MockAnsibleModule):
        mock_instance = MockAnsibleModule.return_value
        mock_instance.check_mode = True
        mock_instance._diff = True
        mock_instance._name = "my_module"
        mock_instance.params = {"foo": "bar"}

        with patch.dict(DEFAULT_SETTINGS_PATH, {"module_class": MockAnsibleModule}):
            module = ThalesCipherTrustModule(
                argument_spec={},
                supports_check_mode=True,
            )

        assert module.check_mode is True
        assert module._diff is True
        assert module._name == "my_module"
        assert module.params == {"foo": "bar"}

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules.AnsibleModule")
    def test_injects_legacy_camelcase_params(self, MockAnsibleModule):
        mock_instance = MockAnsibleModule.return_value
        mock_instance.check_mode = False
        mock_instance._diff = False
        mock_instance._name = "test"
        mock_instance.params = {
            "local_node": {"server_ip": "127.0.0.1"},
            "wrap_key_name": "key-a",
        }

        with patch.dict(DEFAULT_SETTINGS_PATH, {"module_class": MockAnsibleModule}):
            module = ThalesCipherTrustModule(
                argument_spec={"wrapKeyName": {"type": "str"}},
                supports_check_mode=True,
            )

        assert module.params["localNode"]["server_ip"] == "127.0.0.1"
        assert module.params["wrapKeyName"] == "key-a"

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules.AnsibleModule")
    def test_exit_json_delegates(self, MockAnsibleModule):
        mock_instance = MockAnsibleModule.return_value
        mock_instance.check_mode = False
        mock_instance._diff = False
        mock_instance._name = "test"

        with patch.dict(DEFAULT_SETTINGS_PATH, {"module_class": MockAnsibleModule}):
            module = ThalesCipherTrustModule(argument_spec={})

        module.exit_json(changed=True, response={"id": "123"})
        mock_instance.exit_json.assert_called_once_with(changed=True, response={"id": "123"})

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules.AnsibleModule")
    def test_fail_json_delegates(self, MockAnsibleModule):
        mock_instance = MockAnsibleModule.return_value
        mock_instance.check_mode = False
        mock_instance._diff = False
        mock_instance._name = "test"

        with patch.dict(DEFAULT_SETTINGS_PATH, {"module_class": MockAnsibleModule}):
            module = ThalesCipherTrustModule(argument_spec={})

        module.fail_json(msg="something broke")
        mock_instance.fail_json.assert_called_once_with(msg="something broke")

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules.AnsibleModule")
    def test_default_args_false_skips_merge(self, MockAnsibleModule):
        mock_instance = MockAnsibleModule.return_value
        mock_instance.check_mode = False
        mock_instance._diff = False
        mock_instance._name = "test"

        with patch.dict(DEFAULT_SETTINGS_PATH, {"module_class": MockAnsibleModule}):
            module = ThalesCipherTrustModule(
                argument_spec={"op_type": {"type": "str"}},
                default_args=False,
            )

        call_kwargs = MockAnsibleModule.call_args[1]
        assert "localNode" not in call_kwargs["argument_spec"]


# ---------------------------------------------------------------------------
# handle_module_error
# ---------------------------------------------------------------------------

class TestHandleModuleError:
    def test_cm_api_exception_with_code(self):
        module = MagicMock()
        exc = CMApiException(message="Not Found", api_error_code=404)

        handle_module_error(module, exc)

        module.fail_json.assert_called_once()
        msg = module.fail_json.call_args[1]["msg"]
        assert "API Error" in msg
        assert "404" in msg
        assert "Not Found" in msg

    def test_cm_api_exception_without_code(self):
        module = MagicMock()
        exc = CMApiException(message="Generic error")

        handle_module_error(module, exc)

        msg = module.fail_json.call_args[1]["msg"]
        assert "API Error" in msg
        assert "Generic error" in msg

    def test_ciphertrust_error(self):
        module = MagicMock()
        exc = AnsibleCMException(message="Something bad")

        handle_module_error(module, exc)

        msg = module.fail_json.call_args[1]["msg"]
        assert "Something bad" in msg

    def test_unexpected_error(self):
        module = MagicMock()
        exc = ValueError("unexpected")

        handle_module_error(module, exc)

        msg = module.fail_json.call_args[1]["msg"]
        assert "Unexpected error" in msg
        assert "unexpected" in msg


# ---------------------------------------------------------------------------
# ciphertrust_operation context manager
# ---------------------------------------------------------------------------

class TestCiphertrustOperation:
    def test_no_exception_passes_through(self):
        module = MagicMock()

        with ciphertrust_operation(module):
            result = 42

        module.fail_json.assert_not_called()

    def test_catches_ciphertrust_error(self):
        module = MagicMock()

        with ciphertrust_operation(module):
            raise AnsibleCMException(message="Oops")

        module.fail_json.assert_called_once()
        msg = module.fail_json.call_args[1]["msg"]
        assert "Oops" in msg

    def test_catches_cm_api_exception(self):
        module = MagicMock()

        with ciphertrust_operation(module):
            raise CMApiException(message="Forbidden", api_error_code=403)

        msg = module.fail_json.call_args[1]["msg"]
        assert "403" in msg

    def test_does_not_catch_non_ciphertrust_exceptions(self):
        module = MagicMock()

        with pytest.raises(ValueError):
            with ciphertrust_operation(module):
                raise ValueError("not a CT error")

        module.fail_json.assert_not_called()


# ---------------------------------------------------------------------------
# Raw urllib errors must not escape ciphertrust_operation
# ---------------------------------------------------------------------------

class TestRawUrllibErrorHandling:
    """Defence in depth: CipherTrustClient translates transport errors, but any
    code path that bypasses it must still fail cleanly rather than traceback."""

    @staticmethod
    def _module():
        module = MagicMock()

        def fail_json(**kwargs):
            raise MockFailJsonException(**kwargs)

        module.fail_json = fail_json
        return module

    def test_http_error_becomes_fail_json(self):
        module = self._module()

        with pytest.raises(MockFailJsonException) as exc_info:
            with ciphertrust_operation(module):
                raise HTTPError(
                    "https://cm.example.com/api/v1/vault/keys2",
                    400, "Bad Request", {}, None,
                )

        assert "400" in exc_info.value.kwargs["msg"]

    def test_url_error_becomes_fail_json(self):
        module = self._module()

        with pytest.raises(MockFailJsonException) as exc_info:
            with ciphertrust_operation(module):
                raise URLError("connection refused")

        assert "connection refused" in exc_info.value.kwargs["msg"]
