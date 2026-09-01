#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/modules/group_save.py

These exercise the real ``idempotent_create`` / ``idempotent_patch`` helpers
against a faked CipherTrustClient, so they assert what the module actually
does rather than what a mocked helper was told to return.
"""

import importlib

import pytest
from unittest.mock import MagicMock, patch

from test_helpers import MockExitJsonException, MockFailJsonException, TEST_NODE

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.modules.group_save"

# Import via the dotted collection path so this module object is the same one
# ``mock.patch`` resolves.  Importing the attribute off the aliased ``plugins``
# package yields a *different* module object under the conftest namespace
# mapper, and patches would silently apply to the wrong copy.
group_save = importlib.import_module(MODULE_PATH)


def _params(**overrides):
    params = {
        "localNode": TEST_NODE.copy(),
        "op_type": "create",
        "name": "Test1",
        "old_name": None,
        "app_metadata": None,
        "client_metadata": None,
        "user_metadata": None,
    }
    params.update(overrides)
    return params


def _run(mock_module, params, client_behaviour):
    """Run group_save.main() with a faked client, returning the exit kwargs."""
    mock_module.params = params
    client = MagicMock()
    client_behaviour(client)

    with patch(f"{MODULE_PATH}.ThalesCipherTrustModule", return_value=mock_module), \
            patch(f"{MODULE_PATH}.CipherTrustClient", return_value=client), \
            patch(f"{MODULE_PATH}.create") as create_fn, \
            patch(f"{MODULE_PATH}.patch") as patch_fn:
        create_fn.return_value = {"id": "new-id", "name": params["name"]}
        patch_fn.return_value = {"id": "grp-1", "name": params["name"]}
        try:
            group_save.main()
        except MockExitJsonException as exc:
            return exc.kwargs, create_fn, patch_fn
    raise AssertionError("main() did not call exit_json")


class TestGroupSaveCreate:
    def test_create_when_absent_reports_changed(self, mock_module):
        result, create_fn, _unused = _run(
            mock_module,
            _params(op_type="create"),
            lambda c: setattr(c, "get", MagicMock(return_value={"resources": []})),
        )

        assert result["changed"] is True
        create_fn.assert_called_once()

    def test_create_when_present_is_idempotent(self, mock_module):
        existing = {"id": "grp-1", "name": "Test1"}
        result, create_fn, _unused = _run(
            mock_module,
            _params(op_type="create"),
            lambda c: setattr(
                c, "get", MagicMock(return_value={"resources": [existing]})
            ),
        )

        assert result["changed"] is False
        assert result["response"] == existing
        create_fn.assert_not_called()


class TestGroupSavePatch:
    def test_patch_is_idempotent_when_state_already_matches(self, mock_module):
        """Second run against unchanged CM state must report changed=False."""
        result, _unused, patch_fn = _run(
            mock_module,
            _params(op_type="patch", old_name="Test1", name="Test1"),
            lambda c: setattr(
                c, "get", MagicMock(return_value={"id": "grp-1", "name": "Test1"})
            ),
        )

        assert result["changed"] is False
        patch_fn.assert_not_called()

    def test_patch_applies_a_real_rename(self, mock_module):
        result, _unused, patch_fn = _run(
            mock_module,
            _params(op_type="patch", old_name="Test1", name="Renamed"),
            lambda c: setattr(
                c, "get", MagicMock(return_value={"id": "grp-1", "name": "Test1"})
            ),
        )

        assert result["changed"] is True
        patch_fn.assert_called_once()

    def test_patch_detects_metadata_change(self, mock_module):
        result, _unused, patch_fn = _run(
            mock_module,
            _params(
                op_type="patch",
                old_name="Test1",
                name="Test1",
                app_metadata={"team": "platform"},
            ),
            lambda c: setattr(
                c,
                "get",
                MagicMock(return_value={"id": "grp-1", "name": "Test1"}),
            ),
        )

        assert result["changed"] is True
        patch_fn.assert_called_once()

    def test_patch_check_mode_does_not_write(self, mock_module):
        mock_module.check_mode = True
        try:
            result, _unused, patch_fn = _run(
                mock_module,
                _params(op_type="patch", old_name="Test1", name="Renamed"),
                lambda c: setattr(
                    c, "get", MagicMock(return_value={"id": "grp-1", "name": "Test1"})
                ),
            )
        finally:
            mock_module.check_mode = False

        assert result["changed"] is True
        patch_fn.assert_not_called()


class TestGroupSaveErrorHandling:
    def test_api_error_becomes_fail_json(self, mock_module):
        """A CM error during the operation must fail cleanly, not traceback."""
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
            CMApiException,
        )

        mock_module.params = _params(op_type="create")
        client = MagicMock()
        client.get.side_effect = CMApiException(
            message="API error: Forbidden", api_error_code=403
        )

        with patch(f"{MODULE_PATH}.ThalesCipherTrustModule", return_value=mock_module), \
                patch(f"{MODULE_PATH}.CipherTrustClient", return_value=client):
            with pytest.raises(MockFailJsonException) as exc_info:
                group_save.main()

        assert "403" in exc_info.value.kwargs["msg"]
