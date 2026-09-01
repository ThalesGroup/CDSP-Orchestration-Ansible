#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/modules/vault_keys2_op.py

Every op_type is driven through the *real* ``keys2`` helpers with only the
HTTP client faked, so these assert the URL and payload the collection would
actually put on the wire -- including the query-string builder and the
``messageStr``/``keyFormat`` field remaps.
"""

import importlib
import json

import pytest
from unittest.mock import MagicMock, patch

from test_helpers import MockExitJsonException, MockFailJsonException, TEST_NODE

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.modules.vault_keys2_op"
KEYS2_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.keys2"

vault_keys2_op = importlib.import_module(MODULE_PATH)


def _params(op_type, **overrides):
    params = {
        "localNode": TEST_NODE.copy(),
        "op_type": op_type,
        "cm_key_id": "key-123",
        "key_version": None,
        "id_type": None,
        "includeMaterial": None,
        "reason": None,
        "compromiseOccurrenceDate": None,
        "messageStr": None,
        "keyFormat": None,
        "newKeyName": None,
        "meta": None,
    }
    params.update(overrides)
    return params


def _run(mock_module, params, response=None):
    """Run main() with a faked HTTP client; return (exit kwargs, client mock)."""
    mock_module.params = params
    client = MagicMock()
    client.post.return_value = response if response is not None else {"status": "ok"}

    with patch(f"{MODULE_PATH}.ThalesCipherTrustModule", return_value=mock_module), \
            patch(f"{KEYS2_PATH}.CipherTrustClient", return_value=client):
        try:
            vault_keys2_op.main()
        except MockExitJsonException as exc:
            return exc.kwargs, client
    raise AssertionError("main() did not call exit_json")


def _posted_url(client):
    return client.post.call_args[0][0]


def _posted_body(client):
    kwargs = client.post.call_args[1]
    return json.loads(kwargs["data"]) if kwargs.get("data") else None


@pytest.mark.parametrize("op_type", ["destroy", "archive", "recover"])
class TestSimpleLifecycleOps:
    def test_posts_to_the_op_endpoint(self, op_type, mock_module):
        result, client = _run(mock_module, _params(op_type))

        assert result["changed"] is True
        assert result["response"] == {"status": "ok"}
        assert _posted_url(client) == f"vault/keys2/key-123/{op_type}"

    def test_check_mode_makes_no_call(self, op_type, mock_module):
        mock_module.check_mode = True
        try:
            result, client = _run(mock_module, _params(op_type))
        finally:
            mock_module.check_mode = False

        assert result["changed"] is True
        client.post.assert_not_called()


class TestQueryStringHandling:
    def test_key_version_and_id_type_become_query_params(self, mock_module):
        _unused, client = _run(
            mock_module, _params("archive", key_version=2, id_type="name")
        )

        url = _posted_url(client)
        assert url.startswith("vault/keys2/key-123/archive?")
        assert "version=2" in url
        assert "type=name" in url

    def test_omitted_query_params_are_not_sent(self, mock_module):
        _unused, client = _run(mock_module, _params("archive"))

        assert "?" not in _posted_url(client)

    def test_clone_passes_include_material(self, mock_module):
        _unused, client = _run(
            mock_module, _params("clone", includeMaterial=True, newKeyName="copy-1")
        )

        url = _posted_url(client)
        assert url.startswith("vault/keys2/key-123/clone?")
        assert "includeMaterial=True" in url
        # includeMaterial routes the URL and must not be duplicated in the body
        assert "includeMaterial" not in (_posted_body(client) or {})
        assert _posted_body(client)["newKeyName"] == "copy-1"


class TestFieldRemapping:
    def test_revoke_remaps_message_str_to_message(self, mock_module):
        _unused, client = _run(
            mock_module,
            _params("revoke", reason="KeyCompromise", messageStr="rotated out"),
        )

        body = _posted_body(client)
        assert body["message"] == "rotated out"
        assert "messageStr" not in body
        assert body["reason"] == "KeyCompromise"

    def test_reactivate_remaps_message_str_to_message(self, mock_module):
        _unused, client = _run(
            mock_module,
            _params("reactivate", reason="DeactivatedToActive", messageStr="back"),
        )

        body = _posted_body(client)
        assert body["message"] == "back"
        assert "messageStr" not in body

    def test_export_remaps_key_format_to_format(self, mock_module):
        _unused, client = _run(mock_module, _params("export", keyFormat="pkcs8"))

        body = _posted_body(client)
        assert body["format"] == "pkcs8"
        assert "keyFormat" not in body

    def test_routing_kwargs_never_reach_the_body(self, mock_module):
        """node/cm_key_id/key_version/id_type build the request, not the payload."""
        _unused, client = _run(
            mock_module,
            _params("revoke", key_version=3, id_type="id", reason="Superseded"),
        )

        body = _posted_body(client)
        for routing_key in ("node", "cm_key_id", "key_version", "id_type"):
            assert routing_key not in body


class TestErrorHandling:
    def test_api_error_becomes_fail_json(self, mock_module):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
            CMApiException,
        )

        mock_module.params = _params("archive")
        client = MagicMock()
        client.post.side_effect = CMApiException(
            message="key is destroyed", api_error_code=409
        )

        with patch(f"{MODULE_PATH}.ThalesCipherTrustModule", return_value=mock_module), \
                patch(f"{KEYS2_PATH}.CipherTrustClient", return_value=client):
            with pytest.raises(MockFailJsonException) as exc_info:
                vault_keys2_op.main()

        assert "409" in exc_info.value.kwargs["msg"]
