#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/cm_api.py

Covers: is_json, build_request_payload, _build_query_string,
CipherTrustClient (auth, HTTP verbs, JWT caching, error handling),
and backward-compatible wrapper functions.
"""

import io
import json
import time
import pytest
from unittest.mock import MagicMock, patch
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError

from test_helpers import MockFailJsonException

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    is_json,
    build_request_payload,
    _build_query_string,
    CipherTrustClient,
    _client_from_node,
    DELETEByNameOrId,
    DeleteWithoutData,
    GETIdByQueryParam,
    _jwt_cache,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ciphertrust_operation,
)

# Reusable test node
TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}


# ---------------------------------------------------------------------------
# is_json
# ---------------------------------------------------------------------------

class TestIsJson:
    def test_valid_json_object(self):
        assert is_json('{"key": "value"}') is True

    def test_valid_json_array(self):
        assert is_json('[1, 2, 3]') is True

    def test_valid_json_string(self):
        assert is_json('"hello"') is True

    def test_valid_json_number(self):
        assert is_json('42') is True

    def test_invalid_json(self):
        assert is_json('not json') is False

    def test_empty_string(self):
        assert is_json('') is False

    def test_none_returns_false(self):
        assert is_json(None) is False


# ---------------------------------------------------------------------------
# build_request_payload
# ---------------------------------------------------------------------------

class TestBuildRequestPayload:
    def test_basic(self):
        result = json.loads(build_request_payload({"name": "foo", "age": 30}))
        assert result == {"name": "foo", "age": 30}

    def test_filters_none_values(self):
        result = json.loads(
            build_request_payload({"name": "foo", "desc": None, "age": 25})
        )
        assert result == {"name": "foo", "age": 25}
        assert "desc" not in result

    def test_all_none_returns_empty(self):
        result = json.loads(build_request_payload({"a": None, "b": None}))
        assert result == {}

    def test_empty_dict(self):
        result = json.loads(build_request_payload({}))
        assert result == {}

    def test_with_remap(self):
        result = json.loads(
            build_request_payload(
                {"messageStr": "hello", "other": "val"},
                remap={"messageStr": "message"},
            )
        )
        assert result == {"message": "hello", "other": "val"}

    def test_remap_only_affects_specified_keys(self):
        result = json.loads(
            build_request_payload(
                {"a": 1, "b": 2},
                remap={"a": "alpha"},
            )
        )
        assert result == {"alpha": 1, "b": 2}


# ---------------------------------------------------------------------------
# _build_query_string
# ---------------------------------------------------------------------------

class TestBuildQueryString:
    def test_basic(self):
        result = _build_query_string({"skip": 0, "limit": 10})
        assert "?" in result
        assert "skip=0" in result
        assert "limit=10" in result

    def test_filters_none(self):
        result = _build_query_string({"skip": 0, "limit": None})
        assert "skip=0" in result
        assert "limit" not in result

    def test_all_none_returns_empty(self):
        result = _build_query_string({"a": None, "b": None})
        assert result == ""

    def test_empty_dict(self):
        result = _build_query_string({})
        assert result == ""


# ---------------------------------------------------------------------------
# CipherTrustClient
# ---------------------------------------------------------------------------

class TestCipherTrustClient:

    def setup_method(self):
        """Clear JWT cache before each test."""
        _jwt_cache.clear()

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_authenticate_stores_jwt(self, MockRequest):
        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"jwt": "tok123"}).encode()
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        client._authenticate()

        assert client._token == "tok123"
        # Verify it was cached
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        assert cache_key in _jwt_cache
        assert _jwt_cache[cache_key][0] == "tok123"

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_authenticate_with_domain_path(self, MockRequest):
        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"jwt": "tok456"}).encode()
        mock_req.open.return_value = mock_response

        node = {**TEST_NODE, "auth_domain_path": "my/domain"}
        client = CipherTrustClient(node)
        client._authenticate()

        # Verify auth_domain_path was sent in payload
        call_args = mock_req.open.call_args
        sent_data = json.loads(call_args[1]["data"])
        assert sent_data["auth_domain_path"] == "my/domain"

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_ensure_authenticated_uses_cache(self, MockRequest):
        # Pre-populate cache
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("cached_token", time.time() + 600)

        client = CipherTrustClient(TEST_NODE)
        client._ensure_authenticated()

        assert client._token == "cached_token"
        # Request should NOT have been called (no auth needed)
        MockRequest.return_value.open.assert_not_called()

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_ensure_authenticated_refreshes_expired_cache(self, MockRequest):
        # Expired cache entry
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("old_token", time.time() - 10)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"jwt": "new_token"}).encode()
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        client._ensure_authenticated()

        assert client._token == "new_token"

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_headers_include_bearer_token(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("my_jwt", time.time() + 600)

        client = CipherTrustClient(TEST_NODE)
        headers = client._headers()

        assert headers["Authorization"] == "Bearer my_jwt"
        assert "application/json" in headers["Content-Type"]

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_request_get(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("jwt", time.time() + 600)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"id": "abc"}).encode()
        mock_response.getcode.return_value = 200
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        result = client.get("vault/keys2")

        assert result == {"id": "abc"}
        call_args = mock_req.open.call_args
        assert call_args[1]["method"] == "GET"
        assert "vault/keys2" in call_args[1]["url"]

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_request_post_with_data(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("jwt", time.time() + 600)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"id": "new_id"}).encode()
        mock_response.getcode.return_value = 201
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        payload = json.dumps({"name": "test_key"})
        result = client.post("vault/keys2", data=payload)

        assert result == {"id": "new_id"}
        call_args = mock_req.open.call_args
        assert call_args[1]["method"] == "POST"
        assert call_args[1]["data"] == payload

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_request_empty_body_returns_empty_dict(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("jwt", time.time() + 600)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = b""
        mock_response.getcode.return_value = 204
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        result = client.request("DELETE", "some/endpoint")

        assert result == {}

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_request_raises_cmapi_on_code_desc(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("jwt", time.time() + 600)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"codeDesc": "ResourceNotFound"}
        ).encode()
        mock_response.getcode.return_value = 404
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        with pytest.raises(CMApiException) as exc_info:
            client.get("vault/keys2/nonexistent")

        assert "ResourceNotFound" in str(exc_info.value)

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_request_non_json_body_returned_raw(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("jwt", time.time() + 600)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = b"plain text response"
        mock_response.getcode.return_value = 200
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        result = client.request("GET", "some/endpoint")

        assert result == b"plain text response"

    def test_base_url_construction(self):
        client = CipherTrustClient(TEST_NODE)
        assert client._base_url == "https://test.example.com/api/v1/"

    def test_verify_default_false(self):
        node = {**TEST_NODE}
        del node["verify"]
        client = CipherTrustClient(node)
        assert client._verify is False

    def test_verify_true(self):
        node = {**TEST_NODE, "verify": True}
        client = CipherTrustClient(node)
        assert client._verify is True

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_put(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("jwt", time.time() + 600)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"ok": True}).encode()
        mock_response.getcode.return_value = 200
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        result = client.put("some/endpoint", data='{"key": "val"}')
        assert result == {"ok": True}

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_patch(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("jwt", time.time() + 600)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"updated": True}).encode()
        mock_response.getcode.return_value = 200
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        result = client.patch("some/endpoint", data='{"x": 1}')
        assert result == {"updated": True}

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_delete(self, MockRequest):
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("jwt", time.time() + 600)

        mock_req = MockRequest.return_value
        mock_response = MagicMock()
        mock_response.read.return_value = b""
        mock_response.getcode.return_value = 204
        mock_req.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        result = client.delete("some/endpoint")
        assert result == {}


# ---------------------------------------------------------------------------
# Backward-compatible wrapper functions
# ---------------------------------------------------------------------------

class TestBackwardCompatWrappers:

    def setup_method(self):
        _jwt_cache.clear()

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.CipherTrustClient"
    )
    def test_client_from_node(self, MockClient):
        client = _client_from_node(TEST_NODE)
        MockClient.assert_called_once_with(TEST_NODE)

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.CipherTrustClient"
    )
    def test_delete_by_name_or_id(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.delete.return_value = {}

        result = DELETEByNameOrId(
            key="my_key", cm_node=TEST_NODE, cm_api_endpoint="vault/keys2"
        )

        mock_instance.delete.assert_called_once_with("vault/keys2/my_key")

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.CipherTrustClient"
    )
    def test_delete_without_data(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.delete.return_value = {}

        result = DeleteWithoutData(cm_node=TEST_NODE, cm_api_endpoint="some/path")
        mock_instance.delete.assert_called_once_with("some/path")

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.CipherTrustClient"
    )
    def test_get_id_by_query_param_with_results(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.get.return_value = {
            "resources": [{"id": "abc123", "name": "my_thing"}]
        }

        result = GETIdByQueryParam(
            param="name",
            value="my_thing",
            cm_node=TEST_NODE,
            cm_api_endpoint="vault/keys2",
            id="id",
        )
        assert result == {"id": "abc123"}

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.CipherTrustClient"
    )
    def test_get_id_by_query_param_no_id_returns_full(self, MockClient):
        mock_instance = MockClient.return_value
        resp = {"resources": [{"id": "abc123", "name": "thing"}]}
        mock_instance.get.return_value = resp

        result = GETIdByQueryParam(
            param="name",
            value="thing",
            cm_node=TEST_NODE,
            cm_api_endpoint="vault/keys2",
        )
        assert result == resp

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.CipherTrustClient"
    )
    def test_get_id_by_query_param_no_results_raises(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.get.return_value = {"resources": []}

        with pytest.raises(CMApiException, match="No matching records"):
            GETIdByQueryParam(
                param="name",
                value="ghost",
                cm_node=TEST_NODE,
                cm_api_endpoint="vault/keys2",
            )

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.CipherTrustClient"
    )
    def test_get_id_by_query_param_bad_response_raises(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.get.return_value = "unexpected string"

        with pytest.raises(CMApiException, match="Error fetching data"):
            GETIdByQueryParam(
                param="name",
                value="x",
                cm_node=TEST_NODE,
                cm_api_endpoint="vault/keys2",
            )

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.CipherTrustClient"
    )
    def test_get_id_by_query_param_none_param(self, MockClient):
        """When param is None, should query the endpoint directly without filters."""
        mock_instance = MockClient.return_value
        mock_instance.get.return_value = {
            "resources": [{"id": "abc"}]
        }

        result = GETIdByQueryParam(
            param=None,
            value=None,
            cm_node=TEST_NODE,
            cm_api_endpoint="vault/keys2",
            id="id",
        )
        mock_instance.get.assert_called_once_with("vault/keys2")
        assert result == {"id": "abc"}


# ---------------------------------------------------------------------------
# Transport error handling
#
# CM returns 4xx/5xx for bad payloads, expired credentials, duplicate names
# and server faults.  urllib surfaces those as HTTPError, and connection
# failures as URLError.  Neither is part of the CipherTrustError hierarchy,
# so unless the client translates them they escape ``ciphertrust_operation``
# and the module dies with a traceback instead of a clean fail_json.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_backoff():
    """Keep the retry policy's timing out of the test run."""
    with patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils"
        ".cm_api._BACKOFF_SECONDS",
        (0, 0),
    ):
        yield


class TestTransportErrorHandling:

    def setup_method(self):
        _jwt_cache.clear()

    @staticmethod
    def _authed_client():
        cache_key = (TEST_NODE["server_ip"], TEST_NODE["user"], "")
        _jwt_cache[cache_key] = ("supersecretjwt", time.time() + 600)
        return CipherTrustClient(TEST_NODE)

    @staticmethod
    def _http_error(code=400, body=None, msg="Bad Request"):
        fp = io.BytesIO(body.encode()) if body is not None else None
        return HTTPError(
            "https://test.example.com/api/v1/vault/keys2", code, msg, {}, fp
        )

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_http_error_becomes_cmapi_exception(self, MockRequest):
        MockRequest.return_value.open.side_effect = self._http_error(
            400, json.dumps({"codeDesc": "InvalidPayload"})
        )

        client = self._authed_client()
        with pytest.raises(CMApiException) as exc_info:
            client.post("vault/keys2", data="{}")

        assert exc_info.value.api_error_code == 400

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_http_error_message_includes_cm_detail(self, MockRequest):
        MockRequest.return_value.open.side_effect = self._http_error(
            409, json.dumps({"codeDesc": "AlreadyExists", "message": "name in use"})
        )

        client = self._authed_client()
        with pytest.raises(CMApiException) as exc_info:
            client.post("usermgmt/groups", data="{}")

        rendered = str(exc_info.value)
        assert "AlreadyExists" in rendered or "name in use" in rendered

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_http_error_without_readable_body(self, MockRequest):
        MockRequest.return_value.open.side_effect = self._http_error(500, None, "Boom")

        client = self._authed_client()
        with pytest.raises(CMApiException) as exc_info:
            client.get("vault/keys2")

        assert exc_info.value.api_error_code == 500

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_http_error_with_non_json_body(self, MockRequest):
        MockRequest.return_value.open.side_effect = self._http_error(
            502, "<html>gateway</html>", "Bad Gateway"
        )

        client = self._authed_client()
        with pytest.raises(CMApiException) as exc_info:
            client.get("vault/keys2")

        assert exc_info.value.api_error_code == 502

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_http_error_does_not_leak_credentials(self, MockRequest):
        MockRequest.return_value.open.side_effect = self._http_error(
            401, json.dumps({"codeDesc": "Unauthorized"})
        )

        client = self._authed_client()
        with pytest.raises(CMApiException) as exc_info:
            client.get("vault/keys2")

        rendered = str(exc_info.value)
        assert "supersecretjwt" not in rendered
        assert TEST_NODE["password"] not in rendered

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_url_error_becomes_cmapi_exception(self, MockRequest):
        MockRequest.return_value.open.side_effect = URLError("timed out")

        client = self._authed_client()
        with pytest.raises(CMApiException) as exc_info:
            client.get("vault/keys2")

        assert "timed out" in str(exc_info.value)

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_auth_http_error_becomes_cmapi_exception(self, MockRequest):
        MockRequest.return_value.open.side_effect = self._http_error(
            401, json.dumps({"codeDesc": "InvalidCredentials"}), "Unauthorized"
        )

        client = CipherTrustClient(TEST_NODE)
        with pytest.raises(CMApiException) as exc_info:
            client.get("vault/keys2")

        assert exc_info.value.api_error_code == 401
        assert TEST_NODE["password"] not in str(exc_info.value)

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_auth_url_error_becomes_cmapi_exception(self, MockRequest):
        MockRequest.return_value.open.side_effect = URLError("no route to host")

        client = CipherTrustClient(TEST_NODE)
        with pytest.raises(CMApiException) as exc_info:
            client.get("vault/keys2")

        assert TEST_NODE["password"] not in str(exc_info.value)

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_auth_response_without_jwt_becomes_cmapi_exception(self, MockRequest):
        mock_response = MagicMock()
        mock_response.read.return_value = b"<html>not the login endpoint</html>"
        MockRequest.return_value.open.return_value = mock_response

        client = CipherTrustClient(TEST_NODE)
        with pytest.raises(CMApiException):
            client.get("vault/keys2")

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_api_error_reaches_fail_json_not_traceback(self, MockRequest):
        """End-to-end: a CM 400 must land in fail_json, not escape the module."""
        MockRequest.return_value.open.side_effect = self._http_error(
            400, json.dumps({"codeDesc": "InvalidPayload"})
        )

        module = MagicMock()
        module.fail_json.side_effect = MockFailJsonException

        client = self._authed_client()
        with pytest.raises(MockFailJsonException):
            with ciphertrust_operation(module):
                client.post("vault/keys2", data="{}")

        assert module.fail_json.called


class TestRetryPolicy:
    """Reads are retried through a blip; writes are not replayed.

    Retrying a POST, PATCH or DELETE that may already have been applied risks
    duplicating a write against CipherTrust Manager, so only GET is retried on
    a transient failure. A 401 is different: the request was rejected before
    anything happened, so any method re-authenticates once and retries.
    """

    def setup_method(self):
        _jwt_cache.clear()

    @staticmethod
    def _ok_response(payload=None):
        response = MagicMock()
        response.read.return_value = json.dumps(payload or {"ok": True}).encode()
        response.getcode.return_value = 200
        return response

    @staticmethod
    def _authed():
        _jwt_cache[(TEST_NODE["server_ip"], TEST_NODE["user"], "")] = (
            "jwt", time.time() + 600
        )
        return CipherTrustClient(TEST_NODE)

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_expired_session_is_renewed_and_the_call_retried(self, MockRequest):
        auth = MagicMock()
        auth.read.return_value = json.dumps({"jwt": "fresh"}).encode()
        MockRequest.return_value.open.side_effect = [
            HTTPError("https://cm/api/v1/vault/keys2", 401, "Unauthorized", {}, None),
            auth,                       # re-authentication
            self._ok_response({"id": "k1"}),
        ]

        client = self._authed()
        assert client.get("vault/keys2") == {"id": "k1"}

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_repeated_401_gives_up(self, MockRequest):
        auth = MagicMock()
        auth.read.return_value = json.dumps({"jwt": "fresh"}).encode()
        MockRequest.return_value.open.side_effect = [
            HTTPError("https://cm/api/v1/x", 401, "Unauthorized", {}, None),
            auth,
            HTTPError("https://cm/api/v1/x", 401, "Unauthorized", {}, None),
        ]

        client = self._authed()
        with pytest.raises(CMApiException) as exc_info:
            client.get("x")
        assert exc_info.value.api_error_code == 401

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_get_is_retried_through_a_transient_error(self, MockRequest):
        MockRequest.return_value.open.side_effect = [
            HTTPError("https://cm/api/v1/x", 503, "Unavailable", {}, None),
            self._ok_response({"id": "k1"}),
        ]

        client = self._authed()
        assert client.get("x") == {"id": "k1"}

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_get_gives_up_after_the_configured_attempts(self, MockRequest):
        MockRequest.return_value.open.side_effect = HTTPError(
            "https://cm/api/v1/x", 503, "Unavailable", {}, None
        )

        client = self._authed()
        with pytest.raises(CMApiException):
            client.get("x")
        assert MockRequest.return_value.open.call_count == 3

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_write_is_not_replayed_on_a_transient_error(self, MockRequest):
        MockRequest.return_value.open.side_effect = HTTPError(
            "https://cm/api/v1/x", 503, "Unavailable", {}, None
        )

        client = self._authed()
        with pytest.raises(CMApiException):
            client.post("x", data="{}")
        assert MockRequest.return_value.open.call_count == 1, \
            "a POST must not be replayed against CipherTrust Manager"

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api.Request"
    )
    def test_connection_failure_is_retried_for_reads_only(self, MockRequest):
        MockRequest.return_value.open.side_effect = URLError("connection reset")

        client = self._authed()
        with pytest.raises(CMApiException):
            client.get("x")
        reads = MockRequest.return_value.open.call_count

        MockRequest.return_value.open.reset_mock()
        with pytest.raises(CMApiException):
            client.delete("x")
        writes = MockRequest.return_value.open.call_count

        assert reads == 3 and writes == 1
