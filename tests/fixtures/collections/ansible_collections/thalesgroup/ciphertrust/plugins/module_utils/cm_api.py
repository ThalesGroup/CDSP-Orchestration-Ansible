# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import time
from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.error import HTTPError

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)


def is_json(myjson):
    """Check whether a string is valid JSON. Single source for the collection."""
    try:
        json.loads(myjson)
    except (ValueError, TypeError):
        return False
    return True


def build_request_payload(kwargs, remap=None):
    """Build a JSON request payload from keyword arguments.

    Filters out ``None`` values.  An optional *remap* dict translates
    keyword names (e.g. ``{"messageStr": "message"}``).
    """
    request = {}
    for key, value in kwargs.items():
        if value is not None:
            out_key = remap.get(key, key) if remap else key
            request[out_key] = value
    return json.dumps(request)


def _build_query_string(params):
    """Build a URL query string from a dict, omitting ``None`` values.

    Returns the string including the leading ``?``, or empty string if
    no params are set.
    """
    parts = []
    for key, value in params.items():
        if value is not None:
            parts.append("{0}={1}".format(key, value))
    if parts:
        return "?" + "&".join(parts)
    return ""


# ---------------------------------------------------------------------------
# Module-level JWT cache.  Keyed by (server_ip, user, auth_domain_path).
# Allows multiple CipherTrustClient instances within the same Ansible task
# invocation to share a single token, eliminating redundant auth calls.
# ---------------------------------------------------------------------------
_jwt_cache = {}

_TOKEN_TTL = 890  # seconds — slightly under the CM 15-minute default


class CipherTrustClient(object):
    """Thin HTTP client for CipherTrust Manager REST API.

    Provides ``get``, ``post``, ``put``, ``patch``, ``delete`` methods
    that handle authentication, JWT caching, TLS verification, and
    centralized error handling.

    Sensitive-data invariants:
      * The JWT bearer token is kept in ``_token`` and used only in the
        ``Authorization`` header.  It MUST NOT be placed in module
        results, exception messages, or debug output.
    """

    def __init__(self, node):
        self._server_ip = node["server_ip"]
        self._user = node["user"]
        self._password = node["password"]
        self._verify = bool(node.get("verify", False))
        self._auth_domain_path = node.get("auth_domain_path", "") or ""
        self._base_url = "https://" + self._server_ip + "/api/v1/"
        self._token = None
        self._cache_key = (self._server_ip, self._user, self._auth_domain_path)

    # -- authentication -----------------------------------------------------

    def _ensure_authenticated(self):
        cached = _jwt_cache.get(self._cache_key)
        if cached and time.time() < cached[1]:
            self._token = cached[0]
            return
        self._authenticate()

    def _authenticate(self):
        headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
        }
        auth_url = self._base_url + "auth/tokens"

        payload = {
            "grant_type": "password",
            "username": self._user,
            "password": self._password,
        }
        if self._auth_domain_path:
            payload["auth_domain_path"] = self._auth_domain_path

        r = Request(headers=headers, timeout=120, validate_certs=self._verify)
        _res = r.open(method="POST", url=auth_url, data=json.dumps(payload))
        response = json.loads(_res.read())
        self._token = response["jwt"]
        _jwt_cache[self._cache_key] = (self._token, time.time() + _TOKEN_TTL)

    def _headers(self):
        self._ensure_authenticated()
        return {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": "Bearer " + self._token,
        }

    # -- HTTP verbs ---------------------------------------------------------

    def request(self, method, endpoint, data=None):
        """Execute an API call and return the parsed response body.

        Raises ``CMApiException`` on application-level errors (``codeDesc``
        in the response) and re-raises ``HTTPError`` on transport errors.
        """
        url = self._base_url + endpoint
        try:
            r = Request(
                headers=self._headers(), timeout=120, validate_certs=self._verify
            )
            _res = r.open(method=method, url=url, data=data)
            body = _res.read()
            status_code = _res.getcode()

            if body:
                try:
                    response = json.loads(body)
                except (ValueError, TypeError):
                    # Non-JSON body (e.g. empty 204 or plain text)
                    return body
            else:
                return {}

            # CM application-level error check
            if isinstance(response, dict) and "codeDesc" in response:
                raise CMApiException(
                    message="API error: " + response.get("codeDesc", "Unknown"),
                    api_error_code=status_code,
                )

            return response
        except HTTPError as err:
            raise err

    def get(self, endpoint):
        return self.request("GET", endpoint)

    def post(self, endpoint, data=None):
        return self.request("POST", endpoint, data=data)

    def put(self, endpoint, data=None):
        return self.request("PUT", endpoint, data=data)

    def patch(self, endpoint, data=None):
        return self.request("PATCH", endpoint, data=data)

    def delete(self, endpoint):
        return self.request("DELETE", endpoint)


# ---------------------------------------------------------------------------
# Backward-compatible wrapper functions.
#
# These are used by ``cm_resource_delete.py`` and
# ``cm_resource_get_id_from_name.py`` which import specific function names
# directly.  All domain-level module_utils (dpg.py, cte.py, …) have been
# migrated to use ``CipherTrustClient`` directly and no longer call these.
# ---------------------------------------------------------------------------

def _client_from_node(node):
    """Convenience: create a CipherTrustClient from a node dict."""
    return CipherTrustClient(node)


def DELETEByNameOrId(key=None, cm_node=None, cm_api_endpoint=None):
    client = _client_from_node(cm_node)
    return client.delete(cm_api_endpoint + "/" + key)


def DeleteWithoutData(cm_node=None, cm_api_endpoint=None):
    client = _client_from_node(cm_node)
    return client.delete(cm_api_endpoint)


def GETIdByQueryParam(
    param=None, value=None, cm_node=None, cm_api_endpoint=None, id=None
):
    client = _client_from_node(cm_node)
    if param is not None:
        url = cm_api_endpoint + "/?skip=0&limit=1&" + param + "=" + value
    else:
        url = cm_api_endpoint

    response = client.get(url)

    if not isinstance(response, dict) or response.get("resources") is None:
        raise CMApiException(
            message="Error fetching data " + str(response),
            api_error_code=0,
        )

    if len(response["resources"]) > 0:
        if id is None:
            return response
        else:
            return {"id": response["resources"][0][id]}
    else:
        raise CMApiException(
            message="No matching records found",
            api_error_code=0,
        )
