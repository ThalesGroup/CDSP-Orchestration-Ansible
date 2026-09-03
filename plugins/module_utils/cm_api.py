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
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.six.moves.urllib.parse import quote, urlencode

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


def quote_segment(value):
    """Percent-encode a single URL path segment.

    Resource names and identifiers come from playbooks and may legitimately
    contain spaces, or maliciously contain ``/``, ``?`` or ``#``. Encoding with
    ``safe=""`` keeps the value inside its own path segment, so a value such as
    ``../../usermgmt/users/admin`` cannot walk out of the collection it was
    meant to address.
    """
    if value is None:
        return ""
    return quote(str(value), safe="")


def quote_query_value(value):
    """Percent-encode a query-string value, preserving list separators.

    CipherTrust accepts comma-separated index lists (``userIndexList=0,1``);
    a comma is a legal sub-delimiter in a query, so it is kept literal while
    everything that could inject another parameter is encoded.
    """
    if value is None:
        return ""
    return quote(str(value), safe=",")


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
    """Build an encoded URL query string, omitting ``None`` values.

    Values are percent-encoded, so a resource name containing ``&`` cannot
    inject additional query parameters and change what the request selects.

    Returns the string including the leading ``?``, or empty string if
    no params are set.
    """
    pairs = [(key, value) for key, value in params.items() if value is not None]
    if not pairs:
        return ""
    return "?" + urlencode(pairs)


def _error_detail(err):
    """Best-effort extraction of CM's error description from an HTTPError body.

    CM returns a JSON body such as ``{"codeDesc": "...", "message": "..."}``
    on most failures.  Falls back to the raw (truncated) body, then to the
    HTTP reason phrase.  Never includes request headers, so the bearer token
    and password cannot leak into the message.
    """
    body = b""
    try:
        body = err.read()
    except Exception:
        body = b""

    if body:
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            return body.strip()[:512]
        if isinstance(parsed, dict):
            # ``codeDesc`` is a fixed label for the error class -- for a
            # rejected payload it is always "NCERRBadRequest: Bad HTTP
            # request", which tells the user nothing.  ``message`` carries the
            # per-field detail ("iv: AES/CBC/PKCS5Padding algorithm requires a
            # 16 byte IV").  Report both, so the message names the failure and
            # says what to change.
            code_desc = parsed.get("codeDesc")
            detail = parsed.get("message") or parsed.get("error") or parsed.get("detail")
            if code_desc and detail and str(detail) != str(code_desc):
                return "{0}: {1}".format(code_desc, detail)[:512]
            for value in (code_desc, detail):
                if value:
                    return str(value)[:512]
        return str(parsed)[:512]

    return str(getattr(err, "reason", "") or getattr(err, "msg", "") or "")[:512]


# ---------------------------------------------------------------------------
# Module-level JWT cache.  Keyed by (server_ip, user, auth_domain_path).
# Allows multiple CipherTrustClient instances within the same Ansible task
# invocation to share a single token, eliminating redundant auth calls.
# ---------------------------------------------------------------------------
_jwt_cache = {}

_TOKEN_TTL = 890  # seconds — slightly under the CM 15-minute default

# Transient-failure policy. Only GET is retried: replaying a POST, PATCH or
# DELETE that may already have been applied risks duplicating a write, which
# matters more here than resilience does. A 401 is different -- it means the
# request was rejected before doing anything -- so any method re-authenticates
# once and is retried.
_RETRY_STATUSES = frozenset([429, 502, 503, 504])
_BACKOFF_SECONDS = (1.0, 3.0)


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
        try:
            _res = r.open(method="POST", url=auth_url, data=json.dumps(payload))
            response = json.loads(_res.read())
            self._token = response["jwt"]
        except HTTPError as err:
            raise CMApiException(
                message="Authentication to CipherTrust Manager at {0} failed "
                        "for user '{1}': {2}".format(
                            self._server_ip, self._user, _error_detail(err)
                        ),
                api_error_code=err.code,
            )
        except URLError as err:
            raise CMApiException(
                message="Could not connect to CipherTrust Manager at {0}: {1}".format(
                    self._server_ip, getattr(err, "reason", err)
                ),
            )
        except (ValueError, TypeError, KeyError):
            raise CMApiException(
                message="Unexpected authentication response from CipherTrust "
                        "Manager at {0}: no JWT in response body.".format(
                            self._server_ip
                        ),
            )
        _jwt_cache[self._cache_key] = (self._token, time.time() + _TOKEN_TTL)

    def _invalidate_token(self):
        """Drop the cached JWT so the next call re-authenticates."""
        _jwt_cache.pop(self._cache_key, None)
        self._token = None

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
        in the response), on HTTP error statuses, and on connection failures,
        so that ``ciphertrust_operation`` can turn any of them into a clean
        ``fail_json`` instead of letting a traceback escape the module.

        An expired session is renewed once transparently; transient server
        errors are retried for GET only (see ``_RETRY_STATUSES``).
        """
        url = self._base_url + endpoint
        attempt = 0
        reauthenticated = False

        while True:
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
                if err.code == 401 and not reauthenticated:
                    # The session expired earlier than the cached TTL implied.
                    reauthenticated = True
                    self._invalidate_token()
                    continue
                if (err.code in _RETRY_STATUSES and method == "GET"
                        and attempt < len(_BACKOFF_SECONDS)):
                    time.sleep(_BACKOFF_SECONDS[attempt])
                    attempt += 1
                    continue
                raise CMApiException(
                    message="{0} {1} failed: {2}".format(
                        method, endpoint, _error_detail(err)
                    ),
                    api_error_code=err.code,
                )

            except URLError as err:
                if method == "GET" and attempt < len(_BACKOFF_SECONDS):
                    time.sleep(_BACKOFF_SECONDS[attempt])
                    attempt += 1
                    continue
                raise CMApiException(
                    message="Could not connect to CipherTrust Manager at {0} "
                            "for {1} {2}: {3}".format(
                                self._server_ip, method, endpoint,
                                getattr(err, "reason", err),
                            ),
                )

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
    return client.delete(cm_api_endpoint + "/" + quote_segment(key))


def DeleteWithoutData(cm_node=None, cm_api_endpoint=None):
    client = _client_from_node(cm_node)
    return client.delete(cm_api_endpoint)


def GETIdByQueryParam(
    param=None, value=None, cm_node=None, cm_api_endpoint=None, id=None
):
    client = _client_from_node(cm_node)
    if param is not None:
        url = cm_api_endpoint + "/" + _build_query_string(
            {"skip": 0, "limit": 1, param: value}
        )
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
        resource = response["resources"][0]
        if id not in resource:
            raise CMApiException(
                message="Matching resource has no '{0}' field; got: {1}".format(
                    id, sorted(resource)
                ),
                api_error_code=0,
            )
        return {"id": resource[id]}
    else:
        raise CMApiException(
            message="No matching records found",
            api_error_code=0,
        )
