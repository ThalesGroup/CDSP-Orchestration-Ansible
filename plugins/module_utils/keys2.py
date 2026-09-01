# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    build_request_payload,
    _build_query_string,
)


def _key_op_url(cm_key_id, action, key_version=None, id_type=None, includeMaterial=None):
    """Build a vault/keys2/<id>/<action>?... URL."""
    qs_params = {}
    if key_version is not None:
        qs_params["version"] = key_version
    if id_type is not None:
        qs_params["type"] = id_type
    if includeMaterial is not None:
        qs_params["includeMaterial"] = includeMaterial
    return "vault/keys2/" + cm_key_id + "/" + action + _build_query_string(qs_params)


# -- CRUD -------------------------------------------------------------------

def create(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "vault/keys2",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def patch(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "vault/keys2/" + kwargs["cm_key_id"],
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "cm_key_id")}
        ),
    )


def version_create(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "vault/keys2/" + kwargs["cm_key_id"] + "/versions",
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "cm_key_id")}
        ),
    )


# -- Key lifecycle operations -----------------------------------------------

_OP_EXCLUDE = frozenset(["node", "cm_key_id", "key_version", "id_type"])


def destroy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    url = _key_op_url(kwargs["cm_key_id"], "destroy", kwargs.get("key_version"), kwargs.get("id_type"))
    return client.post(url)


def archive(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    url = _key_op_url(kwargs["cm_key_id"], "archive", kwargs.get("key_version"), kwargs.get("id_type"))
    return client.post(url)


def recover(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    url = _key_op_url(kwargs["cm_key_id"], "recover", kwargs.get("key_version"), kwargs.get("id_type"))
    return client.post(url)


def revoke(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    url = _key_op_url(kwargs["cm_key_id"], "revoke", kwargs.get("key_version"), kwargs.get("id_type"))
    payload_dict = {k: v for k, v in kwargs.items() if k not in _OP_EXCLUDE}
    return client.post(url, data=build_request_payload(payload_dict, remap={"messageStr": "message"}))


def reactivate(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    url = _key_op_url(kwargs["cm_key_id"], "reactivate", kwargs.get("key_version"), kwargs.get("id_type"))
    payload_dict = {k: v for k, v in kwargs.items() if k not in _OP_EXCLUDE}
    return client.post(url, data=build_request_payload(payload_dict, remap={"messageStr": "message"}))


def export(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    url = _key_op_url(kwargs["cm_key_id"], "export", kwargs.get("key_version"), kwargs.get("id_type"))
    payload_dict = {k: v for k, v in kwargs.items() if k not in _OP_EXCLUDE}
    return client.post(url, data=build_request_payload(payload_dict, remap={"keyFormat": "format"}))


def clone(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    url = _key_op_url(
        kwargs["cm_key_id"], "clone",
        kwargs.get("key_version"), kwargs.get("id_type"), kwargs.get("includeMaterial"),
    )
    exclude = _OP_EXCLUDE | {"includeMaterial"}
    payload_dict = {k: v for k, v in kwargs.items() if k not in exclude}
    return client.post(url, data=build_request_payload(payload_dict))
