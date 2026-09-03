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
    quote_segment,
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
    return ("vault/keys2/" + quote_segment(cm_key_id) + "/" + action
            + _build_query_string(qs_params))


# -- CRUD -------------------------------------------------------------------

def create(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "vault/keys2",
        data=build_request_payload(fields),
    )


def patch(node, cm_key_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "vault/keys2/" + quote_segment(cm_key_id),
        data=build_request_payload(
            fields
        ),
    )


def version_create(node, cm_key_id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "vault/keys2/" + quote_segment(cm_key_id) + "/versions",
        data=build_request_payload(
            fields
        ),
    )


# -- Key lifecycle operations -----------------------------------------------


def destroy(node, cm_key_id, key_version=None, id_type=None, **fields):
    client = CipherTrustClient(node)
    url = _key_op_url(cm_key_id, "destroy", key_version, id_type)
    return client.post(url)


def archive(node, cm_key_id, key_version=None, id_type=None, **fields):
    client = CipherTrustClient(node)
    url = _key_op_url(cm_key_id, "archive", key_version, id_type)
    return client.post(url)


def recover(node, cm_key_id, key_version=None, id_type=None, **fields):
    client = CipherTrustClient(node)
    url = _key_op_url(cm_key_id, "recover", key_version, id_type)
    return client.post(url)


def revoke(node, cm_key_id, key_version=None, id_type=None, **fields):
    client = CipherTrustClient(node)
    url = _key_op_url(cm_key_id, "revoke", key_version, id_type)
    payload_dict = fields
    return client.post(url, data=build_request_payload(payload_dict, remap={"messageStr": "message"}))


def reactivate(node, cm_key_id, key_version=None, id_type=None, **fields):
    client = CipherTrustClient(node)
    url = _key_op_url(cm_key_id, "reactivate", key_version, id_type)
    payload_dict = fields
    return client.post(url, data=build_request_payload(payload_dict, remap={"messageStr": "message"}))


def export(node, cm_key_id, key_version=None, id_type=None, **fields):
    client = CipherTrustClient(node)
    url = _key_op_url(cm_key_id, "export", key_version, id_type)
    payload_dict = fields
    return client.post(url, data=build_request_payload(payload_dict, remap={"keyFormat": "format"}))


def clone(node, cm_key_id, key_version=None, id_type=None,
          includeMaterial=None, **fields):
    client = CipherTrustClient(node)
    url = _key_op_url(cm_key_id, "clone", key_version, id_type, includeMaterial)
    return client.post(url, data=build_request_payload(fields))
