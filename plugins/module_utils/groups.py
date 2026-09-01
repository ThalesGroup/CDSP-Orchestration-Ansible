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
)


def create(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "usermgmt/groups",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def patch(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "usermgmt/groups/" + quote_segment(kwargs["old_name"]),
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "old_name")}
        ),
    )


def addUserToGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "usermgmt/groups/" + quote_segment(kwargs["name"]) + "/users/" + quote_segment(kwargs["object_id"]),
    )


def addClientToGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "client-management/groups/" + quote_segment(kwargs["name"]) + "/clients/" + quote_segment(kwargs["object_id"]),
    )


def deleteUserFromGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "usermgmt/groups/" + quote_segment(kwargs["name"]) + "/users/" + quote_segment(kwargs["object_id"]),
    )


def deleteClientFromGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "client-management/groups/" + quote_segment(kwargs["name"]) + "/clients/" + quote_segment(kwargs["object_id"]),
    )
