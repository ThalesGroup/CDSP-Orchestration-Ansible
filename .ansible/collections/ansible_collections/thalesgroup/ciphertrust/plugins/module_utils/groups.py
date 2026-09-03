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


def create(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "usermgmt/groups",
        data=build_request_payload(fields),
    )


def patch(node, old_name, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "usermgmt/groups/" + quote_segment(old_name),
        data=build_request_payload(
            fields
        ),
    )


def addUserToGroup(node, object_id, name, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "usermgmt/groups/" + quote_segment(name) + "/users/" + quote_segment(object_id),
    )


def addClientToGroup(node, object_id, name, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "client-management/groups/" + quote_segment(name) + "/clients/" + quote_segment(object_id),
    )


def deleteUserFromGroup(node, object_id, name, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "usermgmt/groups/" + quote_segment(name) + "/users/" + quote_segment(object_id),
    )


def deleteClientFromGroup(node, object_id, name, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "client-management/groups/" + quote_segment(name) + "/clients/" + quote_segment(object_id),
    )
