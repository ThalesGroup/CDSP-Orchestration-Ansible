# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
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
        "usermgmt/groups/" + kwargs["old_name"],
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "old_name")}
        ),
    )


def addUserToGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "usermgmt/groups/" + kwargs["name"] + "/users/" + kwargs["object_id"],
    )


def addClientToGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "client-management/groups/" + kwargs["name"] + "/clients/" + kwargs["object_id"],
    )


def deleteUserFromGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "usermgmt/groups/" + kwargs["name"] + "/users/" + kwargs["object_id"],
    )


def deleteClientFromGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "client-management/groups/" + kwargs["name"] + "/clients/" + kwargs["object_id"],
    )
