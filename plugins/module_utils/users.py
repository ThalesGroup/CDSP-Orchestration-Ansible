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
        "usermgmt/users",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def patch(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "usermgmt/users/" + kwargs["cm_user_id"],
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "cm_user_id")}
        ),
    )


def changepw(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "auth/changepw",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def patch_self(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "auth/self/user",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )
