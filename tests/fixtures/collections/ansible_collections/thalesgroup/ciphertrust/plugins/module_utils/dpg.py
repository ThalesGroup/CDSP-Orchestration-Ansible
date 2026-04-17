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
)


def _exclude(kwargs, *keys):
    return {k: v for k, v in kwargs.items() if k not in keys}


# -- Access Policy ----------------------------------------------------------

def createAccessPolicy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/access-policies",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateAccessPolicy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/access-policies/" + kwargs["policy_id"],
        data=build_request_payload(_exclude(kwargs, "node", "policy_id")),
    )


def accessPolicyAddUserSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/access-policies/" + kwargs["policy_id"] + "/user-set",
        data=build_request_payload(_exclude(kwargs, "node", "policy_id")),
    )


def accessPolicyUpdateUserSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/access-policies/"
        + kwargs["policy_id"]
        + "/user-set/"
        + kwargs["policy_user_set_id"],
        data=build_request_payload(
            _exclude(kwargs, "node", "policy_id", "policy_user_set_id")
        ),
    )


def accessPolicyDeleteUserSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "data-protection/access-policies/"
        + kwargs["policy_id"]
        + "/user-set/"
        + kwargs["policy_user_set_id"],
    )


# -- Protection Policy ------------------------------------------------------

def createProtectionPolicy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/protection-policies",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateProtectionPolicy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/protection-policies/" + kwargs["policy_name"],
        data=build_request_payload(_exclude(kwargs, "node", "policy_name")),
    )


# -- UserSet ----------------------------------------------------------------

def createUserSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/user-sets",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateUserSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/user-sets/" + kwargs["user_set_id"],
        data=build_request_payload(_exclude(kwargs, "node", "user_set_id")),
    )


# -- Character Set ----------------------------------------------------------

def createCharacterSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/character-sets",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateCharacterSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/character-sets/" + kwargs["char_set_id"],
        data=build_request_payload(_exclude(kwargs, "node", "char_set_id")),
    )


# -- Masking Format ---------------------------------------------------------

def createMaskingFormat(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/masking-formats",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateMaskingFormat(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/masking-formats/" + kwargs["masking_format_id"],
        data=build_request_payload(_exclude(kwargs, "node", "masking_format_id")),
    )


# -- Client Profile ---------------------------------------------------------

def createClientProfile(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/client-profiles",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateClientProfile(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/client-profiles/" + kwargs["profile_id"],
        data=build_request_payload(_exclude(kwargs, "node", "profile_id")),
    )


# -- DPG Policy -------------------------------------------------------------

def createDPGPolicy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/dpg-policies",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateDPGPolicy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/dpg-policies/" + kwargs["policy_id"],
        data=build_request_payload(_exclude(kwargs, "node", "policy_id")),
    )


def dpgPolicyAddAPIUrl(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "data-protection/dpg-policies/" + kwargs["policy_id"] + "/api-urls",
        data=build_request_payload(_exclude(kwargs, "node", "policy_id")),
    )


def dpgPolicyUpdateAPIUrl(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "data-protection/dpg-policies/"
        + kwargs["policy_id"]
        + "/api-urls/"
        + kwargs["api_url_id"],
        data=build_request_payload(
            _exclude(kwargs, "node", "policy_id", "api_url_id")
        ),
    )


def dpgPolicyDeleteAPIUrl(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "data-protection/dpg-policies/"
        + kwargs["policy_id"]
        + "/api-urls/"
        + kwargs["api_url_id"],
    )
