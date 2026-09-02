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


# -- Access Policy ----------------------------------------------------------

def createAccessPolicy(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/access-policies",
        data=build_request_payload(fields),
    )


def updateAccessPolicy(node, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/access-policies/" + quote_segment(policy_id),
        data=build_request_payload(fields),
    )


def accessPolicyAddUserSet(node, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/access-policies/" + quote_segment(policy_id) + "/user-set",
        data=build_request_payload(fields),
    )


def accessPolicyUpdateUserSet(node, policy_user_set_id, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/access-policies/"
        + quote_segment(policy_id)
        + "/user-set/"
        + quote_segment(policy_user_set_id),
        data=build_request_payload(
            fields
        ),
    )


def accessPolicyDeleteUserSet(node, policy_user_set_id, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "data-protection/access-policies/"
        + quote_segment(policy_id)
        + "/user-set/"
        + quote_segment(policy_user_set_id),
    )


# -- Protection Policy ------------------------------------------------------

def createProtectionPolicy(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/protection-policies",
        data=build_request_payload(fields),
    )


def updateProtectionPolicy(node, policy_name, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/protection-policies/" + quote_segment(policy_name),
        data=build_request_payload(fields),
    )


# -- UserSet ----------------------------------------------------------------

def createUserSet(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/user-sets",
        data=build_request_payload(fields),
    )


def updateUserSet(node, user_set_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/user-sets/" + quote_segment(user_set_id),
        data=build_request_payload(fields),
    )


# -- Character Set ----------------------------------------------------------

def createCharacterSet(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/character-sets",
        data=build_request_payload(fields),
    )


def updateCharacterSet(node, char_set_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/character-sets/" + quote_segment(char_set_id),
        data=build_request_payload(fields),
    )


# -- Masking Format ---------------------------------------------------------

def createMaskingFormat(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/masking-formats",
        data=build_request_payload(fields),
    )


def updateMaskingFormat(node, masking_format_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/masking-formats/" + quote_segment(masking_format_id),
        data=build_request_payload(fields),
    )


# -- Client Profile ---------------------------------------------------------

def createClientProfile(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/client-profiles",
        data=build_request_payload(fields),
    )


def updateClientProfile(node, profile_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/client-profiles/" + quote_segment(profile_id),
        data=build_request_payload(fields),
    )


# -- DPG Policy -------------------------------------------------------------

def createDPGPolicy(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/dpg-policies",
        data=build_request_payload(fields),
    )


def updateDPGPolicy(node, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/dpg-policies/" + quote_segment(policy_id),
        data=build_request_payload(fields),
    )


def dpgPolicyAddAPIUrl(node, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "data-protection/dpg-policies/" + quote_segment(policy_id) + "/api-urls",
        data=build_request_payload(fields),
    )


def dpgPolicyUpdateAPIUrl(node, api_url_id, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "data-protection/dpg-policies/"
        + quote_segment(policy_id)
        + "/api-urls/"
        + quote_segment(api_url_id),
        data=build_request_payload(
            fields
        ),
    )


def dpgPolicyDeleteAPIUrl(node, api_url_id, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "data-protection/dpg-policies/"
        + quote_segment(policy_id)
        + "/api-urls/"
        + quote_segment(api_url_id),
    )
