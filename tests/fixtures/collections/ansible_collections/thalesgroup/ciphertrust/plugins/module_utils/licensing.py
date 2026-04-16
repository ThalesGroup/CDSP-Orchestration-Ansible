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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)


def getLockdata(node):
    result = dict()
    try:
        client = CipherTrustClient(node)
        response = client.get("licensing/lockdata")
        result["data"] = response
        return result
    except CMApiException:
        result["failed"] = True
        return result


def getTrialLicenseId(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    response = client.get("licensing/trials")

    resources = response["resources"]
    return {
        "id": resources[0]["id"],
        "status": resources[0]["status"],
    }


def addLicense(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "licensing/licenses",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def activateTrial(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "licensing/trials/" + kwargs["trialId"] + "/activate",
    )


def deactivateTrial(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "licensing/trials/" + kwargs["trialId"] + "/deactivate",
    )
