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
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)


def getLockdata(node):
    """Fetch licensing lock data.

    Errors propagate as ``CMApiException`` so the calling module fails
    cleanly. This previously swallowed the exception and returned
    ``{"failed": True}``, which Ansible reported as a successful run.
    """
    client = CipherTrustClient(node)
    return {"data": client.get("licensing/lockdata")}


def getTrialLicenseId(**kwargs):
    """Return the id and status of the first trial licence.

    A CipherTrust Manager with no trials returns an empty resource list; that
    is reported as an error rather than raising ``IndexError``.
    """
    client = CipherTrustClient(kwargs["node"])
    response = client.get("licensing/trials")

    resources = response.get("resources") if isinstance(response, dict) else None
    if not resources:
        raise CMApiException(
            message="No trial licenses found on CipherTrust Manager.",
            api_error_code=0,
        )

    trial = resources[0]
    missing = [field for field in ("id", "status") if field not in trial]
    if missing:
        raise CMApiException(
            message="Trial licence record is missing {0}; got fields: {1}".format(
                ", ".join(missing), sorted(trial)
            ),
            api_error_code=0,
        )

    return {"id": trial["id"], "status": trial["status"]}


def addLicense(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "licensing/licenses",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def activateTrial(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "licensing/trials/" + quote_segment(kwargs["trialId"]) + "/activate",
    )


def deactivateTrial(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "licensing/trials/" + quote_segment(kwargs["trialId"]) + "/deactivate",
    )
