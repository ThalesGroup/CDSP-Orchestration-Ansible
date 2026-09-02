# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    build_request_payload,
)


def restartCMServices(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "system/services/restart",
        data=build_request_payload(fields),
    )
