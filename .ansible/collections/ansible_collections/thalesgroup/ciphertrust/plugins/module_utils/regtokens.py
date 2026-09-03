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
        "client-management/regtokens",
        data=build_request_payload(fields),
    )


def patch(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "client-management/regtokens/" + quote_segment(id),
        data=build_request_payload(
            fields
        ),
    )
