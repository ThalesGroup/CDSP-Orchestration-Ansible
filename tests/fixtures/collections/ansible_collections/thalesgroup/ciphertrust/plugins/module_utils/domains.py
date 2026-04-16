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
        "domains",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def patch(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "domains/" + kwargs["domain_id"],
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "domain_id")}
        ),
    )


def enableSyslogRedirection(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post("domain-syslog-redirection/enable")


def disableSyslogRedirection(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post("domain-syslog-redirection/disable")


# Backward-compatible alias for the incorrectly-named original function
disableInterface = disableSyslogRedirection
