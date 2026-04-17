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


def _iface_url(interface_id, suffix=""):
    return "configs/interfaces/" + interface_id + suffix


def create(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "configs/interfaces",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def patch(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        _iface_url(kwargs["interface_id"]),
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "interface_id")}
        ),
    )


def addCertificateToInterface(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.put(
        _iface_url(kwargs["interface_id"], "/certificate"),
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "interface_id")}
        ),
    )


def getCertificateFromInterface(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.get(_iface_url(kwargs["interface_id"], "/certificate"))


def enableInterface(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(_iface_url(kwargs["interface_id"], "/enable"))


def disableInterface(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(_iface_url(kwargs["interface_id"], "/disable"))


def restoreDefaultTlsCiphers(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        _iface_url(kwargs["interface_id"], "/restore-default-tls-ciphers")
    )


def createCsr(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        _iface_url(kwargs["interface_id"], "/csr"),
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "interface_id")}
        ),
    )


def autogenServerCert(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        _iface_url(kwargs["interface_id"], "/auto-gen-server-cert")
    )


def useCertificate(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        _iface_url(kwargs["interface_id"], "/use-certificate"),
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "interface_id")}
        ),
    )
