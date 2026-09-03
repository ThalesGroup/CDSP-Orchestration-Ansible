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


def _iface_url(interface_id, suffix=""):
    return "configs/interfaces/" + quote_segment(interface_id) + suffix


def create(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "configs/interfaces",
        data=build_request_payload(fields),
    )


def patch(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        _iface_url(quote_segment(interface_id)),
        data=build_request_payload(
            fields
        ),
    )


def addCertificateToInterface(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.put(
        _iface_url(quote_segment(interface_id), "/certificate"),
        data=build_request_payload(
            fields
        ),
    )


def getCertificateFromInterface(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.get(_iface_url(quote_segment(interface_id), "/certificate"))


def enableInterface(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.post(_iface_url(quote_segment(interface_id), "/enable"))


def disableInterface(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.post(_iface_url(quote_segment(interface_id), "/disable"))


def restoreDefaultTlsCiphers(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        _iface_url(quote_segment(interface_id), "/restore-default-tls-ciphers")
    )


def createCsr(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        _iface_url(quote_segment(interface_id), "/csr"),
        data=build_request_payload(
            fields
        ),
    )


def autogenServerCert(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        _iface_url(quote_segment(interface_id), "/auto-gen-server-cert")
    )


def useCertificate(node, interface_id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        _iface_url(quote_segment(interface_id), "/use-certificate"),
        data=build_request_payload(
            fields
        ),
    )
