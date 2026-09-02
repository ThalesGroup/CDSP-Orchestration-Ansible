# -*- coding: utf-8 -*-

# This is a utility file for interacting with the Thales CipherTrust Manager APIs for operations involving local or external certificate authority

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    quote_segment,
    build_request_payload,
)


def createLocalCA(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "ca/local-cas",
        data=build_request_payload(fields),
    )


def updateLocalCA(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "ca/local-cas/" + quote_segment(id),
        data=build_request_payload(
            fields
        ),
    )


def selfSign(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "ca/local-cas/" + quote_segment(id) + "/self-sign",
        data=build_request_payload(
            fields
        ),
    )


def issueCertificate(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "ca/local-cas/" + quote_segment(id) + "/certs",
        data=build_request_payload(
            fields
        ),
    )


def revokeCert(node, cert_id, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "ca/local-cas/" + quote_segment(id) + "/certs/" + quote_segment(cert_id) + "/revoke",
        data=build_request_payload(
            fields
        ),
    )


def resumeCert(node, cert_id, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "ca/local-cas/" + quote_segment(id) + "/certs/" + quote_segment(cert_id) + "/resume",
    )


def createCSR(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "vault/csr",
        data=build_request_payload(fields),
    )


def createCSRAndKey(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "ca/csr",
        data=build_request_payload(fields),
    )
