# -*- coding: utf-8 -*-

# This is a utility file for interacting with the Thales CipherTrust Manager APIs for operations involving local or external certificate authority

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    build_request_payload,
)


def createLocalCA(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "ca/local-cas",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def updateLocalCA(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "ca/local-cas/" + kwargs["id"],
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "id")}
        ),
    )


def selfSign(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "ca/local-cas/" + kwargs["id"] + "/self-sign",
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "id")}
        ),
    )


def issueCertificate(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "ca/local-cas/" + kwargs["id"] + "/certs",
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "id")}
        ),
    )


def revokeCert(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "ca/local-cas/" + kwargs["id"] + "/certs/" + kwargs["cert_id"] + "/revoke",
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "id", "cert_id")}
        ),
    )


def resumeCert(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "ca/local-cas/" + kwargs["id"] + "/certs/" + kwargs["cert_id"] + "/resume",
    )


def createCSR(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "vault/csr",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def createCSRAndKey(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "ca/csr",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )
