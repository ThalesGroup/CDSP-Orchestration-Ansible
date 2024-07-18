# -*- coding: utf-8 -*-

# This is a utility file for interacting with the Thales CipherTrust Manager APIs for operations involving local or external certificate authority

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import ast

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    POSTData,
    PATCHData,
    POSTWithoutData,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)


def createLocalCA(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        __resp = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="ca/local-cas",
            id="id",
        )

        return ast.literal_eval(str(__resp))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateLocalCA(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="ca/local-cas/" + kwargs["id"],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def selfSign(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="ca/local-cas/" + kwargs["id"] + "/self-sign",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def issueCertificate(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="ca/local-cas/" + kwargs["id"] + "/certs",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def revokeCert(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id", "cert_id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="ca/local-cas/"
            + kwargs["id"]
            + "/certs/"
            + kwargs["cert_id"]
            + "/revoke",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def resumeCert(**kwargs):
    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint="ca/local-cas/"
            + kwargs["id"]
            + "/certs/"
            + kwargs["cert_id"]
            + "/resume",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def createCSR(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="vault/csr",
            id="csr",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def createCSRAndKey(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="ca/csr",
            id="csr",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise
