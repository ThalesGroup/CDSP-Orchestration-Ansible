# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import ast

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    POSTData,
    PATCHData,
    POSTWithoutData,
    GETAPIData,
    PUTData,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)

def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError as e:
        return False
    return True


def create(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="configs/interfaces",
            id="name",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def patch(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "interface_id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="configs/interfaces/" + kwargs["interface_id"],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def addCertificateToInterface(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "interface_id"] and value is not None:
            request[key] = value

    url = "configs/interfaces/" + kwargs["interface_id"] + "/certificate"

    payload = json.dumps(request)

    try:
        response = PUTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise

def getCertificateFromInterface(**kwargs):
    url = "configs/interfaces/" + kwargs["interface_id"] + "/certificate"

    try:
        response = GETAPIData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def enableInterface(**kwargs):
    url = "configs/interfaces/" + kwargs["interface_id"] + "/enable"

    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def disableInterface(**kwargs):
    url = "configs/interfaces/" + kwargs["interface_id"] + "/disable"

    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def restoreDefaultTlsCiphers(**kwargs):
    url = (
        "configs/interfaces/" + kwargs["interface_id"] + "/restore-default-tls-ciphers"
    )

    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def createCsr(**kwargs):
    url = "configs/interfaces/" + kwargs["interface_id"] + "/csr"

    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "interface_id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def autogenServerCert(**kwargs):
    url = "configs/interfaces/" + kwargs["interface_id"] + "/auto-gen-server-cert"

    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def useCertificate(**kwargs):
    url = "configs/interfaces/" + kwargs["interface_id"] + "/use-certificate"

    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "interface_id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise
