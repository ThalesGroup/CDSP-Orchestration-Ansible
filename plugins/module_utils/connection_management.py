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
    DELETEByNameOrId,
    POSTWithoutData,
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


def createConnection(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "connection_type"] and value is not None:
            request[key] = value

    if kwargs["connection_type"] == "aws":
        endpoint = "connectionmgmt/services/aws/connections"
    elif kwargs["connection_type"] == "azure":
        endpoint = "connectionmgmt/services/azure/connections"
    elif kwargs["connection_type"] == "elasticsearch":
        endpoint = "connectionmgmt/services/log-forwarders/elasticsearch/connections"
    elif kwargs["connection_type"] == "google":
        endpoint = "connectionmgmt/services/gcp/connections"
    elif kwargs["connection_type"] == "hadoop":
        endpoint = "connectionmgmt/services/hadoop/connections"
    elif kwargs["connection_type"] == "ldap":
        endpoint = "connectionmgmt/services/ldap/connections"
    elif kwargs["connection_type"] == "oidc":
        endpoint = "connectionmgmt/services/oidc/connections"
    elif kwargs["connection_type"] == "oracle":
        endpoint = "connectionmgmt/services/oci/connections"
    elif kwargs["connection_type"] == "scp":
        endpoint = "connectionmgmt/services/scp/connections"
    elif kwargs["connection_type"] == "smb":
        endpoint = "connectionmgmt/services/smb/connections"
    elif kwargs["connection_type"] == "salesforce":
        endpoint = "connectionmgmt/services/salesforce/connections"
    elif kwargs["connection_type"] == "syslog":
        endpoint = "connectionmgmt/services/log-forwarders/syslog/connections"
    elif kwargs["connection_type"] == "luna_nw_hsm":
        endpoint = "connectionmgmt/services/luna-network/connections"
    else:
        endpoint = ""

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint=endpoint,
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def patchConnection(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if (
            key not in ["node", "connection_type", "connection_id"]
            and value is not None
        ):
            request[key] = value

    if kwargs["connection_type"] == "aws":
        endpoint = "connectionmgmt/services/aws/connections/" + kwargs["connection_id"]
    elif kwargs["connection_type"] == "azure":
        endpoint = (
            "connectionmgmt/services/azure/connections/" + kwargs["connection_id"]
        )
    elif kwargs["connection_type"] == "elasticsearch":
        endpoint = (
            "connectionmgmt/services/log-forwarders/elasticsearch/connections/"
            + kwargs["connection_id"]
        )
    elif kwargs["connection_type"] == "google":
        endpoint = "connectionmgmt/services/gcp/connections/" + kwargs["connection_id"]
    elif kwargs["connection_type"] == "hadoop":
        endpoint = (
            "connectionmgmt/services/hadoop/connections" + kwargs["connection_id"]
        )
    elif kwargs["connection_type"] == "ldap":
        endpoint = "connectionmgmt/services/ldap/connections" + kwargs["connection_id"]
    elif kwargs["connection_type"] == "oidc":
        endpoint = "connectionmgmt/services/oidc/connections" + kwargs["connection_id"]
    elif kwargs["connection_type"] == "oracle":
        endpoint = "connectionmgmt/services/oci/connections" + kwargs["connection_id"]
    elif kwargs["connection_type"] == "scp":
        endpoint = "connectionmgmt/services/scp/connections" + kwargs["connection_id"]
    elif kwargs["connection_type"] == "smb":
        endpoint = "connectionmgmt/services/smb/connections" + kwargs["connection_id"]
    elif kwargs["connection_type"] == "salesforce":
        endpoint = (
            "connectionmgmt/services/salesforce/connections" + kwargs["connection_id"]
        )
    elif kwargs["connection_type"] == "syslog":
        endpoint = (
            "connectionmgmt/services/log-forwarders/syslog/connections"
            + kwargs["connection_id"]
        )
    elif kwargs["connection_type"] == "luna_nw_hsm":
        endpoint = (
            "connectionmgmt/services/luna-network/connections" + kwargs["connection_id"]
        )
    else:
        endpoint = ""

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint=endpoint,
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def addHadoopNode(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "connection_id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/hadoop/connections/"
            + kwargs["connection_id"]
            + "/nodes",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateHadoopNode(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "node_id", "connection_id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/hadoop/connections/"
            + kwargs["connection_id"]
            + "/nodes/"
            + kwargs["node_id"],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def deleteHadoopNode(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "node_id", "connection_id"] and value is not None:
            request[key] = value

    try:
        response = DELETEByNameOrId(
            key="id",
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/hadoop/connections/"
            + kwargs["connection_id"]
            + "/nodes/"
            + kwargs["node_id"],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def addLunaPartition(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "connection_id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/luna-network/connections/"
            + kwargs["connection_id"]
            + "/partitions",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def deleteLunaPartition(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "partition_id", "connection_id"] and value is not None:
            request[key] = value

    try:
        response = DELETEByNameOrId(
            key="id",
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/luna-network/connections/"
            + kwargs["connection_id"]
            + "/partitions/"
            + kwargs["partition_id"],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


# enableSTC, disableSTC, addHSMServer, addLunaSTCPartition


def addLunaSTCPartition(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/luna-network/stc-partition",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def addHSMServer(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/luna-network/servers",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def enableSTC(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "connection_id"] and value is not None:
            request[key] = value

    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/luna-network/servers"
            + kwargs["connection_id"]
            + "/enable-stc",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def disableSTC(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "connection_id"] and value is not None:
            request[key] = value

    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint="connectionmgmt/services/luna-network/servers"
            + kwargs["connection_id"]
            + "/disable-stc",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise
