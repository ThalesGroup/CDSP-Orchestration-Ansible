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

# Connection type → API path segment lookup.  Replaces the duplicated
# ``if/elif`` chains that were in ``createConnection`` and ``patchConnection``.
CONNECTION_ENDPOINTS = {
    "aws": "connectionmgmt/services/aws/connections",
    "azure": "connectionmgmt/services/azure/connections",
    "elasticsearch": "connectionmgmt/services/log-forwarders/elasticsearch/connections",
    "google": "connectionmgmt/services/gcp/connections",
    "hadoop": "connectionmgmt/services/hadoop/connections",
    "ldap": "connectionmgmt/services/ldap/connections",
    "oidc": "connectionmgmt/services/oidc/connections",
    "oracle": "connectionmgmt/services/oci/connections",
    "scp": "connectionmgmt/services/scp/connections",
    "smb": "connectionmgmt/services/smb/connections",
    "salesforce": "connectionmgmt/services/salesforce/connections",
    "syslog": "connectionmgmt/services/log-forwarders/syslog/connections",
    "luna_nw_hsm": "connectionmgmt/services/luna-network/connections",
}


def createConnection(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    endpoint = CONNECTION_ENDPOINTS.get(kwargs["connection_type"], "")
    return client.post(
        endpoint,
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "connection_type")}
        ),
    )


def patchConnection(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    endpoint = CONNECTION_ENDPOINTS.get(kwargs["connection_type"], "")
    return client.patch(
        endpoint + "/" + kwargs["connection_id"],
        data=build_request_payload(
            {
                k: v
                for k, v in kwargs.items()
                if k not in ("node", "connection_type", "connection_id")
            }
        ),
    )


def addHadoopNode(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "connectionmgmt/services/hadoop/connections/" + kwargs["connection_id"] + "/nodes",
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "connection_id")}
        ),
    )


def updateHadoopNode(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "connectionmgmt/services/hadoop/connections/"
        + kwargs["connection_id"]
        + "/nodes/"
        + kwargs["node_id"],
        data=build_request_payload(
            {
                k: v
                for k, v in kwargs.items()
                if k not in ("node", "node_id", "connection_id")
            }
        ),
    )


def deleteHadoopNode(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "connectionmgmt/services/hadoop/connections/"
        + kwargs["connection_id"]
        + "/nodes/"
        + kwargs["node_id"],
    )


def addLunaPartition(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "connectionmgmt/services/luna-network/connections/"
        + kwargs["connection_id"]
        + "/partitions",
        data=build_request_payload(
            {k: v for k, v in kwargs.items() if k not in ("node", "connection_id")}
        ),
    )


def deleteLunaPartition(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "connectionmgmt/services/luna-network/connections/"
        + kwargs["connection_id"]
        + "/partitions/"
        + kwargs["partition_id"],
    )


def addLunaSTCPartition(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "connectionmgmt/services/luna-network/stc-partition",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def addHSMServer(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "connectionmgmt/services/luna-network/servers",
        data=build_request_payload({k: v for k, v in kwargs.items() if k != "node"}),
    )


def enableSTC(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "connectionmgmt/services/luna-network/servers/"
        + kwargs["connection_id"]
        + "/enable-stc",
    )


def disableSTC(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "connectionmgmt/services/luna-network/servers/"
        + kwargs["connection_id"]
        + "/disable-stc",
    )
