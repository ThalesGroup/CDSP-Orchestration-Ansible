# -*- coding: utf-8 -*-

# This is a utility file for interacting with the Thales CipherTrust Manager APIs for CipherTrust Transparent Encryption

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    quote_segment,
    quote_query_value,
    build_request_payload,
    _build_query_string,
)


def _exclude(kwargs, *keys):
    return {k: v for k, v in kwargs.items() if k not in keys}


# -- CTE Policy -------------------------------------------------------------

def createCTEPolicy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/policies",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateCTEPolicy(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/policies/" + quote_segment(kwargs["policy_id"]),
        data=build_request_payload(_exclude(kwargs, "node", "policy_id")),
    )


def ctePolicyAddRule(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/policies/"
        + quote_segment(kwargs["policy_id"])
        + "/"
        + quote_segment(kwargs["rule_name"]),
        data=build_request_payload(
            _exclude(kwargs, "node", "policy_id", "rule_name")
        ),
    )


def ctePolicyPatchRule(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/policies/"
        + quote_segment(kwargs["policy_id"])
        + "/"
        + quote_segment(kwargs["rule_name"])
        + "/"
        + quote_segment(kwargs["rule_id"]),
        data=build_request_payload(
            _exclude(kwargs, "node", "policy_id", "rule_name", "rule_id")
        ),
    )


def ctePolicyDeleteRule(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "transparent-encryption/policies/"
        + quote_segment(kwargs["policy_id"])
        + "/"
        + quote_segment(kwargs["rule_name"])
        + "/"
        + quote_segment(kwargs["rule_id"]),
    )


# -- ProcessSet --------------------------------------------------------------

def createProcessSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/processsets",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateProcessSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/processsets/" + quote_segment(kwargs["id"]),
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def addProcessToSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/processsets/" + quote_segment(kwargs["id"]) + "/addprocesses",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def updateProcessInSetByIndex(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/processsets/"
        + quote_segment(kwargs["id"])
        + "/updateprocess/"
        + quote_segment(kwargs["processIndex"]),
        data=build_request_payload(_exclude(kwargs, "node", "id", "processIndex")),
    )


def deleteProcessInSetByIndex(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "transparent-encryption/processsets/"
        + quote_segment(kwargs["id"])
        + "/delprocesses?processIndexList="
        + quote_query_value(kwargs["processIndex"]),
    )


# -- ResourceSet -------------------------------------------------------------

def createResourceSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/resourcesets",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateResourceSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/resourcesets/" + quote_segment(kwargs["id"]),
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def addResourceToSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/resourcesets/" + quote_segment(kwargs["id"]) + "/addresources",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def updateResourceInSetByIndex(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/resourcesets/"
        + quote_segment(kwargs["id"])
        + "/updateresource/"
        + quote_segment(kwargs["resourceIndex"]),
        data=build_request_payload(_exclude(kwargs, "node", "id", "resourceIndex")),
    )


def deleteResourceInSetByIndex(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "transparent-encryption/resourcesets/"
        + quote_segment(kwargs["id"])
        + "/delresources?resourceIndexList="
        + quote_query_value(kwargs["resourceIndex"]),
    )


# -- SignatureSet ------------------------------------------------------------

def createSignatureSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/signaturesets",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateSignatureSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/signaturesets/" + quote_segment(kwargs["id"]),
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def addSignatureToSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/signaturesets/" + quote_segment(kwargs["id"]) + "/addsignatures",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def getSignatureFromSetByFilter(**kwargs):
    """Look up a signature in a set, optionally filtered by file name.

    ``file_name`` is optional in the module's ``required_if`` rules, so it is
    built into the query only when supplied. Concatenating it unconditionally
    raised ``TypeError`` for a task that passed only ``id``.
    """
    client = CipherTrustClient(kwargs["node"])
    query = _build_query_string({
        "skip": 0,
        "limit": 1,
        "file_name": kwargs.get("file_name"),
    })
    return client.get(
        "transparent-encryption/signaturesets/"
        + quote_segment(kwargs["id"])
        + "/signatures"
        + query,
    )


def deleteSignatureInSetById(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "transparent-encryption/signaturesets/"
        + quote_segment(kwargs["id"])
        + "/signatures/"
        + quote_segment(kwargs["signature_id"]),
    )


def sendSignAppRequest(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/signaturesets/" + quote_segment(kwargs["id"]) + "/signapp",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def querySignAppRequest(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/signaturesets/" + quote_segment(kwargs["id"]) + "/querysignapp",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def cancelSignAppRequest(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/signaturesets/" + quote_segment(kwargs["id"]) + "/cancelsignapp",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


# -- CTE UserSet -------------------------------------------------------------

def createUserSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/usersets",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateUserSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/usersets/" + quote_segment(kwargs["id"]),
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def addUserToSet(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/usersets/" + quote_segment(kwargs["id"]) + "/addusers",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def updateUserInSetByIndex(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/usersets/"
        + quote_segment(kwargs["id"])
        + "/updateuser/"
        + quote_segment(kwargs["userIndex"]),
        data=build_request_payload(_exclude(kwargs, "node", "id", "userIndex")),
    )


def deleteUserInSetByIndex(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "transparent-encryption/usersets/"
        + quote_segment(kwargs["id"])
        + "/delusers?userIndexList="
        + quote_query_value(kwargs["userIndex"]),
    )


# -- CSI Storage Group -------------------------------------------------------

def createCSIStorageGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/csigroups",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateCSIStorageGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/csigroups/" + quote_segment(kwargs["id"]),
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def csiGroupAddClient(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/csigroups/" + quote_segment(kwargs["id"]) + "/clients",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def csiGroupRemoveClient(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "transparent-encryption/csigroups/"
        + quote_segment(kwargs["id"])
        + "/clients/"
        + quote_segment(kwargs["client_id"]),
    )


def csiGroupAddGuardPoint(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/csigroups/" + quote_segment(kwargs["id"]) + "/guardpoints",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def csiGroupUpdateGuardPoint(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/csigroups/guardpoints/" + quote_segment(kwargs["gp_id"]),
        data=build_request_payload(_exclude(kwargs, "node", "gp_id")),
    )


def csiGroupRemoveGuardPoint(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "transparent-encryption/csigroups/guardpoints/" + quote_segment(kwargs["gp_id"]),
    )


# -- CTE Client Group --------------------------------------------------------

def createClientGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/clientgroups",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def updateClientGroup(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clientgroups/" + quote_segment(kwargs["id"]),
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def clientGroupAddClients(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/clientgroups/" + quote_segment(kwargs["id"]) + "/clients",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def clientGroupAddGuardPoint(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/clientgroups/" + quote_segment(kwargs["id"]) + "/guardpoints",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def clientGroupUpdateGuardPoint(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clientgroups/"
        + quote_segment(kwargs["id"])
        + "/guardpoints/"
        + quote_segment(kwargs["guardpoint_id"]),
        data=build_request_payload(
            _exclude(kwargs, "node", "id", "guardpoint_id")
        ),
    )


def clientGroupUnguardGuardPoint(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clientgroups/" + quote_segment(kwargs["id"]) + "/guardpoints/unguard",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def clientGroupAuthBinaries(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clientgroups/" + quote_segment(kwargs["id"]) + "/auth-binaries",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def clientGroupDeleteClient(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.delete(
        "transparent-encryption/clientgroups/"
        + quote_segment(kwargs["id"])
        + "/clients/"
        + quote_segment(kwargs["client_id"]),
    )


def clientGroupLDTPause(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/clientgroups/" + quote_segment(kwargs["id"]) + "/ldtpause",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


# -- CTE Client --------------------------------------------------------------

def createClient(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/clients",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def patchClient(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clients/" + quote_segment(kwargs["id"]),
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def clientAddGuardPoint(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/clients/" + quote_segment(kwargs["id"]) + "/guardpoints",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def unEnrollClient(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/unenroll",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def deleteClients(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clients/delete",
        data=build_request_payload(_exclude(kwargs, "node")),
    )


def deleteClientById(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clients/" + quote_segment(kwargs["id"]) + "/delete",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def updateClientAuthBinaries(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clients/" + quote_segment(kwargs["id"]) + "/auth-binaries",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def sendLDTPauseCmd(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.post(
        "transparent-encryption/clients/" + quote_segment(kwargs["id"]) + "/ldtpause",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def patchGuardPointCTEClient(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clients/"
        + quote_segment(kwargs["id"])
        + "/guardpoints/"
        + quote_segment(kwargs["gp_id"]),
        data=build_request_payload(_exclude(kwargs, "node", "id", "gp_id")),
    )


def unGuardPoints(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clients/" + quote_segment(kwargs["id"]) + "/guardpoints/unguard",
        data=build_request_payload(_exclude(kwargs, "node", "id")),
    )


def updateGPEarlyAccess(**kwargs):
    client = CipherTrustClient(kwargs["node"])
    return client.patch(
        "transparent-encryption/clients/"
        + quote_segment(kwargs["id"])
        + "/guardpoints/"
        + quote_segment(kwargs["gp_id"])
        + "/early-access",
        data=build_request_payload(_exclude(kwargs, "node", "id", "gp_id")),
    )
