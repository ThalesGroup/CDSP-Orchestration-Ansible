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


# -- CTE Policy -------------------------------------------------------------

def createCTEPolicy(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/policies",
        data=build_request_payload(fields),
    )


def updateCTEPolicy(node, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/policies/" + quote_segment(policy_id),
        data=build_request_payload(fields),
    )


def ctePolicyAddRule(node, rule_name, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/policies/"
        + quote_segment(policy_id)
        + "/"
        + quote_segment(rule_name),
        data=build_request_payload(
            fields
        ),
    )


def ctePolicyPatchRule(node, rule_id, rule_name, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/policies/"
        + quote_segment(policy_id)
        + "/"
        + quote_segment(rule_name)
        + "/"
        + quote_segment(rule_id),
        data=build_request_payload(
            fields
        ),
    )


def ctePolicyDeleteRule(node, rule_id, rule_name, policy_id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "transparent-encryption/policies/"
        + quote_segment(policy_id)
        + "/"
        + quote_segment(rule_name)
        + "/"
        + quote_segment(rule_id),
    )


# -- ProcessSet --------------------------------------------------------------

def createProcessSet(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/processsets",
        data=build_request_payload(fields),
    )


def updateProcessSet(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/processsets/" + quote_segment(id),
        data=build_request_payload(fields),
    )


def addProcessToSet(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/processsets/" + quote_segment(id) + "/addprocesses",
        data=build_request_payload(fields),
    )


def updateProcessInSetByIndex(node, processIndex, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/processsets/"
        + quote_segment(id)
        + "/updateprocess/"
        + quote_segment(processIndex),
        data=build_request_payload(fields),
    )


def deleteProcessInSetByIndex(node, processIndex, id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "transparent-encryption/processsets/"
        + quote_segment(id)
        + "/delprocesses?processIndexList="
        + quote_query_value(processIndex),
    )


# -- ResourceSet -------------------------------------------------------------

def createResourceSet(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/resourcesets",
        data=build_request_payload(fields),
    )


def updateResourceSet(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/resourcesets/" + quote_segment(id),
        data=build_request_payload(fields),
    )


def addResourceToSet(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/resourcesets/" + quote_segment(id) + "/addresources",
        data=build_request_payload(fields),
    )


def updateResourceInSetByIndex(node, resourceIndex, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/resourcesets/"
        + quote_segment(id)
        + "/updateresource/"
        + quote_segment(resourceIndex),
        data=build_request_payload(fields),
    )


def deleteResourceInSetByIndex(node, resourceIndex, id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "transparent-encryption/resourcesets/"
        + quote_segment(id)
        + "/delresources?resourceIndexList="
        + quote_query_value(resourceIndex),
    )


# -- SignatureSet ------------------------------------------------------------

def createSignatureSet(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/signaturesets",
        data=build_request_payload(fields),
    )


def updateSignatureSet(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/signaturesets/" + quote_segment(id),
        data=build_request_payload(fields),
    )


def addSignatureToSet(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/signaturesets/" + quote_segment(id) + "/addsignatures",
        data=build_request_payload(fields),
    )


def getSignatureFromSetByFilter(node, id, file_name=None, **fields):
    """Look up a signature in a set, optionally filtered by file name.

    ``file_name`` is optional in the module's ``required_if`` rules, so it is
    built into the query only when supplied. Concatenating it unconditionally
    raised ``TypeError`` for a task that passed only ``id``.
    """
    client = CipherTrustClient(node)
    query = _build_query_string({
        "skip": 0,
        "limit": 1,
        "file_name": file_name,
    })
    return client.get(
        "transparent-encryption/signaturesets/"
        + quote_segment(id)
        + "/signatures"
        + query,
    )


def deleteSignatureInSetById(node, signature_id, id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "transparent-encryption/signaturesets/"
        + quote_segment(id)
        + "/signatures/"
        + quote_segment(signature_id),
    )


def sendSignAppRequest(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/signaturesets/" + quote_segment(id) + "/signapp",
        data=build_request_payload(fields),
    )


def querySignAppRequest(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/signaturesets/" + quote_segment(id) + "/querysignapp",
        data=build_request_payload(fields),
    )


def cancelSignAppRequest(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/signaturesets/" + quote_segment(id) + "/cancelsignapp",
        data=build_request_payload(fields),
    )


# -- CTE UserSet -------------------------------------------------------------

def createUserSet(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/usersets",
        data=build_request_payload(fields),
    )


def updateUserSet(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/usersets/" + quote_segment(id),
        data=build_request_payload(fields),
    )


def addUserToSet(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/usersets/" + quote_segment(id) + "/addusers",
        data=build_request_payload(fields),
    )


def updateUserInSetByIndex(node, userIndex, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/usersets/"
        + quote_segment(id)
        + "/updateuser/"
        + quote_segment(userIndex),
        data=build_request_payload(fields),
    )


def deleteUserInSetByIndex(node, userIndex, id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "transparent-encryption/usersets/"
        + quote_segment(id)
        + "/delusers?userIndexList="
        + quote_query_value(userIndex),
    )


# -- CSI Storage Group -------------------------------------------------------

def createCSIStorageGroup(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/csigroups",
        data=build_request_payload(fields),
    )


def updateCSIStorageGroup(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/csigroups/" + quote_segment(id),
        data=build_request_payload(fields),
    )


def csiGroupAddClient(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/csigroups/" + quote_segment(id) + "/clients",
        data=build_request_payload(fields),
    )


def csiGroupRemoveClient(node, client_id, id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "transparent-encryption/csigroups/"
        + quote_segment(id)
        + "/clients/"
        + quote_segment(client_id),
    )


def csiGroupAddGuardPoint(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/csigroups/" + quote_segment(id) + "/guardpoints",
        data=build_request_payload(fields),
    )


def csiGroupUpdateGuardPoint(node, gp_id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/csigroups/guardpoints/" + quote_segment(gp_id),
        data=build_request_payload(fields),
    )


def csiGroupRemoveGuardPoint(node, gp_id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "transparent-encryption/csigroups/guardpoints/" + quote_segment(gp_id),
    )


# -- CTE Client Group --------------------------------------------------------

def createClientGroup(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/clientgroups",
        data=build_request_payload(fields),
    )


def updateClientGroup(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clientgroups/" + quote_segment(id),
        data=build_request_payload(fields),
    )


def clientGroupAddClients(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/clientgroups/" + quote_segment(id) + "/clients",
        data=build_request_payload(fields),
    )


def clientGroupAddGuardPoint(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/clientgroups/" + quote_segment(id) + "/guardpoints",
        data=build_request_payload(fields),
    )


def clientGroupUpdateGuardPoint(node, guardpoint_id, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clientgroups/"
        + quote_segment(id)
        + "/guardpoints/"
        + quote_segment(guardpoint_id),
        data=build_request_payload(
            fields
        ),
    )


def clientGroupUnguardGuardPoint(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clientgroups/" + quote_segment(id) + "/guardpoints/unguard",
        data=build_request_payload(fields),
    )


def clientGroupAuthBinaries(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clientgroups/" + quote_segment(id) + "/auth-binaries",
        data=build_request_payload(fields),
    )


def clientGroupDeleteClient(node, client_id, id, **fields):
    client = CipherTrustClient(node)
    return client.delete(
        "transparent-encryption/clientgroups/"
        + quote_segment(id)
        + "/clients/"
        + quote_segment(client_id),
    )


def clientGroupLDTPause(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/clientgroups/" + quote_segment(id) + "/ldtpause",
        data=build_request_payload(fields),
    )


# -- CTE Client --------------------------------------------------------------

def createClient(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/clients",
        data=build_request_payload(fields),
    )


def patchClient(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clients/" + quote_segment(id),
        data=build_request_payload(fields),
    )


def clientAddGuardPoint(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/clients/" + quote_segment(id) + "/guardpoints",
        data=build_request_payload(fields),
    )


def unEnrollClient(node, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/unenroll",
        data=build_request_payload(fields),
    )


def deleteClients(node, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clients/delete",
        data=build_request_payload(fields),
    )


def deleteClientById(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clients/" + quote_segment(id) + "/delete",
        data=build_request_payload(fields),
    )


def updateClientAuthBinaries(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clients/" + quote_segment(id) + "/auth-binaries",
        data=build_request_payload(fields),
    )


def sendLDTPauseCmd(node, id, **fields):
    client = CipherTrustClient(node)
    return client.post(
        "transparent-encryption/clients/" + quote_segment(id) + "/ldtpause",
        data=build_request_payload(fields),
    )


def patchGuardPointCTEClient(node, gp_id, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clients/"
        + quote_segment(id)
        + "/guardpoints/"
        + quote_segment(gp_id),
        data=build_request_payload(fields),
    )


def unGuardPoints(node, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clients/" + quote_segment(id) + "/guardpoints/unguard",
        data=build_request_payload(fields),
    )


def updateGPEarlyAccess(node, gp_id, id, **fields):
    client = CipherTrustClient(node)
    return client.patch(
        "transparent-encryption/clients/"
        + quote_segment(id)
        + "/guardpoints/"
        + quote_segment(gp_id)
        + "/early-access",
        data=build_request_payload(fields),
    )
