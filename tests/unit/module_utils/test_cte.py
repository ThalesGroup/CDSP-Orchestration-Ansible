#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/cte.py"""

from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte import (
    # CTE Policy
    createCTEPolicy, updateCTEPolicy, ctePolicyAddRule, ctePolicyPatchRule, ctePolicyDeleteRule,
    # ProcessSet
    createProcessSet, updateProcessSet, addProcessToSet,
    updateProcessInSetByIndex, deleteProcessInSetByIndex,
    # ResourceSet
    createResourceSet, updateResourceSet, addResourceToSet,
    updateResourceInSetByIndex, deleteResourceInSetByIndex,
    # SignatureSet
    createSignatureSet, updateSignatureSet, addSignatureToSet,
    getSignatureFromSetByFilter, deleteSignatureInSetById,
    sendSignAppRequest, querySignAppRequest, cancelSignAppRequest,
    # CTE UserSet
    createUserSet, updateUserSet, addUserToSet,
    updateUserInSetByIndex, deleteUserInSetByIndex,
    # CSI Storage Group
    createCSIStorageGroup, updateCSIStorageGroup,
    csiGroupAddClient, csiGroupRemoveClient,
    csiGroupAddGuardPoint, csiGroupUpdateGuardPoint, csiGroupRemoveGuardPoint,
    # CTE Client Group
    createClientGroup, updateClientGroup,
    clientGroupAddClients, clientGroupAddGuardPoint,
    clientGroupUpdateGuardPoint, clientGroupUnguardGuardPoint,
    clientGroupAuthBinaries, clientGroupDeleteClient, clientGroupLDTPause,
    # CTE Client
    createClient, patchClient, clientAddGuardPoint,
    unEnrollClient, deleteClients, deleteClientById,
    updateClientAuthBinaries, sendLDTPauseCmd,
    patchGuardPointCTEClient, unGuardPoints, updateGPEarlyAccess,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cte.CipherTrustClient"


# ---------------------------------------------------------------------------
# CTE Policy
# ---------------------------------------------------------------------------

class TestCTEPolicy:
    @patch(MODULE_PATH)
    def test_create(self, MC):
        m = MC.return_value
        m.post.return_value = {"id": "p1"}
        createCTEPolicy(node=TEST_NODE, name="pol1")
        assert m.post.call_args[0][0] == "transparent-encryption/policies"

    @patch(MODULE_PATH)
    def test_update(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateCTEPolicy(node=TEST_NODE, policy_id="p1", description="updated")
        assert m.patch.call_args[0][0] == "transparent-encryption/policies/p1"

    @patch(MODULE_PATH)
    def test_add_rule(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        ctePolicyAddRule(node=TEST_NODE, policy_id="p1", rule_name="securityrules")
        assert m.post.call_args[0][0] == "transparent-encryption/policies/p1/securityrules"

    @patch(MODULE_PATH)
    def test_patch_rule(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        ctePolicyPatchRule(node=TEST_NODE, policy_id="p1", rule_name="securityrules", rule_id="r1")
        assert m.patch.call_args[0][0] == "transparent-encryption/policies/p1/securityrules/r1"

    @patch(MODULE_PATH)
    def test_delete_rule(self, MC):
        m = MC.return_value
        m.delete.return_value = {}
        ctePolicyDeleteRule(node=TEST_NODE, policy_id="p1", rule_name="securityrules", rule_id="r1")
        m.delete.assert_called_once_with("transparent-encryption/policies/p1/securityrules/r1")


# ---------------------------------------------------------------------------
# ProcessSet
# ---------------------------------------------------------------------------

class TestProcessSet:
    @patch(MODULE_PATH)
    def test_create(self, MC):
        m = MC.return_value
        m.post.return_value = {"id": "ps1"}
        createProcessSet(node=TEST_NODE, name="pset")
        assert m.post.call_args[0][0] == "transparent-encryption/processsets"

    @patch(MODULE_PATH)
    def test_update(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateProcessSet(node=TEST_NODE, id="ps1", name="updated")
        assert m.patch.call_args[0][0] == "transparent-encryption/processsets/ps1"

    @patch(MODULE_PATH)
    def test_add_process(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        addProcessToSet(node=TEST_NODE, id="ps1", directory="/opt")
        assert m.patch.call_args[0][0] == "transparent-encryption/processsets/ps1/addprocesses"

    @patch(MODULE_PATH)
    def test_update_by_index(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateProcessInSetByIndex(node=TEST_NODE, id="ps1", processIndex="0")
        assert m.patch.call_args[0][0] == "transparent-encryption/processsets/ps1/updateprocess/0"

    @patch(MODULE_PATH)
    def test_delete_by_index(self, MC):
        m = MC.return_value
        m.delete.return_value = {}
        deleteProcessInSetByIndex(node=TEST_NODE, id="ps1", processIndex="0")
        m.delete.assert_called_once_with("transparent-encryption/processsets/ps1/delprocesses?processIndexList=0")


# ---------------------------------------------------------------------------
# ResourceSet
# ---------------------------------------------------------------------------

class TestResourceSet:
    @patch(MODULE_PATH)
    def test_create(self, MC):
        m = MC.return_value
        m.post.return_value = {"id": "rs1"}
        createResourceSet(node=TEST_NODE, name="rset")
        assert m.post.call_args[0][0] == "transparent-encryption/resourcesets"

    @patch(MODULE_PATH)
    def test_update(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateResourceSet(node=TEST_NODE, id="rs1")
        assert m.patch.call_args[0][0] == "transparent-encryption/resourcesets/rs1"

    @patch(MODULE_PATH)
    def test_add_resource(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        addResourceToSet(node=TEST_NODE, id="rs1")
        assert m.patch.call_args[0][0] == "transparent-encryption/resourcesets/rs1/addresources"

    @patch(MODULE_PATH)
    def test_update_by_index(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateResourceInSetByIndex(node=TEST_NODE, id="rs1", resourceIndex="0")
        assert m.patch.call_args[0][0] == "transparent-encryption/resourcesets/rs1/updateresource/0"

    @patch(MODULE_PATH)
    def test_delete_by_index(self, MC):
        m = MC.return_value
        m.delete.return_value = {}
        deleteResourceInSetByIndex(node=TEST_NODE, id="rs1", resourceIndex="0")
        m.delete.assert_called_once_with("transparent-encryption/resourcesets/rs1/delresources?resourceIndexList=0")


# ---------------------------------------------------------------------------
# SignatureSet
# ---------------------------------------------------------------------------

class TestSignatureSet:
    @patch(MODULE_PATH)
    def test_create(self, MC):
        m = MC.return_value
        m.post.return_value = {"id": "ss1"}
        createSignatureSet(node=TEST_NODE, name="sigset")
        assert m.post.call_args[0][0] == "transparent-encryption/signaturesets"

    @patch(MODULE_PATH)
    def test_update(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateSignatureSet(node=TEST_NODE, id="ss1")
        assert m.patch.call_args[0][0] == "transparent-encryption/signaturesets/ss1"

    @patch(MODULE_PATH)
    def test_add_signature(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        addSignatureToSet(node=TEST_NODE, id="ss1")
        assert m.patch.call_args[0][0] == "transparent-encryption/signaturesets/ss1/addsignatures"

    @patch(MODULE_PATH)
    def test_get_by_filter(self, MC):
        m = MC.return_value
        m.get.return_value = {"resources": []}
        getSignatureFromSetByFilter(node=TEST_NODE, id="ss1", file_name="test.bin")
        assert "file_name=test.bin" in m.get.call_args[0][0]

    @patch(MODULE_PATH)
    def test_delete_by_id(self, MC):
        m = MC.return_value
        m.delete.return_value = {}
        deleteSignatureInSetById(node=TEST_NODE, id="ss1", signature_id="sig1")
        m.delete.assert_called_once_with("transparent-encryption/signaturesets/ss1/signatures/sig1")

    @patch(MODULE_PATH)
    def test_sign_app_request(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        sendSignAppRequest(node=TEST_NODE, id="ss1")
        assert m.post.call_args[0][0] == "transparent-encryption/signaturesets/ss1/signapp"

    @patch(MODULE_PATH)
    def test_query_sign_app(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        querySignAppRequest(node=TEST_NODE, id="ss1")
        assert m.post.call_args[0][0] == "transparent-encryption/signaturesets/ss1/querysignapp"

    @patch(MODULE_PATH)
    def test_cancel_sign_app(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        cancelSignAppRequest(node=TEST_NODE, id="ss1")
        assert m.post.call_args[0][0] == "transparent-encryption/signaturesets/ss1/cancelsignapp"


# ---------------------------------------------------------------------------
# CTE UserSet
# ---------------------------------------------------------------------------

class TestCTEUserSet:
    @patch(MODULE_PATH)
    def test_create(self, MC):
        m = MC.return_value
        m.post.return_value = {"id": "us1"}
        createUserSet(node=TEST_NODE, name="uset")
        assert m.post.call_args[0][0] == "transparent-encryption/usersets"

    @patch(MODULE_PATH)
    def test_update(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateUserSet(node=TEST_NODE, id="us1")
        assert m.patch.call_args[0][0] == "transparent-encryption/usersets/us1"

    @patch(MODULE_PATH)
    def test_add_user(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        addUserToSet(node=TEST_NODE, id="us1")
        assert m.patch.call_args[0][0] == "transparent-encryption/usersets/us1/addusers"

    @patch(MODULE_PATH)
    def test_update_by_index(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateUserInSetByIndex(node=TEST_NODE, id="us1", userIndex="0")
        assert m.patch.call_args[0][0] == "transparent-encryption/usersets/us1/updateuser/0"

    @patch(MODULE_PATH)
    def test_delete_by_index(self, MC):
        m = MC.return_value
        m.delete.return_value = {}
        deleteUserInSetByIndex(node=TEST_NODE, id="us1", userIndex="0,1")
        m.delete.assert_called_once_with("transparent-encryption/usersets/us1/delusers?userIndexList=0,1")


# ---------------------------------------------------------------------------
# CSI Storage Group
# ---------------------------------------------------------------------------

class TestCSIStorageGroup:
    @patch(MODULE_PATH)
    def test_create(self, MC):
        m = MC.return_value
        m.post.return_value = {"id": "csi1"}
        createCSIStorageGroup(node=TEST_NODE, name="csigrp")
        assert m.post.call_args[0][0] == "transparent-encryption/csigroups"

    @patch(MODULE_PATH)
    def test_update(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateCSIStorageGroup(node=TEST_NODE, id="csi1")
        assert m.patch.call_args[0][0] == "transparent-encryption/csigroups/csi1"

    @patch(MODULE_PATH)
    def test_add_client(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        csiGroupAddClient(node=TEST_NODE, id="csi1")
        assert m.post.call_args[0][0] == "transparent-encryption/csigroups/csi1/clients"

    @patch(MODULE_PATH)
    def test_remove_client(self, MC):
        m = MC.return_value
        m.delete.return_value = {}
        csiGroupRemoveClient(node=TEST_NODE, id="csi1", client_id="c1")
        m.delete.assert_called_once_with("transparent-encryption/csigroups/csi1/clients/c1")

    @patch(MODULE_PATH)
    def test_add_guard_point(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        csiGroupAddGuardPoint(node=TEST_NODE, id="csi1")
        assert m.post.call_args[0][0] == "transparent-encryption/csigroups/csi1/guardpoints"

    @patch(MODULE_PATH)
    def test_update_guard_point(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        csiGroupUpdateGuardPoint(node=TEST_NODE, gp_id="gp1")
        assert m.patch.call_args[0][0] == "transparent-encryption/csigroups/guardpoints/gp1"

    @patch(MODULE_PATH)
    def test_remove_guard_point(self, MC):
        m = MC.return_value
        m.delete.return_value = {}
        csiGroupRemoveGuardPoint(node=TEST_NODE, gp_id="gp1")
        m.delete.assert_called_once_with("transparent-encryption/csigroups/guardpoints/gp1")


# ---------------------------------------------------------------------------
# CTE Client Group
# ---------------------------------------------------------------------------

class TestClientGroup:
    @patch(MODULE_PATH)
    def test_create(self, MC):
        m = MC.return_value
        m.post.return_value = {"id": "cg1"}
        createClientGroup(node=TEST_NODE, name="grp1")
        assert m.post.call_args[0][0] == "transparent-encryption/clientgroups"

    @patch(MODULE_PATH)
    def test_update(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateClientGroup(node=TEST_NODE, id="cg1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clientgroups/cg1"

    @patch(MODULE_PATH)
    def test_add_clients(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        clientGroupAddClients(node=TEST_NODE, id="cg1")
        assert m.post.call_args[0][0] == "transparent-encryption/clientgroups/cg1/clients"

    @patch(MODULE_PATH)
    def test_add_guard_point(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        clientGroupAddGuardPoint(node=TEST_NODE, id="cg1")
        assert m.post.call_args[0][0] == "transparent-encryption/clientgroups/cg1/guardpoints"

    @patch(MODULE_PATH)
    def test_update_guard_point(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        clientGroupUpdateGuardPoint(node=TEST_NODE, id="cg1", guardpoint_id="gp1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clientgroups/cg1/guardpoints/gp1"

    @patch(MODULE_PATH)
    def test_unguard(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        clientGroupUnguardGuardPoint(node=TEST_NODE, id="cg1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clientgroups/cg1/guardpoints/unguard"

    @patch(MODULE_PATH)
    def test_auth_binaries(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        clientGroupAuthBinaries(node=TEST_NODE, id="cg1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clientgroups/cg1/auth-binaries"

    @patch(MODULE_PATH)
    def test_delete_client(self, MC):
        m = MC.return_value
        m.delete.return_value = {}
        clientGroupDeleteClient(node=TEST_NODE, id="cg1", client_id="c1")
        m.delete.assert_called_once_with("transparent-encryption/clientgroups/cg1/clients/c1")

    @patch(MODULE_PATH)
    def test_ldt_pause(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        clientGroupLDTPause(node=TEST_NODE, id="cg1")
        assert m.post.call_args[0][0] == "transparent-encryption/clientgroups/cg1/ldtpause"


# ---------------------------------------------------------------------------
# CTE Client
# ---------------------------------------------------------------------------

class TestCTEClient:
    @patch(MODULE_PATH)
    def test_create_client(self, MC):
        m = MC.return_value
        m.post.return_value = {"id": "cl1"}
        createClient(node=TEST_NODE, name="client1")
        assert m.post.call_args[0][0] == "transparent-encryption/clients"

    @patch(MODULE_PATH)
    def test_patch_client(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        patchClient(node=TEST_NODE, id="cl1", description="updated")
        assert m.patch.call_args[0][0] == "transparent-encryption/clients/cl1"

    @patch(MODULE_PATH)
    def test_add_guard_point(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        clientAddGuardPoint(node=TEST_NODE, id="cl1")
        assert m.post.call_args[0][0] == "transparent-encryption/clients/cl1/guardpoints"

    @patch(MODULE_PATH)
    def test_unenroll(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        unEnrollClient(node=TEST_NODE, client_id="cl1")
        assert m.post.call_args[0][0] == "transparent-encryption/unenroll"

    @patch(MODULE_PATH)
    def test_delete_clients(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        deleteClients(node=TEST_NODE, client_ids=["cl1", "cl2"])
        assert m.patch.call_args[0][0] == "transparent-encryption/clients/delete"

    @patch(MODULE_PATH)
    def test_delete_client_by_id(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        deleteClientById(node=TEST_NODE, id="cl1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clients/cl1/delete"

    @patch(MODULE_PATH)
    def test_update_auth_binaries(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateClientAuthBinaries(node=TEST_NODE, id="cl1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clients/cl1/auth-binaries"

    @patch(MODULE_PATH)
    def test_ldt_pause(self, MC):
        m = MC.return_value
        m.post.return_value = {}
        sendLDTPauseCmd(node=TEST_NODE, id="cl1")
        assert m.post.call_args[0][0] == "transparent-encryption/clients/cl1/ldtpause"

    @patch(MODULE_PATH)
    def test_patch_guard_point(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        patchGuardPointCTEClient(node=TEST_NODE, id="cl1", gp_id="gp1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clients/cl1/guardpoints/gp1"

    @patch(MODULE_PATH)
    def test_unguard_points(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        unGuardPoints(node=TEST_NODE, id="cl1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clients/cl1/guardpoints/unguard"

    @patch(MODULE_PATH)
    def test_update_gp_early_access(self, MC):
        m = MC.return_value
        m.patch.return_value = {}
        updateGPEarlyAccess(node=TEST_NODE, id="cl1", gp_id="gp1")
        assert m.patch.call_args[0][0] == "transparent-encryption/clients/cl1/guardpoints/gp1/early-access"
