#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/connection_management.py"""

import json
import pytest
from unittest.mock import patch, MagicMock

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connection_management import (
    CONNECTION_ENDPOINTS,
    createConnection,
    patchConnection,
    addHadoopNode,
    updateHadoopNode,
    deleteHadoopNode,
    addLunaPartition,
    deleteLunaPartition,
    addLunaSTCPartition,
    addHSMServer,
    enableSTC,
    disableSTC,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.connection_management.CipherTrustClient"


class TestConnectionEndpoints:
    def test_all_connection_types_mapped(self):
        expected_types = [
            "aws", "azure", "elasticsearch", "google", "hadoop",
            "ldap", "oidc", "oracle", "scp", "smb", "salesforce",
            "syslog", "luna_nw_hsm",
        ]
        for conn_type in expected_types:
            assert conn_type in CONNECTION_ENDPOINTS

    def test_aws_endpoint(self):
        assert CONNECTION_ENDPOINTS["aws"] == "connectionmgmt/services/aws/connections"


class TestCreateConnection:
    @patch(MODULE_PATH)
    def test_creates_aws_connection(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "conn-1"}

        result = createConnection(
            node=TEST_NODE, connection_type="aws", name="MyAWS", access_key="AK"
        )

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "connectionmgmt/services/aws/connections"
        payload = json.loads(call_args[1]["data"])
        assert payload["name"] == "MyAWS"
        assert payload["access_key"] == "AK"
        assert "connection_type" not in payload
        assert "node" not in payload

    @patch(MODULE_PATH)
    def test_creates_azure_connection(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        createConnection(node=TEST_NODE, connection_type="azure", name="MyAzure")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "connectionmgmt/services/azure/connections"


class TestPatchConnection:
    @patch(MODULE_PATH)
    def test_patches_connection(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {}

        patchConnection(
            node=TEST_NODE,
            connection_type="aws",
            connection_id="conn-1",
            name="UpdatedName",
        )

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "connectionmgmt/services/aws/connections/conn-1"
        payload = json.loads(call_args[1]["data"])
        assert payload["name"] == "UpdatedName"
        assert "connection_type" not in payload
        assert "connection_id" not in payload


class TestAddHadoopNode:
    @patch(MODULE_PATH)
    def test_adds_hadoop_node(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        addHadoopNode(
            node=TEST_NODE, connection_id="conn-1", hostname="hadoop1.local"
        )

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "connectionmgmt/services/hadoop/connections/conn-1/nodes"
        payload = json.loads(call_args[1]["data"])
        assert payload["hostname"] == "hadoop1.local"
        assert "connection_id" not in payload


class TestUpdateHadoopNode:
    @patch(MODULE_PATH)
    def test_updates_hadoop_node(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {}

        updateHadoopNode(
            node=TEST_NODE,
            connection_id="conn-1",
            node_id="node-1",
            hostname="hadoop2.local",
        )

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "connectionmgmt/services/hadoop/connections/conn-1/nodes/node-1"
        payload = json.loads(call_args[1]["data"])
        assert payload["hostname"] == "hadoop2.local"
        assert "connection_id" not in payload
        assert "node_id" not in payload


class TestDeleteHadoopNode:
    @patch(MODULE_PATH)
    def test_deletes_hadoop_node(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.delete.return_value = {}

        deleteHadoopNode(
            node=TEST_NODE, connection_id="conn-1", node_id="node-1"
        )

        mock_instance.delete.assert_called_once_with(
            "connectionmgmt/services/hadoop/connections/conn-1/nodes/node-1"
        )


class TestAddLunaPartition:
    @patch(MODULE_PATH)
    def test_adds_partition(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        addLunaPartition(
            node=TEST_NODE, connection_id="conn-1", serial="SN123"
        )

        call_args = mock_instance.post.call_args
        expected = "connectionmgmt/services/luna-network/connections/conn-1/partitions"
        assert call_args[0][0] == expected


class TestDeleteLunaPartition:
    @patch(MODULE_PATH)
    def test_deletes_partition(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.delete.return_value = {}

        deleteLunaPartition(
            node=TEST_NODE, connection_id="conn-1", partition_id="part-1"
        )

        mock_instance.delete.assert_called_once_with(
            "connectionmgmt/services/luna-network/connections/conn-1/partitions/part-1"
        )


class TestAddLunaSTCPartition:
    @patch(MODULE_PATH)
    def test_posts_stc_partition(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        addLunaSTCPartition(node=TEST_NODE, serial="SN456")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "connectionmgmt/services/luna-network/stc-partition"


class TestAddHSMServer:
    @patch(MODULE_PATH)
    def test_posts_hsm_server(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        addHSMServer(node=TEST_NODE, hostname="hsm.local")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "connectionmgmt/services/luna-network/servers"


class TestEnableSTC:
    @patch(MODULE_PATH)
    def test_enables_stc(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        enableSTC(node=TEST_NODE, connection_id="conn-1")

        mock_instance.post.assert_called_once_with(
            "connectionmgmt/services/luna-network/servers/conn-1/enable-stc"
        )


class TestDisableSTC:
    @patch(MODULE_PATH)
    def test_disables_stc(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        disableSTC(node=TEST_NODE, connection_id="conn-1")

        mock_instance.post.assert_called_once_with(
            "connectionmgmt/services/luna-network/servers/conn-1/disable-stc"
        )
