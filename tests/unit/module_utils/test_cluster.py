#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/cluster.py"""

import json
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cluster import (
    new,
    csr,
    sign,
    join,
)

TEST_NODE = {
    "server_ip": "10.0.0.1",
    "server_private_ip": "192.168.1.1",
    "server_port": 5432,
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MASTER_NODE = {
    "server_ip": "10.0.0.100",
    "server_private_ip": "192.168.1.100",
    "server_port": 5432,
    "user": "admin",
    "password": "master123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cluster.CipherTrustClient"


class TestNew:
    @patch(MODULE_PATH)
    def test_creates_cluster(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        result = new(node=TEST_NODE)

        MockClient.assert_called_once_with(TEST_NODE)
        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "cluster/new"
        payload = json.loads(call_args[1]["data"])
        assert payload["localNodeHost"] == "192.168.1.1"
        assert payload["localNodePort"] == 5432
        assert payload["publicAddress"] == "10.0.0.1"
        assert result == "Cluster creation initiated successfully!"


class TestCSR:
    @patch(MODULE_PATH)
    def test_generates_csr(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"csr": "CSR_DATA"}

        result = csr(node=TEST_NODE, master=MASTER_NODE)

        MockClient.assert_called_once_with(TEST_NODE)
        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "cluster/csr"
        payload = json.loads(call_args[1]["data"])
        assert payload["localNodeHost"] == "192.168.1.1"
        assert payload["publicAddress"] == "10.0.0.100"
        assert result == "CSR_DATA"

    @patch(MODULE_PATH)
    def test_csr_returns_full_response_if_no_csr_key(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"data": "something_else"}

        result = csr(node=TEST_NODE, master=MASTER_NODE)
        assert result == {"data": "something_else"}


class TestSign:
    @patch(MODULE_PATH)
    def test_signs_csr(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"cert": "CERT_DATA", "cachain": "CHAIN"}

        result = sign(
            node=TEST_NODE, master=MASTER_NODE, csr="CSR_DATA"
        )

        # Sign uses the master node
        MockClient.assert_called_once_with(MASTER_NODE)
        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "nodes"
        payload = json.loads(call_args[1]["data"])
        assert payload["csr"] == "CSR_DATA"
        assert payload["newNodeHost"] == "192.168.1.1"
        assert payload["shared_hsm_partition"] is False


class TestJoin:
    @patch(MODULE_PATH)
    def test_joins_cluster(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"status": "joining"}

        result = join(
            node=TEST_NODE,
            master=MASTER_NODE,
            cert="CERT_DATA",
            caChain="CA_CHAIN",
            mkek_blob="MKEK_BLOB",
        )

        # Join uses the node (not master)
        MockClient.assert_called_once_with(TEST_NODE)
        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "cluster/join"
        payload = json.loads(call_args[1]["data"])
        assert payload["cert"] == "CERT_DATA"
        assert payload["cachain"] == "CA_CHAIN"
        assert payload["mkek_blob"] == "MKEK_BLOB"
        assert payload["localNodeHost"] == "192.168.1.1"
        assert payload["memberNodeHost"] == "192.168.1.100"
        assert payload["blocking"] is False
