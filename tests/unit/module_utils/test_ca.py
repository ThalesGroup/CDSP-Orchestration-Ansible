#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/ca.py"""

import json
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.ca import (
    createLocalCA,
    updateLocalCA,
    selfSign,
    issueCertificate,
    revokeCert,
    resumeCert,
    createCSR,
    createCSRAndKey,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.ca.CipherTrustClient"


class TestCreateLocalCA:
    @patch(MODULE_PATH)
    def test_posts_to_correct_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "ca-1", "uri": "ca/local-cas/ca-1"}

        result = createLocalCA(
            node=TEST_NODE, cn="Test CA", algorithm="RSA", size=2048
        )

        MockClient.assert_called_once_with(TEST_NODE)
        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "ca/local-cas"
        payload = json.loads(call_args[1]["data"])
        assert payload["cn"] == "Test CA"
        assert payload["algorithm"] == "RSA"
        assert payload["size"] == 2048
        assert "node" not in payload
        assert result == {"id": "ca-1", "uri": "ca/local-cas/ca-1"}


class TestUpdateLocalCA:
    @patch(MODULE_PATH)
    def test_patches_correct_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {"id": "ca-1", "cn": "Updated CA"}

        result = updateLocalCA(node=TEST_NODE, id="ca-1", cn="Updated CA")

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "ca/local-cas/ca-1"
        payload = json.loads(call_args[1]["data"])
        assert payload["cn"] == "Updated CA"
        assert "id" not in payload
        assert "node" not in payload


class TestSelfSign:
    @patch(MODULE_PATH)
    def test_posts_to_self_sign_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"cert": "PEM..."}

        result = selfSign(node=TEST_NODE, id="ca-1", duration=365)

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "ca/local-cas/ca-1/self-sign"
        payload = json.loads(call_args[1]["data"])
        assert payload["duration"] == 365
        assert "id" not in payload


class TestIssueCertificate:
    @patch(MODULE_PATH)
    def test_posts_to_certs_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"cert": "PEM...", "id": "cert-1"}

        result = issueCertificate(node=TEST_NODE, id="ca-1", csr="CSR_DATA")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "ca/local-cas/ca-1/certs"
        payload = json.loads(call_args[1]["data"])
        assert payload["csr"] == "CSR_DATA"
        assert "id" not in payload


class TestRevokeCert:
    @patch(MODULE_PATH)
    def test_posts_to_revoke_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"status": "revoked"}

        result = revokeCert(
            node=TEST_NODE, id="ca-1", cert_id="cert-1", reason="superseded"
        )

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "ca/local-cas/ca-1/certs/cert-1/revoke"
        payload = json.loads(call_args[1]["data"])
        assert payload["reason"] == "superseded"
        assert "id" not in payload
        assert "cert_id" not in payload


class TestResumeCert:
    @patch(MODULE_PATH)
    def test_posts_to_resume_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"status": "active"}

        result = resumeCert(node=TEST_NODE, id="ca-1", cert_id="cert-1")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "ca/local-cas/ca-1/certs/cert-1/resume"


class TestCreateCSR:
    @patch(MODULE_PATH)
    def test_posts_to_vault_csr(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"csr": "CSR_DATA"}

        result = createCSR(node=TEST_NODE, cn="test.example.com", algorithm="RSA")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "vault/csr"
        payload = json.loads(call_args[1]["data"])
        assert payload["cn"] == "test.example.com"


class TestCreateCSRAndKey:
    @patch(MODULE_PATH)
    def test_posts_to_ca_csr(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"csr": "CSR", "key_id": "k1"}

        result = createCSRAndKey(node=TEST_NODE, cn="example.com")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "ca/csr"
        payload = json.loads(call_args[1]["data"])
        assert payload["cn"] == "example.com"
