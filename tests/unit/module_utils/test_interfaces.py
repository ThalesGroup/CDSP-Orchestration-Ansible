#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/interfaces.py"""

import json
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.interfaces import (
    _iface_url,
    create,
    patch as iface_patch,
    addCertificateToInterface,
    getCertificateFromInterface,
    enableInterface,
    disableInterface,
    restoreDefaultTlsCiphers,
    createCsr,
    autogenServerCert,
    useCertificate,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.interfaces.CipherTrustClient"


class TestIfaceUrl:
    def test_basic(self):
        assert _iface_url("iface-1") == "configs/interfaces/iface-1"

    def test_with_suffix(self):
        assert _iface_url("iface-1", "/certificate") == "configs/interfaces/iface-1/certificate"

    def test_empty_suffix(self):
        assert _iface_url("iface-1", "") == "configs/interfaces/iface-1"


class TestCreate:
    @patch(MODULE_PATH)
    def test_posts_to_interfaces(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "iface-1"}

        result = create(node=TEST_NODE, port=9005, mode="tls-cert-and-pw-optional")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "configs/interfaces"
        payload = json.loads(call_args[1]["data"])
        assert payload["port"] == 9005
        assert payload["mode"] == "tls-cert-and-pw-optional"
        assert "node" not in payload


class TestPatch:
    @patch(MODULE_PATH)
    def test_patches_interface(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {}

        iface_patch(node=TEST_NODE, interface_id="iface-1", port=9006)

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "configs/interfaces/iface-1"
        payload = json.loads(call_args[1]["data"])
        assert payload["port"] == 9006
        assert "interface_id" not in payload


class TestAddCertificateToInterface:
    @patch(MODULE_PATH)
    def test_puts_certificate(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.put.return_value = {}

        addCertificateToInterface(
            node=TEST_NODE, interface_id="iface-1", certificate="CERT_DATA"
        )

        call_args = mock_instance.put.call_args
        assert call_args[0][0] == "configs/interfaces/iface-1/certificate"
        payload = json.loads(call_args[1]["data"])
        assert payload["certificate"] == "CERT_DATA"
        assert "interface_id" not in payload


class TestGetCertificateFromInterface:
    @patch(MODULE_PATH)
    def test_gets_certificate(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.get.return_value = {"cert": "PEM_DATA"}

        result = getCertificateFromInterface(node=TEST_NODE, interface_id="iface-1")

        mock_instance.get.assert_called_once_with(
            "configs/interfaces/iface-1/certificate"
        )
        assert result == {"cert": "PEM_DATA"}


class TestEnableInterface:
    @patch(MODULE_PATH)
    def test_posts_to_enable(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        enableInterface(node=TEST_NODE, interface_id="iface-1")

        mock_instance.post.assert_called_once_with(
            "configs/interfaces/iface-1/enable"
        )


class TestDisableInterface:
    @patch(MODULE_PATH)
    def test_posts_to_disable(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        disableInterface(node=TEST_NODE, interface_id="iface-1")

        mock_instance.post.assert_called_once_with(
            "configs/interfaces/iface-1/disable"
        )


class TestRestoreDefaultTlsCiphers:
    @patch(MODULE_PATH)
    def test_posts_to_restore(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        restoreDefaultTlsCiphers(node=TEST_NODE, interface_id="iface-1")

        mock_instance.post.assert_called_once_with(
            "configs/interfaces/iface-1/restore-default-tls-ciphers"
        )


class TestCreateCsr:
    @patch(MODULE_PATH)
    def test_posts_csr_request(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"csr": "CSR_DATA"}

        result = createCsr(node=TEST_NODE, interface_id="iface-1", cn="test.com")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "configs/interfaces/iface-1/csr"
        payload = json.loads(call_args[1]["data"])
        assert payload["cn"] == "test.com"
        assert "interface_id" not in payload


class TestAutogenServerCert:
    @patch(MODULE_PATH)
    def test_posts_to_autogen(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        autogenServerCert(node=TEST_NODE, interface_id="iface-1")

        mock_instance.post.assert_called_once_with(
            "configs/interfaces/iface-1/auto-gen-server-cert"
        )


class TestUseCertificate:
    @patch(MODULE_PATH)
    def test_posts_use_certificate(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        useCertificate(
            node=TEST_NODE, interface_id="iface-1", cert_id="cert-1"
        )

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "configs/interfaces/iface-1/use-certificate"
        payload = json.loads(call_args[1]["data"])
        assert payload["cert_id"] == "cert-1"
