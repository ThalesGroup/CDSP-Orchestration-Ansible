#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/keys2.py"""

import json
import pytest
from unittest.mock import patch, MagicMock

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.keys2 import (
    _key_op_url,
    create,
    patch as keys2_patch,
    version_create,
    destroy,
    archive,
    recover,
    revoke,
    reactivate,
    export,
    clone,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.keys2.CipherTrustClient"


# ---------------------------------------------------------------------------
# _key_op_url
# ---------------------------------------------------------------------------

class TestKeyOpUrl:
    def test_basic(self):
        url = _key_op_url("key-1", "destroy")
        assert url == "vault/keys2/key-1/destroy"

    def test_with_version(self):
        url = _key_op_url("key-1", "archive", key_version=2)
        assert "version=2" in url

    def test_with_id_type(self):
        url = _key_op_url("key-1", "recover", id_type="name")
        assert "type=name" in url

    def test_with_include_material(self):
        url = _key_op_url("key-1", "clone", includeMaterial=True)
        assert "includeMaterial=True" in url

    def test_multiple_params(self):
        url = _key_op_url("key-1", "export", key_version=3, id_type="id")
        assert "?" in url
        assert "version=3" in url
        assert "type=id" in url

    def test_no_params(self):
        url = _key_op_url("key-1", "destroy")
        assert "?" not in url


# ---------------------------------------------------------------------------
# CRUD Operations
# ---------------------------------------------------------------------------

class TestCreate:
    @patch(MODULE_PATH)
    def test_posts_to_vault_keys2(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "k1", "name": "MyKey"}

        result = create(
            node=TEST_NODE, name="MyKey", algorithm="AES", size=256
        )

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "vault/keys2"
        payload = json.loads(call_args[1]["data"])
        assert payload["name"] == "MyKey"
        assert payload["algorithm"] == "AES"
        assert payload["size"] == 256
        assert "node" not in payload


class TestPatch:
    @patch(MODULE_PATH)
    def test_patches_key_by_id(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {"id": "k1", "name": "Renamed"}

        result = keys2_patch(
            node=TEST_NODE, cm_key_id="k1", name="Renamed"
        )

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "vault/keys2/k1"
        payload = json.loads(call_args[1]["data"])
        assert payload["name"] == "Renamed"
        assert "cm_key_id" not in payload
        assert "node" not in payload


class TestVersionCreate:
    @patch(MODULE_PATH)
    def test_posts_to_versions_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "k1", "version": 2}

        result = version_create(node=TEST_NODE, cm_key_id="k1")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "vault/keys2/k1/versions"


# ---------------------------------------------------------------------------
# Key Lifecycle Operations
# ---------------------------------------------------------------------------

class TestDestroy:
    @patch(MODULE_PATH)
    def test_posts_to_destroy_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        destroy(node=TEST_NODE, cm_key_id="k1")

        assert "destroy" in mock_instance.post.call_args[0][0]

    @patch(MODULE_PATH)
    def test_with_version(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        destroy(node=TEST_NODE, cm_key_id="k1", key_version=3)

        url = mock_instance.post.call_args[0][0]
        assert "version=3" in url


class TestArchive:
    @patch(MODULE_PATH)
    def test_posts_to_archive_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        archive(node=TEST_NODE, cm_key_id="k1")

        assert "archive" in mock_instance.post.call_args[0][0]


class TestRecover:
    @patch(MODULE_PATH)
    def test_posts_to_recover_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        recover(node=TEST_NODE, cm_key_id="k1")

        assert "recover" in mock_instance.post.call_args[0][0]


class TestRevoke:
    @patch(MODULE_PATH)
    def test_posts_to_revoke_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        revoke(node=TEST_NODE, cm_key_id="k1", messageStr="compromised")

        url = mock_instance.post.call_args[0][0]
        assert "revoke" in url


class TestReactivate:
    @patch(MODULE_PATH)
    def test_posts_to_reactivate_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        reactivate(node=TEST_NODE, cm_key_id="k1", messageStr="restored")

        url = mock_instance.post.call_args[0][0]
        assert "reactivate" in url


class TestExport:
    @patch(MODULE_PATH)
    def test_posts_to_export_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"material": "KEY_MATERIAL"}

        result = export(
            node=TEST_NODE, cm_key_id="k1", keyFormat="pkcs8"
        )

        url = mock_instance.post.call_args[0][0]
        assert "export" in url


class TestClone:
    @patch(MODULE_PATH)
    def test_posts_to_clone_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "k2"}

        result = clone(
            node=TEST_NODE,
            cm_key_id="k1",
            includeMaterial=True,
        )

        url = mock_instance.post.call_args[0][0]
        assert "clone" in url
        assert "includeMaterial=True" in url
