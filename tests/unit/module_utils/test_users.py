#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/users.py"""

import json
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.users import (
    create,
    patch as users_patch,
    changepw,
    patch_self,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.users.CipherTrustClient"


class TestCreate:
    @patch(MODULE_PATH)
    def test_posts_to_users_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"user_id": "u1", "username": "newuser"}

        result = create(
            node=TEST_NODE,
            username="newuser",
            password="secret",
            email="user@test.com",
        )

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "usermgmt/users"
        payload = json.loads(call_args[1]["data"])
        assert payload["username"] == "newuser"
        assert payload["password"] == "secret"
        assert payload["email"] == "user@test.com"
        assert "node" not in payload

    @patch(MODULE_PATH)
    def test_none_fields_excluded(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        create(node=TEST_NODE, username="u1", email=None)

        payload = json.loads(mock_instance.post.call_args[1]["data"])
        assert "email" not in payload


class TestPatch:
    @patch(MODULE_PATH)
    def test_patches_user_by_id(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {"user_id": "u1", "email": "new@test.com"}

        result = users_patch(
            node=TEST_NODE, cm_user_id="u1", email="new@test.com"
        )

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "usermgmt/users/u1"
        payload = json.loads(call_args[1]["data"])
        assert payload["email"] == "new@test.com"
        assert "cm_user_id" not in payload
        assert "node" not in payload


class TestChangePW:
    @patch(MODULE_PATH)
    def test_patches_auth_changepw(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {}

        changepw(node=TEST_NODE, password="old", new_password="new")

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "auth/changepw"
        payload = json.loads(call_args[1]["data"])
        assert payload["password"] == "old"
        assert payload["new_password"] == "new"
        assert "node" not in payload


class TestPatchSelf:
    @patch(MODULE_PATH)
    def test_patches_auth_self_user(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {}

        patch_self(node=TEST_NODE, email="me@test.com")

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "auth/self/user"
        payload = json.loads(call_args[1]["data"])
        assert payload["email"] == "me@test.com"
        assert "node" not in payload
