#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/groups.py"""

import json
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.groups import (
    create,
    patch as groups_patch,
    addUserToGroup,
    addClientToGroup,
    deleteUserFromGroup,
    deleteClientFromGroup,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.groups.CipherTrustClient"


class TestCreate:
    @patch(MODULE_PATH)
    def test_posts_to_groups_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"name": "Admins"}

        result = create(node=TEST_NODE, name="Admins")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "usermgmt/groups"
        payload = json.loads(call_args[1]["data"])
        assert payload["name"] == "Admins"
        assert "node" not in payload

    @patch(MODULE_PATH)
    def test_with_metadata(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        create(node=TEST_NODE, name="G1", app_metadata={"key": "val"})

        payload = json.loads(mock_instance.post.call_args[1]["data"])
        assert payload["app_metadata"] == {"key": "val"}


class TestPatch:
    @patch(MODULE_PATH)
    def test_patches_by_old_name(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {"name": "NewName"}

        result = groups_patch(node=TEST_NODE, old_name="OldName", name="NewName")

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "usermgmt/groups/OldName"
        payload = json.loads(call_args[1]["data"])
        assert payload["name"] == "NewName"
        assert "old_name" not in payload
        assert "node" not in payload


class TestAddUserToGroup:
    @patch(MODULE_PATH)
    def test_posts_user_to_group(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        addUserToGroup(node=TEST_NODE, name="Admins", object_id="user-123")

        mock_instance.post.assert_called_once_with(
            "usermgmt/groups/Admins/users/user-123"
        )


class TestAddClientToGroup:
    @patch(MODULE_PATH)
    def test_posts_client_to_group(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        addClientToGroup(node=TEST_NODE, name="Admins", object_id="client-456")

        mock_instance.post.assert_called_once_with(
            "client-management/groups/Admins/clients/client-456"
        )


class TestDeleteUserFromGroup:
    @patch(MODULE_PATH)
    def test_deletes_user_from_group(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.delete.return_value = {}

        deleteUserFromGroup(node=TEST_NODE, name="Admins", object_id="user-123")

        mock_instance.delete.assert_called_once_with(
            "usermgmt/groups/Admins/users/user-123"
        )


class TestDeleteClientFromGroup:
    @patch(MODULE_PATH)
    def test_deletes_client_from_group(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.delete.return_value = {}

        deleteClientFromGroup(node=TEST_NODE, name="Admins", object_id="client-456")

        mock_instance.delete.assert_called_once_with(
            "client-management/groups/Admins/clients/client-456"
        )
