#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/dpg.py"""

import json
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg import (
    _exclude,
    createAccessPolicy,
    updateAccessPolicy,
    accessPolicyAddUserSet,
    accessPolicyUpdateUserSet,
    accessPolicyDeleteUserSet,
    createProtectionPolicy,
    updateProtectionPolicy,
    createUserSet,
    updateUserSet,
    createCharacterSet,
    updateCharacterSet,
    createMaskingFormat,
    updateMaskingFormat,
    createClientProfile,
    updateClientProfile,
    createDPGPolicy,
    updateDPGPolicy,
    dpgPolicyAddAPIUrl,
    dpgPolicyUpdateAPIUrl,
    dpgPolicyDeleteAPIUrl,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.dpg.CipherTrustClient"


class TestExclude:
    def test_excludes_keys(self):
        data = {"a": 1, "b": 2, "c": 3}
        assert _exclude(data, "a", "c") == {"b": 2}

    def test_excludes_nothing(self):
        data = {"a": 1, "b": 2}
        assert _exclude(data) == {"a": 1, "b": 2}


class TestAccessPolicy:
    @patch(MODULE_PATH)
    def test_create(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {"id": "ap-1"}

        result = createAccessPolicy(node=TEST_NODE, name="policy1")

        assert mock.post.call_args[0][0] == "data-protection/access-policies"
        payload = json.loads(mock.post.call_args[1]["data"])
        assert payload["name"] == "policy1"
        assert "node" not in payload

    @patch(MODULE_PATH)
    def test_update(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        updateAccessPolicy(node=TEST_NODE, policy_id="ap-1", name="updated")

        assert mock.patch.call_args[0][0] == "data-protection/access-policies/ap-1"
        payload = json.loads(mock.patch.call_args[1]["data"])
        assert payload["name"] == "updated"
        assert "policy_id" not in payload

    @patch(MODULE_PATH)
    def test_add_user_set(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {}

        accessPolicyAddUserSet(node=TEST_NODE, policy_id="ap-1", user_set_id="us-1")

        assert mock.post.call_args[0][0] == "data-protection/access-policies/ap-1/user-set"

    @patch(MODULE_PATH)
    def test_update_user_set(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        accessPolicyUpdateUserSet(
            node=TEST_NODE, policy_id="ap-1", policy_user_set_id="pus-1", name="new"
        )

        assert mock.patch.call_args[0][0] == "data-protection/access-policies/ap-1/user-set/pus-1"

    @patch(MODULE_PATH)
    def test_delete_user_set(self, MockClient):
        mock = MockClient.return_value
        mock.delete.return_value = {}

        accessPolicyDeleteUserSet(
            node=TEST_NODE, policy_id="ap-1", policy_user_set_id="pus-1"
        )

        mock.delete.assert_called_once_with(
            "data-protection/access-policies/ap-1/user-set/pus-1"
        )


class TestProtectionPolicy:
    @patch(MODULE_PATH)
    def test_create(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {"id": "pp-1"}

        createProtectionPolicy(node=TEST_NODE, name="FPE_Policy")

        assert mock.post.call_args[0][0] == "data-protection/protection-policies"

    @patch(MODULE_PATH)
    def test_update(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        updateProtectionPolicy(node=TEST_NODE, policy_name="FPE_Policy", key="newkey")

        assert mock.patch.call_args[0][0] == "data-protection/protection-policies/FPE_Policy"
        payload = json.loads(mock.patch.call_args[1]["data"])
        assert "policy_name" not in payload


class TestDPGUserSet:
    @patch(MODULE_PATH)
    def test_create(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {"id": "us-1"}

        createUserSet(node=TEST_NODE, name="set1")

        assert mock.post.call_args[0][0] == "data-protection/user-sets"

    @patch(MODULE_PATH)
    def test_update(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        updateUserSet(node=TEST_NODE, user_set_id="us-1", name="updated")

        assert mock.patch.call_args[0][0] == "data-protection/user-sets/us-1"


class TestCharacterSet:
    @patch(MODULE_PATH)
    def test_create(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {"id": "cs-1"}

        createCharacterSet(node=TEST_NODE, name="alpha_set")

        assert mock.post.call_args[0][0] == "data-protection/character-sets"

    @patch(MODULE_PATH)
    def test_update(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        updateCharacterSet(node=TEST_NODE, char_set_id="cs-1", name="updated")

        assert mock.patch.call_args[0][0] == "data-protection/character-sets/cs-1"


class TestMaskingFormat:
    @patch(MODULE_PATH)
    def test_create(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {"id": "mf-1"}

        createMaskingFormat(node=TEST_NODE, name="SSN_mask")

        assert mock.post.call_args[0][0] == "data-protection/masking-formats"

    @patch(MODULE_PATH)
    def test_update(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        updateMaskingFormat(node=TEST_NODE, masking_format_id="mf-1", name="new")

        assert mock.patch.call_args[0][0] == "data-protection/masking-formats/mf-1"


class TestClientProfile:
    @patch(MODULE_PATH)
    def test_create(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {"id": "cp-1"}

        createClientProfile(node=TEST_NODE, name="profile1")

        assert mock.post.call_args[0][0] == "data-protection/client-profiles"

    @patch(MODULE_PATH)
    def test_update(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        updateClientProfile(node=TEST_NODE, profile_id="cp-1", name="updated")

        assert mock.patch.call_args[0][0] == "data-protection/client-profiles/cp-1"


class TestDPGPolicy:
    @patch(MODULE_PATH)
    def test_create(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {"id": "dpg-1"}

        createDPGPolicy(node=TEST_NODE, name="MyDPG")

        assert mock.post.call_args[0][0] == "data-protection/dpg-policies"

    @patch(MODULE_PATH)
    def test_update(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        updateDPGPolicy(node=TEST_NODE, policy_id="dpg-1", description="updated")

        assert mock.patch.call_args[0][0] == "data-protection/dpg-policies/dpg-1"

    @patch(MODULE_PATH)
    def test_add_api_url(self, MockClient):
        mock = MockClient.return_value
        mock.post.return_value = {}

        dpgPolicyAddAPIUrl(
            node=TEST_NODE, policy_id="dpg-1", url="/api/v1/data"
        )

        assert mock.post.call_args[0][0] == "data-protection/dpg-policies/dpg-1/api-urls"

    @patch(MODULE_PATH)
    def test_update_api_url(self, MockClient):
        mock = MockClient.return_value
        mock.patch.return_value = {}

        dpgPolicyUpdateAPIUrl(
            node=TEST_NODE, policy_id="dpg-1", api_url_id="url-1", url="/updated"
        )

        assert mock.patch.call_args[0][0] == "data-protection/dpg-policies/dpg-1/api-urls/url-1"

    @patch(MODULE_PATH)
    def test_delete_api_url(self, MockClient):
        mock = MockClient.return_value
        mock.delete.return_value = {}

        dpgPolicyDeleteAPIUrl(
            node=TEST_NODE, policy_id="dpg-1", api_url_id="url-1"
        )

        mock.delete.assert_called_once_with(
            "data-protection/dpg-policies/dpg-1/api-urls/url-1"
        )
