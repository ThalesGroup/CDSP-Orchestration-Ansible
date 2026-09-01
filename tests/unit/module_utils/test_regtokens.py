#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/regtokens.py"""

import json
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.regtokens import (
    create,
    patch as regtokens_patch,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.regtokens.CipherTrustClient"


class TestCreate:
    @patch(MODULE_PATH)
    def test_posts_to_regtokens_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "tok-1", "token": "REGTOKEN"}

        result = create(
            node=TEST_NODE, ca_id="ca-1", lifetime="24h"
        )

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "client-management/regtokens"
        payload = json.loads(call_args[1]["data"])
        assert payload["ca_id"] == "ca-1"
        assert payload["lifetime"] == "24h"
        assert "node" not in payload

    @patch(MODULE_PATH)
    def test_none_values_excluded(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        create(node=TEST_NODE, ca_id="ca-1", lifetime=None)

        payload = json.loads(mock_instance.post.call_args[1]["data"])
        assert "lifetime" not in payload


class TestPatch:
    @patch(MODULE_PATH)
    def test_patches_regtoken_by_id(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {"id": "tok-1"}

        result = regtokens_patch(
            node=TEST_NODE, id="tok-1", lifetime="48h"
        )

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "client-management/regtokens/tok-1"
        payload = json.loads(call_args[1]["data"])
        assert payload["lifetime"] == "48h"
        assert "id" not in payload
        assert "node" not in payload
