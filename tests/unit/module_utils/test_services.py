#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/services.py"""

import json
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.services import (
    restartCMServices,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}


class TestRestartCMServices:
    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.services.CipherTrustClient"
    )
    def test_restart_with_services_and_delay(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"status": "restarting"}

        result = restartCMServices(
            node=TEST_NODE, delay=5, services=["nae-kmip", "web"]
        )

        MockClient.assert_called_once_with(TEST_NODE)
        mock_instance.post.assert_called_once()

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "system/services/restart"

        # Verify payload contains delay and services
        payload = json.loads(call_args[1]["data"])
        assert payload["delay"] == 5
        assert payload["services"] == ["nae-kmip", "web"]
        assert result == {"status": "restarting"}

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.services.CipherTrustClient"
    )
    def test_restart_filters_node_from_payload(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        restartCMServices(node=TEST_NODE, delay=10)

        payload = json.loads(mock_instance.post.call_args[1]["data"])
        assert "node" not in payload
        assert payload["delay"] == 10

    @patch(
        "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.services.CipherTrustClient"
    )
    def test_restart_none_values_filtered(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        restartCMServices(node=TEST_NODE, delay=5, services=None)

        payload = json.loads(mock_instance.post.call_args[1]["data"])
        assert "services" not in payload
