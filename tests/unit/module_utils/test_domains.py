#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/domains.py"""

import json
import pytest
from unittest.mock import patch, MagicMock

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.domains import (
    create,
    patch as domain_patch,
    enableSyslogRedirection,
    disableSyslogRedirection,
    disableInterface,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.domains.CipherTrustClient"


class TestCreate:
    @patch(MODULE_PATH)
    def test_posts_to_domains_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "dom-1", "name": "TestDomain"}

        result = create(
            node=TEST_NODE, name="TestDomain", admins=["admin|user1"]
        )

        MockClient.assert_called_once_with(TEST_NODE)
        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "domains"
        payload = json.loads(call_args[1]["data"])
        assert payload["name"] == "TestDomain"
        assert payload["admins"] == ["admin|user1"]
        assert "node" not in payload
        assert result == {"id": "dom-1", "name": "TestDomain"}

    @patch(MODULE_PATH)
    def test_none_values_filtered(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {}

        create(node=TEST_NODE, name="Test", admins=None)

        payload = json.loads(mock_instance.post.call_args[1]["data"])
        assert payload == {"name": "Test"}


class TestPatch:
    @patch(MODULE_PATH)
    def test_patches_correct_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.patch.return_value = {"id": "dom-1", "name": "Updated"}

        result = domain_patch(
            node=TEST_NODE, domain_id="dom-1", connection_id="conn-1"
        )

        call_args = mock_instance.patch.call_args
        assert call_args[0][0] == "domains/dom-1"
        payload = json.loads(call_args[1]["data"])
        assert payload["connection_id"] == "conn-1"
        assert "node" not in payload
        assert "domain_id" not in payload


class TestEnableSyslogRedirection:
    @patch(MODULE_PATH)
    def test_posts_to_enable_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"status": "enabled"}

        result = enableSyslogRedirection(node=TEST_NODE)

        MockClient.assert_called_once_with(TEST_NODE)
        mock_instance.post.assert_called_once_with("domain-syslog-redirection/enable")


class TestDisableSyslogRedirection:
    @patch(MODULE_PATH)
    def test_posts_to_disable_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"status": "disabled"}

        result = disableSyslogRedirection(node=TEST_NODE)

        mock_instance.post.assert_called_once_with("domain-syslog-redirection/disable")


class TestDisableInterfaceAlias:
    def test_alias_points_to_disable_syslog_redirection(self):
        """disableInterface should be the same function as disableSyslogRedirection."""
        assert disableInterface is disableSyslogRedirection
