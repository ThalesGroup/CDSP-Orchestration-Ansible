#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/licensing.py"""

import json
import pytest
from unittest.mock import patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.licensing import (
    getLockdata,
    getTrialLicenseId,
    addLicense,
    activateTrial,
    deactivateTrial,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)

TEST_NODE = {
    "server_ip": "test.example.com",
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}

MODULE_PATH = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.licensing.CipherTrustClient"


class TestGetLockdata:
    @patch(MODULE_PATH)
    def test_returns_data_on_success(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.get.return_value = {"lockCode": "ABC123"}

        result = getLockdata(TEST_NODE)

        mock_instance.get.assert_called_once_with("licensing/lockdata")
        assert result == {"data": {"lockCode": "ABC123"}}

    @patch(MODULE_PATH)
    def test_propagates_api_error(self, MockClient):
        """A failed lookup must not be reported to Ansible as success."""
        mock_instance = MockClient.return_value
        mock_instance.get.side_effect = CMApiException(
            message="Forbidden", api_error_code=403
        )

        with pytest.raises(CMApiException):
            getLockdata(TEST_NODE)


class TestGetTrialLicenseId:
    @patch(MODULE_PATH)
    def test_returns_first_trial_id(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.get.return_value = {
            "resources": [
                {"id": "trial-1", "status": "active"},
                {"id": "trial-2", "status": "expired"},
            ]
        }

        result = getTrialLicenseId(node=TEST_NODE)

        mock_instance.get.assert_called_once_with("licensing/trials")
        assert result == {"id": "trial-1", "status": "active"}


class TestAddLicense:
    @patch(MODULE_PATH)
    def test_posts_license(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"id": "lic-1"}

        result = addLicense(node=TEST_NODE, license="LICENSE_STRING")

        call_args = mock_instance.post.call_args
        assert call_args[0][0] == "licensing/licenses"
        payload = json.loads(call_args[1]["data"])
        assert payload["license"] == "LICENSE_STRING"
        assert "node" not in payload


class TestActivateTrial:
    @patch(MODULE_PATH)
    def test_posts_to_activate_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"status": "activated"}

        result = activateTrial(node=TEST_NODE, trialId="trial-1")

        mock_instance.post.assert_called_once_with(
            "licensing/trials/trial-1/activate"
        )


class TestDeactivateTrial:
    @patch(MODULE_PATH)
    def test_posts_to_deactivate_endpoint(self, MockClient):
        mock_instance = MockClient.return_value
        mock_instance.post.return_value = {"status": "deactivated"}

        result = deactivateTrial(node=TEST_NODE, trialId="trial-1")

        mock_instance.post.assert_called_once_with(
            "licensing/trials/trial-1/deactivate"
        )


class TestTrialLookupIsDefensive:
    """A CM with no trials returns an empty list; that must not be an
    IndexError escaping as a traceback."""

    @patch(MODULE_PATH)
    def test_no_trials_reports_an_error(self, MockClient):
        MockClient.return_value.get.return_value = {"resources": []}

        with pytest.raises(CMApiException, match="No trial licenses"):
            getTrialLicenseId(node=TEST_NODE)

    @patch(MODULE_PATH)
    def test_missing_resources_key_reports_an_error(self, MockClient):
        MockClient.return_value.get.return_value = {}

        with pytest.raises(CMApiException, match="No trial licenses"):
            getTrialLicenseId(node=TEST_NODE)

    @patch(MODULE_PATH)
    def test_incomplete_trial_record_reports_the_missing_fields(self, MockClient):
        MockClient.return_value.get.return_value = {"resources": [{"id": "t1"}]}

        with pytest.raises(CMApiException, match="status"):
            getTrialLicenseId(node=TEST_NODE)
