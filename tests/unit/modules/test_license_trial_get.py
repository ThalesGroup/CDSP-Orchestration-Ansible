#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/modules/license_trial_get.py"""

import pytest
from unittest.mock import patch

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import MockExitJsonException, MockFailJsonException, TEST_NODE
from ansible_collections.thalesgroup.ciphertrust.plugins.modules.license_trial_get import main


class TestLicenseTrialGet:
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.license_trial_get.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.license_trial_get.getTrialLicenseId")
    def test_get_trial_license(self, mock_get_id, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy()
        }
        
        mock_get_id.return_value = "trial-lic-123"

        with pytest.raises(MockExitJsonException) as excinfo:
            main()

        assert excinfo.value.kwargs["changed"] is False
        assert excinfo.value.kwargs["response"] == "trial-lic-123"

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.license_trial_get.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.license_trial_get.getTrialLicenseId")
    def test_get_trial_license_fails(self, mock_get_id, mock_thales_module, mock_module):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException
        
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy()
        }
        
        mock_get_id.side_effect = CMApiException("Not found")

        with pytest.raises(MockFailJsonException) as excinfo:
            main()

        assert "Not found" in excinfo.value.kwargs["msg"]
