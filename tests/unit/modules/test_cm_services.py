#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/modules/cm_services.py"""

import pytest
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import MockExitJsonException, MockFailJsonException, TEST_NODE
from ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_services import main


class TestCMServices:
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_services.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_services.restartCMServices")
    def test_restart_services(self, mock_restart, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "restart",
            "services": ["web", "db"]
        }
        mock_restart.return_value = {"status": "restarted"}

        with pytest.raises(MockExitJsonException) as excinfo:
            main()

        assert excinfo.value.kwargs["changed"] is True
        assert excinfo.value.kwargs["response"] == {"status": "restarted"}
        mock_restart.assert_called_once_with(
            node=mock_module.params["localNode"],
            delay=None,
            services=["web", "db"]
        )

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_services.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_services.restartCMServices")
    def test_handles_ciphertrust_error(self, mock_restart, mock_thales_module, mock_module):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException
        
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "restart",
            "services": ["web"]
        }
        mock_restart.side_effect = CMApiException("Restart failed")

        with pytest.raises(MockFailJsonException) as excinfo:
            main()

        assert "Restart failed" in excinfo.value.kwargs["msg"]
