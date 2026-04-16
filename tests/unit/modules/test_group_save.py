#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/modules/group_save.py"""

import pytest
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import MockExitJsonException, MockFailJsonException, TEST_NODE
from ansible_collections.thalesgroup.ciphertrust.plugins.modules.group_save import main


class TestGroupSave:
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.group_save.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.group_save.idempotent_create")
    def test_create_group(self, mock_create, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "create",
            "name": "Admins",
        }
        
        mock_create.return_value = (True, {"id": "grp1"}, "grp1")

        with pytest.raises(MockExitJsonException) as excinfo:
            main()

        assert excinfo.value.kwargs["changed"] is True
        assert excinfo.value.kwargs["response"] == {"id": "grp1"}

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.group_save.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.group_save.idempotent_patch")
    def test_patch_group(self, mock_patch, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "patch",
            "name": "Admins",
            "id": "grp1"
        }
        
        mock_patch.return_value = (False, {"id": "grp1", "name": "Admins"}, "grp1")

        with pytest.raises(MockExitJsonException) as excinfo:
            main()

        assert excinfo.value.kwargs["changed"] is False
        assert "response" in excinfo.value.kwargs
