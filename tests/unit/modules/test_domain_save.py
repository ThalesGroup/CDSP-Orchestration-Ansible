#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/modules/domain_save.py"""

import pytest
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import MockExitJsonException, MockFailJsonException, TEST_NODE
from ansible_collections.thalesgroup.ciphertrust.plugins.modules.domain_save import main


class TestDomainSave:
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.domain_save.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.domain_save.idempotent_create")
    def test_create_domain(self, mock_create, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "create",
            "name": "MyDomain",
            "description": "Test Domain",
            "meta": None
        }
        
        mock_create.return_value = (True, {"id": "dom1"}, "dom1")

        with pytest.raises(MockExitJsonException) as excinfo:
            main()

        assert excinfo.value.kwargs["changed"] is True
        assert "response" in excinfo.value.kwargs

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.domain_save.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.domain_save.idempotent_patch")
    def test_patch_domain(self, mock_patch, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "patch",
            "name": "MyDomain",
            "id": "dom1",
            "meta": None
        }
        # missing ID handled inside idempotent_patch
        
        mock_patch.return_value = (False, {"id": "dom1", "name": "MyDomain"}, "dom1")

        with pytest.raises(MockExitJsonException) as excinfo:
            main()

        assert excinfo.value.kwargs["changed"] is False
        assert "response" in excinfo.value.kwargs

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.domain_save.ThalesCipherTrustModule")
    def test_invalid_op_type(self, mock_thales_module, mock_module):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import AnsibleCMValidationException
        
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "delete",
            "name": "MyDomain",
            "meta": None
        }

        with pytest.raises(MockFailJsonException) as excinfo:
            main()

        assert "invalid op_type" in excinfo.value.kwargs["msg"]
