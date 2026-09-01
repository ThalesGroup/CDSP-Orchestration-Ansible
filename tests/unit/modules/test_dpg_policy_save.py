import pytest
from unittest.mock import patch

from test_helpers import MockExitJsonException, TEST_NODE
from ansible_collections.thalesgroup.ciphertrust.plugins.modules.dpg_policy_save import main


class TestDpgPolicySave:
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.dpg_policy_save.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.dpg_policy_save.idempotent_create")
    def test_create(self, mock_create, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "create",
            "id": "123",
            "meta": None,
            "profile_id": "prof1", "policy_id": "pol1", "format_id": "form1",
            "name": "policy-123",
        }
        mock_create.return_value = (True, {"id": "123"}, "123")
        with pytest.raises(MockExitJsonException) as excinfo:
            main()
        assert excinfo.value.kwargs["changed"] is True

    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.dpg_policy_save.ThalesCipherTrustModule")
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.dpg_policy_save.idempotent_patch")
    def test_patch(self, mock_patch, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "patch",
            "name": "Test1",
            "id": "123",
            "meta": None,
            "profile_id": "prof1", "format_id": "form1",
            "policy_id": "policy-123",
        }
        mock_patch.return_value = (False, {"id": "123"}, "123")
        with pytest.raises(MockExitJsonException) as excinfo:
            main()
        assert excinfo.value.kwargs["changed"] is False
