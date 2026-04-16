import pytest
from unittest.mock import patch

from conftest import MockExitJsonException, TEST_NODE
from ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions import main


class TestInterfaceActions:
    def test_execution(self, mock_module):
        with patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions.ThalesCipherTrustModule",
            return_value=mock_module,
        ), patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions.validate_parameters",
            return_value=None,
        ), patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions.enableInterface",
            return_value={"status": "ok"},
        ) as mock_helper:
            mock_module.check_mode = False
            mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "enable",
            "interface_id": "intf-123",
            }

            with pytest.raises(MockExitJsonException) as excinfo:
                main()

        assert excinfo.value.kwargs["changed"] is True
        assert excinfo.value.kwargs["response"] == {"status": "ok"}
        mock_helper.assert_called_once()

    def test_check_mode(self, mock_module):
        with patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions.ThalesCipherTrustModule",
            return_value=mock_module,
        ), patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions.validate_parameters",
            return_value=None,
        ), patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions.enableInterface",
            return_value={"status": "ok"},
        ) as mock_helper:
            mock_module.check_mode = True
            mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "enable",
            "interface_id": "intf-123",
            }

            with pytest.raises(MockExitJsonException) as excinfo:
                main()

        assert excinfo.value.kwargs["changed"] is True
        mock_helper.assert_not_called()
