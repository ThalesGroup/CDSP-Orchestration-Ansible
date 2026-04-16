import pytest
from unittest.mock import patch

from test_helpers import MockExitJsonException, TEST_NODE
from ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_resource_delete import main


class TestCmResourceDelete:
    def test_execution(self, mock_module):
        with patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_resource_delete.ThalesCipherTrustModule",
            return_value=mock_module,
        ), patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_resource_delete.validate_parameters",
            return_value=None,
        ), patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_resource_delete.DeleteWithoutData",
            return_value={"status": "ok"},
        ) as mock_helper:
            mock_module.check_mode = False
            mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "resource_type": "keys",
            "key": "key-123",
            }

            with pytest.raises(MockExitJsonException) as excinfo:
                main()

        assert excinfo.value.kwargs["changed"] is True
        assert excinfo.value.kwargs["response"] == {"status": "ok"}
        mock_helper.assert_called_once()

    def test_check_mode(self, mock_module):
        with patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_resource_delete.ThalesCipherTrustModule",
            return_value=mock_module,
        ), patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_resource_delete.validate_parameters",
            return_value=None,
        ), patch(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules.cm_resource_delete.DeleteWithoutData",
            return_value={"status": "ok"},
        ) as mock_helper:
            mock_module.check_mode = True
            mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "resource_type": "keys",
            "key": "key-123",
            }

            with pytest.raises(MockExitJsonException) as excinfo:
                main()

        assert excinfo.value.kwargs["changed"] is True
        mock_helper.assert_not_called()
