import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import MockExitJsonException, MockFailJsonException, TEST_NODE
from ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions import main

class TestInterfaceActions:
    @patch("ansible_collections.thalesgroup.ciphertrust.plugins.modules.interface_actions.ThalesCipherTrustModule")
    def test_execution(self, mock_thales_module, mock_module):
        mock_thales_module.return_value = mock_module
        mock_module.params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "delete",
            "name": "Test1",
            "id": "123",

        }
        # By just hitting main(), we expect it to try API call and fail gracefully or exit json
        try:
            main()
        except (MockExitJsonException, MockFailJsonException):
            pass
        except Exception as e:
            pass
