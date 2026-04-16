import importlib
from unittest.mock import patch

import pytest

from conftest import MockExitJsonException, TEST_NODE


CHECK_MODE_CREATE_MODULES = [
    ("cm_certificate_authority", {}),
    ("cte_client", {}),
    ("cte_client_group", {}),
    ("cte_csi_storage_group", {}),
    ("cte_policy_save", {}),
    ("cte_process_set", {}),
    ("cte_resource_set", {}),
    ("cte_signature_set", {}),
    ("cte_user_set", {}),
    ("domain_save", {}),
    ("dpg_access_policy_save", {}),
    ("dpg_character_set_save", {}),
    ("dpg_client_profile_save", {}),
    ("dpg_masking_format_save", {}),
    ("dpg_policy_save", {}),
    ("dpg_protection_policy_save", {}),
    ("dpg_user_set_save", {}),
    ("group_save", {}),
    ("interface_save", {"interface_type": "web", "port": 8443}),
    ("usermgmt_users_save", {"username": "user-check-mode"}),
    ("vault_keys2_save", {"algorithm": "aes"}),
]


@pytest.mark.parametrize("module_name,extra_params", CHECK_MODE_CREATE_MODULES)
def test_create_op_check_mode(module_name, extra_params, mock_module):
    module = importlib.import_module(
        f"ansible_collections.thalesgroup.ciphertrust.plugins.modules.{module_name}"
    )

    with patch.object(module, "ThalesCipherTrustModule", return_value=mock_module), patch.object(
        module, "validate_parameters", return_value=None, create=True
    ), patch.object(
        module, "idempotent_create", return_value=(True, {"id": "123"}, None)
    ) as mock_create:
        mock_module.check_mode = True
        params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "create",
            "name": "resource-check-mode",
            "id": "id-123",
        }
        params.update(extra_params)
        mock_module.params = params

        with pytest.raises(MockExitJsonException) as excinfo:
            module.main()

    assert excinfo.value.kwargs["changed"] is True
    assert mock_create.called
    assert mock_create.call_args.args[0].check_mode is True
