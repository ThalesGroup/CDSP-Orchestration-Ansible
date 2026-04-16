import importlib
from unittest.mock import patch

import pytest

from test_helpers import MockExitJsonException, TEST_NODE


CREATE_PATCH_MODULES = [
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
    ("usermgmt_users_save", {"username": "user-idempotent"}),
    ("vault_keys2_save", {"algorithm": "aes"}),
]


@pytest.mark.parametrize("module_name,extra_params", CREATE_PATCH_MODULES)
def test_create_second_run_returns_changed_false(module_name, extra_params, mock_module):
    module = importlib.import_module(
        f"ansible_collections.thalesgroup.ciphertrust.plugins.modules.{module_name}"
    )

    with patch.object(
        module, "ThalesCipherTrustModule", return_value=mock_module
    ), patch.object(
        module, "validate_parameters", return_value=None, create=True
    ), patch.object(
        module,
        "idempotent_create",
        side_effect=[(True, {"id": "123"}, "123"), (False, {"id": "123"}, "123")],
    ) as mock_create:
        params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "create",
            "name": "resource-idempotent",
            "id": "id-123",
        }
        params.update(extra_params)
        mock_module.params = params

        with pytest.raises(MockExitJsonException) as first:
            module.main()
        with pytest.raises(MockExitJsonException) as second:
            module.main()

    assert first.value.kwargs["changed"] is True
    assert second.value.kwargs["changed"] is False
    assert mock_create.call_count == 2


@pytest.mark.parametrize("module_name,extra_params", CREATE_PATCH_MODULES)
def test_patch_second_run_returns_changed_false(module_name, extra_params, mock_module):
    module = importlib.import_module(
        f"ansible_collections.thalesgroup.ciphertrust.plugins.modules.{module_name}"
    )

    with patch.object(
        module, "ThalesCipherTrustModule", return_value=mock_module
    ), patch.object(
        module, "validate_parameters", return_value=None, create=True
    ), patch.object(
        module,
        "idempotent_patch",
        side_effect=[(True, {"id": "123"}, "123"), (False, {"id": "123"}, "123")],
    ) as mock_patch:
        params = {
            "localNode": TEST_NODE.copy(),
            "op_type": "patch",
            "name": "resource-idempotent",
            "id": "id-123",
        }
        params.update(extra_params)
        mock_module.params = params

        with pytest.raises(MockExitJsonException) as first:
            module.main()
        with pytest.raises(MockExitJsonException) as second:
            module.main()

    assert first.value.kwargs["changed"] is True
    assert second.value.kwargs["changed"] is False
    assert mock_patch.call_count == 2
