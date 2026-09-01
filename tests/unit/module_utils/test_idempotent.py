#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/idempotent.py"""

import pytest
from unittest.mock import MagicMock
from ansible.module_utils.six.moves.urllib.error import HTTPError

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    find_resource_by_query,
    resource_needs_update,
    idempotent_create,
    idempotent_patch,
    check_mode_action,
)


# ---------------------------------------------------------------------------
# find_resource_by_query
# ---------------------------------------------------------------------------

class TestFindResourceByQuery:
    def test_found_resource(self):
        client = MagicMock()
        client.get.return_value = {
            "resources": [{"id": "r1", "name": "MyKey"}]
        }

        result = find_resource_by_query(
            client, "vault/keys2", "name", "MyKey"
        )

        assert result == {"id": "r1", "name": "MyKey"}
        client.get.assert_called_once_with(
            "vault/keys2?skip=0&limit=1&name=MyKey"
        )

    def test_no_resources(self):
        client = MagicMock()
        client.get.return_value = {"resources": []}

        result = find_resource_by_query(
            client, "vault/keys2", "name", "ghost"
        )

        assert result is None

    def test_none_value(self):
        client = MagicMock()

        result = find_resource_by_query(client, "vault/keys2", "name", None)

        assert result is None
        client.get.assert_not_called()

    def test_http_error_404_returns_none(self):
        client = MagicMock()
        client.get.side_effect = HTTPError(
            url="", code=404, msg="Not Found", hdrs={}, fp=None
        )

        result = find_resource_by_query(
            client, "vault/keys2", "name", "ghost"
        )

        assert result is None

    def test_api_error_404_returns_none(self):
        client = MagicMock()
        client.get.side_effect = CMApiException(
            message="not found", api_error_code=404
        )

        result = find_resource_by_query(
            client, "vault/keys2", "name", "ghost"
        )

        assert result is None

    def test_server_error_propagates(self):
        """A 500 during lookup must not be mistaken for 'resource absent'."""
        client = MagicMock()
        client.get.side_effect = CMApiException(
            message="boom", api_error_code=500
        )

        with pytest.raises(CMApiException):
            find_resource_by_query(client, "vault/keys2", "name", "boom")

    def test_empty_resources_key(self):
        client = MagicMock()
        client.get.return_value = {"resources": None}

        result = find_resource_by_query(
            client, "vault/keys2", "name", "x"
        )

        assert result is None

    def test_non_dict_response(self):
        client = MagicMock()
        client.get.return_value = "unexpected"

        result = find_resource_by_query(
            client, "vault/keys2", "name", "x"
        )

        assert result is None


# ---------------------------------------------------------------------------
# resource_needs_update
# ---------------------------------------------------------------------------

class TestResourceNeedsUpdate:
    def test_no_change(self):
        current = {"name": "foo", "size": 256}
        desired = {"name": "foo", "size": 256}

        assert resource_needs_update(current, desired) is False

    def test_field_changed(self):
        current = {"name": "foo", "size": 256}
        desired = {"name": "bar", "size": 256}

        assert resource_needs_update(current, desired) is True

    def test_new_field(self):
        current = {"name": "foo"}
        desired = {"name": "foo", "desc": "new description"}

        assert resource_needs_update(current, desired) is True

    def test_none_desired_skipped(self):
        current = {"name": "foo"}
        desired = {"name": "foo", "desc": None}

        assert resource_needs_update(current, desired) is False

    def test_compare_fields_limits_scope(self):
        current = {"name": "foo", "size": 256}
        desired = {"name": "bar", "size": 512}

        # Only compare size
        assert resource_needs_update(
            current, desired, compare_fields=["size"]
        ) is True

    def test_compare_fields_no_change(self):
        current = {"name": "bar", "size": 256}
        desired = {"name": "foo", "size": 256}

        # Only compare size → no diff
        assert resource_needs_update(
            current, desired, compare_fields=["size"]
        ) is False


# ---------------------------------------------------------------------------
# idempotent_create
# ---------------------------------------------------------------------------

class TestIdempotentCreate:
    def test_existing_resource_returns_unchanged(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.return_value = {
            "resources": [{"id": "existing", "name": "foo"}]
        }

        changed, response, diff = idempotent_create(
            module, client,
            endpoint="vault/keys2",
            lookup_param="name",
            lookup_value="foo",
            create_fn=MagicMock(),
            create_kwargs={"node": {}, "name": "foo"},
        )

        assert changed is False
        assert response == {"id": "existing", "name": "foo"}
        assert diff is None

    def test_new_resource_created(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.return_value = {"resources": []}

        create_fn = MagicMock(return_value={"id": "new", "name": "foo"})

        changed, response, diff = idempotent_create(
            module, client,
            endpoint="vault/keys2",
            lookup_param="name",
            lookup_value="foo",
            create_fn=create_fn,
            create_kwargs={"node": {}, "name": "foo"},
        )

        assert changed is True
        assert response == {"id": "new", "name": "foo"}
        create_fn.assert_called_once()

    def test_check_mode_no_create(self):
        module = MagicMock()
        module.check_mode = True
        module._diff = False

        client = MagicMock()
        client.get.return_value = {"resources": []}

        create_fn = MagicMock()

        changed, response, diff = idempotent_create(
            module, client,
            endpoint="vault/keys2",
            lookup_param="name",
            lookup_value="foo",
            create_fn=create_fn,
            create_kwargs={"node": {}, "name": "foo"},
        )

        assert changed is True
        assert response == {}
        create_fn.assert_not_called()

    def test_diff_mode(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = True

        client = MagicMock()
        client.get.return_value = {"resources": []}

        create_fn = MagicMock(return_value={"id": "new"})

        changed, response, diff = idempotent_create(
            module, client,
            endpoint="vault/keys2",
            lookup_param="name",
            lookup_value="foo",
            create_fn=create_fn,
            create_kwargs={"node": {}, "name": "foo"},
        )

        assert diff is not None
        assert diff["before"] == {}
        assert diff["after"] == {"id": "new"}


# ---------------------------------------------------------------------------
# idempotent_patch
# ---------------------------------------------------------------------------

class TestIdempotentPatch:
    def test_no_change_needed(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.return_value = {"id": "r1", "name": "foo", "size": 256}

        changed, response, diff = idempotent_patch(
            module, client,
            endpoint="vault/keys2",
            resource_id="r1",
            patch_fn=MagicMock(),
            patch_kwargs={"node": {}, "name": "foo", "size": 256},
        )

        assert changed is False
        assert diff is None

    def test_change_needed(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.return_value = {"id": "r1", "name": "foo"}

        patch_fn = MagicMock(return_value={"id": "r1", "name": "bar"})

        changed, response, diff = idempotent_patch(
            module, client,
            endpoint="vault/keys2",
            resource_id="r1",
            patch_fn=patch_fn,
            patch_kwargs={"node": {}, "name": "bar"},
        )

        assert changed is True
        patch_fn.assert_called_once()

    def test_check_mode_skips_write(self):
        module = MagicMock()
        module.check_mode = True
        module._diff = False

        client = MagicMock()
        client.get.return_value = {"id": "r1", "name": "foo"}

        patch_fn = MagicMock()

        changed, response, diff = idempotent_patch(
            module, client,
            endpoint="vault/keys2",
            resource_id="r1",
            patch_fn=patch_fn,
            patch_kwargs={"node": {}, "name": "bar"},
        )

        assert changed is True
        patch_fn.assert_not_called()

    def test_routing_field_does_not_force_a_change(self):
        """Routing kwargs (old_name, cm_key_id, policy_id ...) are not resource
        fields.  The GET response never contains them, so comparing them makes
        every patch report changed=True and issue a redundant write."""
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.return_value = {"id": "r1", "name": "newname"}

        patch_fn = MagicMock()

        changed, response, diff = idempotent_patch(
            module, client,
            endpoint="usermgmt/groups",
            resource_id="oldname",
            patch_fn=patch_fn,
            patch_kwargs={"node": {}, "old_name": "oldname", "name": "newname"},
            ignore_fields=("old_name",),
        )

        assert changed is False
        patch_fn.assert_not_called()

    def test_routing_field_excluded_still_detects_real_change(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.return_value = {"id": "r1", "name": "oldname"}

        patch_fn = MagicMock(return_value={"id": "r1", "name": "newname"})

        changed, response, diff = idempotent_patch(
            module, client,
            endpoint="usermgmt/groups",
            resource_id="oldname",
            patch_fn=patch_fn,
            patch_kwargs={"node": {}, "old_name": "oldname", "name": "newname"},
            ignore_fields=("old_name",),
        )

        assert changed is True
        patch_fn.assert_called_once()

    def test_ignore_fields_accepts_multiple(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.return_value = {"id": "r1", "description": "same"}

        patch_fn = MagicMock()

        changed, _unused, _unused2 = idempotent_patch(
            module, client,
            endpoint="data-protection/policies",
            resource_id="p1",
            patch_fn=patch_fn,
            patch_kwargs={
                "node": {},
                "policy_id": "p1",
                "policy_name": "unused-routing-key",
                "description": "same",
            },
            ignore_fields=("policy_id", "policy_name"),
        )

        assert changed is False
        patch_fn.assert_not_called()

    def test_api_error_404_on_get_treated_as_missing(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.side_effect = CMApiException(
            message="not found", api_error_code=404
        )

        patch_fn = MagicMock(return_value={"id": "r1", "name": "bar"})

        changed, response, diff = idempotent_patch(
            module, client,
            endpoint="vault/keys2",
            resource_id="r1",
            patch_fn=patch_fn,
            patch_kwargs={"node": {}, "name": "bar"},
        )

        assert changed is True

    def test_server_error_on_get_propagates(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.side_effect = CMApiException(
            message="boom", api_error_code=500
        )

        with pytest.raises(CMApiException):
            idempotent_patch(
                module, client,
                endpoint="vault/keys2",
                resource_id="r1",
                patch_fn=MagicMock(),
                patch_kwargs={"node": {}, "name": "bar"},
            )

    def test_http_error_on_get_handles_gracefully(self):
        module = MagicMock()
        module.check_mode = False
        module._diff = False

        client = MagicMock()
        client.get.side_effect = HTTPError(
            url="", code=404, msg="Not Found", hdrs={}, fp=None
        )

        patch_fn = MagicMock(return_value={"id": "r1", "name": "bar"})

        changed, response, diff = idempotent_patch(
            module, client,
            endpoint="vault/keys2",
            resource_id="r1",
            patch_fn=patch_fn,
            patch_kwargs={"node": {}, "name": "bar"},
        )

        # Empty current → desired has changes → should update
        assert changed is True


# ---------------------------------------------------------------------------
# check_mode_action
# ---------------------------------------------------------------------------

class TestCheckModeAction:
    def test_check_mode_exits(self):
        module = MagicMock()
        module.check_mode = True

        check_mode_action(module)

        module.exit_json.assert_called_once_with(changed=True)

    def test_normal_mode_continues(self):
        module = MagicMock()
        module.check_mode = False

        check_mode_action(module)

        module.exit_json.assert_not_called()
