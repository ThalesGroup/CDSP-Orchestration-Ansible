# -*- coding: utf-8 -*-
"""The idempotency contract every save-style module must honour.

These drive each module's real ``main()`` -- real validation, real
``idempotent_create`` / ``idempotent_patch``, real payload building -- with
only the HTTP client faked. Nothing here patches the helper under test, so a
regression in the idempotency logic fails these tests rather than passing a
mock's canned return value back to itself.

Each entry below names the parameters a module needs to reach its write path
and one field whose value decides whether a patch is a no-op.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)
from module_harness import make_client, run_main


class Spec(object):
    def __init__(self, name, lookup_key, patch_key, compare_field,
                 same_value, other_value, create_extra=None, patch_extra=None,
                 supports_create=True, resource_id="res-123"):
        self.name = name
        self.lookup_key = lookup_key
        self.patch_key = patch_key
        self.compare_field = compare_field
        self.same_value = same_value
        self.other_value = other_value
        self.create_extra = create_extra or {}
        self.patch_extra = patch_extra or {}
        self.supports_create = supports_create
        # some modules validate the shape of their identifier
        self.resource_id = resource_id

    def __repr__(self):
        return self.name

    def create_params(self):
        params = {"op_type": "create", self.lookup_key: "contract-test"}
        params.update(self.create_extra)
        return params

    def current_state(self, value):
        """What CM would report when the desired state is already in place."""
        state = {"id": self.resource_id, self.compare_field: value}
        state.update(self.patch_extra)
        return state

    def patch_params(self, value):
        params = {"op_type": "patch",
                  self.patch_key: self.resource_id,
                  self.compare_field: value}
        params.update(self.patch_extra)
        return params


SPECS = [
    Spec("cm_certificate_authority", "cn", "id",
         "allow_client_authentication", True, False),
    Spec("cm_regtoken", "name_prefix", "id", "lifetime", "30d", "60d",
         supports_create=False),
    Spec("connection_aws_save", "name", "connection_id",
         "description", "same", "other"),
    Spec("connection_azure_save", "name", "connection_id",
         "description", "same", "other",
         create_extra={"client_id": "app-1", "tenant_id": "tenant-1"}),
    Spec("connection_gcp_save", "name", "connection_id",
         "description", "same", "other",
         create_extra={"key_file": "{\"type\": \"service_account\"}"}),
    Spec("connection_oci_save", "name", "connection_id",
         "description", "same", "other",
         create_extra={"credentials": {"key_file": "-----BEGIN-----"},
                       "fingerprint": "aa:bb", "region": "us-ashburn-1",
                       "tenancy_ocid": "ocid1.tenancy.oc1..a",
                       "user_ocid": "ocid1.user.oc1..b"}),
    Spec("cte_client", "name", "id", "description", "same", "other"),
    Spec("cte_client_group", "name", "id", "description", "same", "other"),
    Spec("cte_csi_storage_group", "name", "id", "description", "same", "other"),
    Spec("cte_policy_save", "name", "policy_id", "description", "same", "other"),
    Spec("cte_process_set", "name", "id", "description", "same", "other"),
    Spec("cte_resource_set", "name", "id", "description", "same", "other"),
    Spec("cte_signature_set", "name", "id", "description", "same", "other"),
    Spec("cte_user_set", "name", "id", "description", "same", "other"),
    Spec("domain_save", "name", "domain_id", "domain_kek_label", "kek-1", "kek-2"),
    Spec("dpg_access_policy_save", "name", "policy_id",
         "default_error_replacement_value", "REDACTED", "HIDDEN"),
    Spec("dpg_character_set_save", "name", "char_set_id",
         "encoding", "UTF-8", "UTF-16"),
    Spec("dpg_client_profile_save", "name", "profile_id",
         "heartbeat_threshold", 30, 60),
    Spec("dpg_masking_format_save", "name", "masking_format_id",
         "mask_char", "X", "*"),
    Spec("dpg_policy_save", "name", "policy_id", "description", "same", "other"),
    Spec("dpg_protection_policy_save", "name", "policy_name",
         "algorithm", "FF1", "FF3"),
    Spec("dpg_user_set_save", "name", "user_set_id",
         "description", "same", "other"),
    Spec("group_save", "name", "old_name", "name", "same", "other"),
    Spec("interface_save", "name", "interface_id", "port", 8443, 9443,
         create_extra={"port": 8443, "interface_type": "web"}),
    Spec("usermgmt_users_save", "username", "cm_user_id",
         "email", "a@example.com", "b@example.com",
         patch_extra={"username": "contract-test"},
         resource_id="local|12345678-1234-1234-1234-123456789abc"),
    Spec("vault_keys2_save", "name", "cm_key_id", "muid", "muid-1", "muid-2",
         create_extra={"algorithm": "aes"}),
]

CREATE_SPECS = [s for s in SPECS if s.supports_create]

all_specs = pytest.mark.parametrize(
    "spec", SPECS, ids=[s.name for s in SPECS]
)
create_specs = pytest.mark.parametrize(
    "spec", CREATE_SPECS, ids=[s.name for s in CREATE_SPECS]
)


@create_specs
class TestCreateIsIdempotent:

    def test_creates_when_the_resource_is_absent(self, spec):
        client = make_client(get={"resources": []})
        result = run_main(spec.name, spec.create_params(), client=client)

        assert not result.failed, result.msg
        assert result.changed is True
        assert client.post.called, "expected a POST to create the resource"

    def test_second_run_reports_no_change(self, spec):
        existing = {"id": spec.resource_id, spec.lookup_key: "contract-test"}
        client = make_client(get={"resources": [existing]})
        result = run_main(spec.name, spec.create_params(), client=client)

        assert not result.failed, result.msg
        assert result.changed is False
        assert not result.wrote(), (
            "an existing resource must not be written to: %s"
            % (result.write_calls(),)
        )
        assert result.kwargs.get("response") == existing

    def test_check_mode_does_not_create(self, spec):
        client = make_client(get={"resources": []})
        result = run_main(spec.name, spec.create_params(),
                          client=client, check_mode=True)

        assert not result.failed, result.msg
        assert result.changed is True
        assert not result.wrote(), "check mode must not write"


@all_specs
class TestPatchIsIdempotent:

    def test_no_change_when_state_already_matches(self, spec):
        current = spec.current_state(spec.same_value)
        client = make_client(get=current)
        result = run_main(spec.name, spec.patch_params(spec.same_value),
                          client=client)

        assert not result.failed, result.msg
        assert result.changed is False, (
            "%s reports changed when the desired state is already in place"
            % spec.name
        )
        assert not result.wrote(), (
            "no write should be issued: %s" % (result.write_calls(),)
        )

    def test_patches_when_state_differs(self, spec):
        current = spec.current_state(spec.other_value)
        client = make_client(get=current)
        result = run_main(spec.name, spec.patch_params(spec.same_value),
                          client=client)

        assert not result.failed, result.msg
        assert result.changed is True
        assert client.patch.called, "expected a PATCH to apply the change"

    def test_check_mode_does_not_patch(self, spec):
        current = spec.current_state(spec.other_value)
        client = make_client(get=current)
        result = run_main(spec.name, spec.patch_params(spec.same_value),
                          client=client, check_mode=True)

        assert not result.failed, result.msg
        assert result.changed is True
        assert not result.wrote(), "check mode must not write"


@all_specs
class TestErrorsSurfaceCleanly:

    def test_api_error_becomes_fail_json(self, spec):
        client = make_client(
            get=CMApiException(message="Forbidden", api_error_code=403)
        )
        result = run_main(spec.name, spec.patch_params(spec.same_value),
                          client=client)

        assert result.failed, "a 403 during lookup must fail the module"
        assert "403" in result.msg

    def test_missing_resource_on_patch_still_writes(self, spec):
        """A 404 on the pre-flight GET means 'not there yet', not an error."""
        client = make_client(
            get=CMApiException(message="not found", api_error_code=404)
        )
        result = run_main(spec.name, spec.patch_params(spec.same_value),
                          client=client)

        assert not result.failed, result.msg
        assert result.changed is True
