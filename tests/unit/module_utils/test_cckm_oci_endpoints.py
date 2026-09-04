# -*- coding: utf-8 -*-
"""Every CCKM OCI request must reach a path the API actually serves.

The counterpart of the AWS, Azure and Google Cloud endpoint tests, written the
same way and for the same reason.

Two things this file guards specifically. CCKM serves one OCI path with a
**trailing slash** -- ``keys/{id}/versions/{version}/`` -- while every sibling
has none, so a helper that trimmed it would 404. And OCI's containment model
means several collections take an OCID rather than a CCKM id, which must still
be encoded into a single path segment.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_oci,
)
from module_harness import make_client
from test_helpers import TEST_NODE as NODE

ID = "res-1"
VERSION = "ver-1"

# Every path CCKM's OCI service serves, with placeholders filled in.
EXPECTED_PATHS = frozenset([
    "cckm/oci/add-compartments",
    "cckm/oci/add-tenancy",
    "cckm/oci/add-vaults",
    "cckm/oci/compartments",
    "cckm/oci/compartments/res-1",
    "cckm/oci/create-external-key",
    "cckm/oci/create-external-vault",
    "cckm/oci/get-compartments",
    "cckm/oci/get-defined-tags",
    "cckm/oci/get-subscribed-regions",
    "cckm/oci/get-vaults",
    "cckm/oci/issuers",
    "cckm/oci/issuers/res-1",
    "cckm/oci/keys",
    "cckm/oci/keys/res-1",
    "cckm/oci/keys/res-1/block",
    "cckm/oci/keys/res-1/cancel-deletion",
    "cckm/oci/keys/res-1/change-compartment",
    "cckm/oci/keys/res-1/delete-backup",
    "cckm/oci/keys/res-1/disable",
    "cckm/oci/keys/res-1/disable-auto-rotation",
    "cckm/oci/keys/res-1/enable",
    "cckm/oci/keys/res-1/enable-auto-rotation",
    "cckm/oci/keys/res-1/refresh",
    "cckm/oci/keys/res-1/restore",
    "cckm/oci/keys/res-1/schedule-deletion",
    "cckm/oci/keys/res-1/unblock",
    "cckm/oci/keys/res-1/versions",
    "cckm/oci/keys/res-1/versions/ver-1/",
    "cckm/oci/keys/res-1/versions/ver-1/cancel-deletion",
    "cckm/oci/keys/res-1/versions/ver-1/schedule-deletion",
    "cckm/oci/reports",
    "cckm/oci/reports/res-1",
    "cckm/oci/reports/res-1/contents",
    "cckm/oci/reports/res-1/download",
    "cckm/oci/storage/list-buckets",
    "cckm/oci/synchronization-jobs",
    "cckm/oci/synchronization-jobs/res-1",
    "cckm/oci/synchronization-jobs/res-1/cancel",
    "cckm/oci/tenancy",
    "cckm/oci/tenancy/res-1",
    "cckm/oci/upload-key",
    "cckm/oci/vaults",
    "cckm/oci/vaults/res-1",
    "cckm/oci/vaults/res-1/block",
    "cckm/oci/vaults/res-1/unblock",
    "cckm/oci/vaults/res-1/update-acls",
])

CALLS = [
    ("tenancy_add", dict()),
    ("tenancy_get", dict(tenancy_id=ID)),
    ("tenancy_list", dict()),
    ("tenancy_delete", dict(tenancy_id=ID)),
    ("subscribed_regions", dict(connection="c")),

    ("compartment_add", dict(connection="c", compartment_id=["x"])),
    ("compartment_get", dict(compartment_id=ID)),
    ("compartment_list", dict()),
    ("compartment_delete", dict(compartment_id=ID)),
    ("compartments_available", dict(connection="c")),
    ("defined_tags_available", dict(connection="c")),
    ("buckets_available", dict(connection="c", compartment_id=ID)),

    ("vault_add", dict(connection="c", region="r", vault_id=["v"])),
    ("vault_create_external", dict(vault_name="v", endpoint_url_hostname="h",
                                   client_application_id="a", issuer_id="i")),
    ("vault_patch", dict(vault_id=ID)),
    ("vault_get", dict(vault_id=ID)),
    ("vault_list", dict()),
    ("vault_delete", dict(vault_id=ID)),
    ("vault_update_acls", dict(vault_id=ID, acls=[])),
    ("vaults_available", dict(connection="c", compartment_id=ID, region="r")),

    ("issuer_create", dict(name="n", jwks_uri_protected=True)),
    ("issuer_patch", dict(issuer_id=ID)),
    ("issuer_get", dict(issuer_id=ID)),
    ("issuer_list", dict()),
    ("issuer_delete", dict(issuer_id=ID)),

    ("key_create", dict(vault="v", name="n", algorithm="AES", length=32,
                        protection_mode="HSM", compartment_id="c")),
    ("key_upload", dict(vault="v", name="n", protection_mode="HSM",
                        compartment_id="c", source_key_identifier="s",
                        source_key_tier="local")),
    ("key_create_external", dict(vault="v", name="n", source_key_identifier="s",
                                 source_key_tier="local")),
    ("key_patch", dict(key_id=ID)),
    ("key_get", dict(key_id=ID)),
    ("key_list", dict()),
    ("key_delete", dict(key_id=ID)),
    ("key_version_create", dict(key_id=ID, is_native=True)),
    ("key_version_list", dict(key_id=ID)),
    ("key_version_get", dict(key_id=ID, version_id=VERSION)),

    ("report_create", dict(name="n", report_type="key-report", oci_params=[])),
    ("report_get", dict(report_id=ID)),
    ("report_list", dict()),
    ("report_delete", dict(report_id=ID)),
    ("report_contents", dict(report_id=ID)),
    ("report_download", dict(report_id=ID)),

    ("sync_start", dict()),
    ("sync_get", dict(job_id=ID)),
    ("sync_list", dict()),
    ("sync_cancel", dict(job_id=ID)),
]
CALLS += [("vault_action", dict(vault_id=ID, action=a))
          for a in sorted(cckm_oci.VAULT_ACTIONS)]
CALLS += [("key_action", dict(key_id=ID, action=a))
          for a in sorted(cckm_oci.KEY_ACTIONS)]
CALLS += [("key_version_action", dict(key_id=ID, version_id=VERSION, action=a))
          for a in sorted(cckm_oci.KEY_VERSION_ACTIONS)]


def _label(name, kwargs):
    parts = ["%s=%s" % (k, v) for k, v in sorted(kwargs.items())
             if k == "action"]
    return "%s(%s)" % (name, ",".join(parts) or "-")


IDS = [_label(name, kw) for name, kw in CALLS]


def _urls_from(monkeypatch, fn_name, kwargs):
    """Every URL the helper requests, with the query string stripped."""
    client = make_client()
    monkeypatch.setattr(cckm_oci, "CipherTrustClient", lambda node: client)
    getattr(cckm_oci, fn_name)(node=NODE, **kwargs)

    urls = []
    for verb in ("get", "post", "put", "patch", "delete"):
        for call in getattr(client, verb).call_args_list:
            if call[0]:
                urls.append(call[0][0].split("?")[0])
    return urls


@pytest.mark.parametrize("fn_name,kwargs", CALLS, ids=IDS)
def test_helper_targets_a_published_path(monkeypatch, fn_name, kwargs):
    urls = _urls_from(monkeypatch, fn_name, kwargs)
    assert urls, "%s made no request" % fn_name
    for url in urls:
        assert url in EXPECTED_PATHS, (
            "%s targets %r, which CCKM's OCI API does not serve"
            % (fn_name, url))


def test_the_key_version_get_keeps_its_trailing_slash():
    """CCKM serves this one path with a trailing slash and its siblings without.

    Trimming it, or adding one to a sibling, produces a 404 that no other test
    in this file would catch.
    """
    assert "cckm/oci/keys/res-1/versions/ver-1/" in EXPECTED_PATHS
    assert "cckm/oci/keys/res-1/versions/ver-1" not in EXPECTED_PATHS


def test_every_public_helper_is_covered():
    """A helper added without a case here would go unchecked."""
    import inspect

    public = {
        name for name, obj in vars(cckm_oci).items()
        if inspect.isfunction(obj)
        and obj.__module__ == cckm_oci.__name__
        and not name.startswith("_")
    }
    covered = {name for name, _kwargs in CALLS}
    assert not public - covered, (
        "request helpers with no endpoint check: %s" % sorted(public - covered))


def test_every_whitelisted_action_is_exercised():
    exercised = {kw["action"] for name, kw in CALLS if "action" in kw}
    declared = (cckm_oci.VAULT_ACTIONS | cckm_oci.KEY_ACTIONS
                | cckm_oci.KEY_VERSION_ACTIONS)
    assert not declared - exercised, (
        "whitelisted actions with no endpoint check: %s"
        % sorted(declared - exercised))


class TestIdentifiersCannotEscapeTheirPath:
    """Ids come from playbooks, and in OCI they are often OCIDs."""

    def test_a_traversing_key_id_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_get",
                          dict(key_id="../../vault/keys2/admin"))
        assert urls == ["cckm/oci/keys/..%2F..%2Fvault%2Fkeys2%2Fadmin"]

    def test_a_traversing_version_id_keeps_the_trailing_slash(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_version_get",
                          dict(key_id="k", version_id="a/b"))
        assert urls == ["cckm/oci/keys/k/versions/a%2Fb/"]


class TestUnsupportedNamesAreRejected:
    """Action names form part of a URL, so they are whitelisted."""

    @pytest.mark.parametrize("fn_name,kwargs", [
        ("key_action", dict(key_id=ID, action="destroy")),
        ("key_version_action", dict(key_id=ID, version_id=VERSION, action="enable")),
        ("vault_action", dict(vault_id=ID, action="delete")),
    ])
    def test_an_unknown_action_is_refused(self, monkeypatch, fn_name, kwargs):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
            AnsibleCMParameterException,
        )
        with pytest.raises(AnsibleCMParameterException):
            _urls_from(monkeypatch, fn_name, kwargs)
