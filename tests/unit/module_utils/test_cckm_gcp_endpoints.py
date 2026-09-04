# -*- coding: utf-8 -*-
"""Every CCKM Google Cloud request must reach a path the API actually serves.

The counterpart of ``test_cckm_aws_endpoints`` and ``test_cckm_azure_endpoints``,
written the same way and for the same reason.

One thing this file is specifically guarding: CCKM serves Google Cloud under
``cckm/google``, not ``cckm/gcp``, while the modules are named for the cloud.
A constant that followed the module names would 404 on every call, and this is
where that shows up.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_gcp,
)
from module_harness import make_client
from test_helpers import TEST_NODE as NODE

ID = "res-1"
VERSION = "ver-1"

# Every path CCKM's Google Cloud service serves, with placeholders filled in.
EXPECTED_PATHS = frozenset([
    "cckm/google/add-key-rings",
    "cckm/google/get-iam-roles",
    "cckm/google/get-key-rings",
    "cckm/google/get-locations",
    "cckm/google/get-projects",
    "cckm/google/key-rings",
    "cckm/google/key-rings/res-1",
    "cckm/google/key-rings/res-1/remove-key-ring",
    "cckm/google/key-rings/res-1/update-acls",
    "cckm/google/keys",
    "cckm/google/keys/res-1",
    "cckm/google/keys/res-1/disable-auto-rotation",
    "cckm/google/keys/res-1/enable-auto-rotation",
    "cckm/google/keys/res-1/policy",
    "cckm/google/keys/res-1/refresh",
    "cckm/google/keys/res-1/versions",
    "cckm/google/keys/res-1/versions/ver-1",
    "cckm/google/keys/res-1/versions/ver-1/cancel-schedule-destroy",
    "cckm/google/keys/res-1/versions/ver-1/disable",
    "cckm/google/keys/res-1/versions/ver-1/download-public-key",
    "cckm/google/keys/res-1/versions/ver-1/enable",
    "cckm/google/keys/res-1/versions/ver-1/re-import",
    "cckm/google/keys/res-1/versions/ver-1/refresh",
    "cckm/google/keys/res-1/versions/ver-1/schedule-destroy",
    "cckm/google/projects",
    "cckm/google/projects/res-1",
    "cckm/google/projects/res-1/update-acls",
    "cckm/google/reports",
    "cckm/google/reports/res-1",
    "cckm/google/reports/res-1/contents",
    "cckm/google/reports/res-1/download",
    "cckm/google/synchronization-jobs",
    "cckm/google/synchronization-jobs/res-1",
    "cckm/google/synchronization-jobs/res-1/cancel",
    "cckm/google/update-all-versions-jobs",
    "cckm/google/update-all-versions-jobs/res-1",
    "cckm/google/upload-key",
])

CALLS = [
    ("project_create", dict(project_id="p")),
    ("project_patch", dict(gcp_project_id=ID)),
    ("project_get", dict(gcp_project_id=ID)),
    ("project_list", dict()),
    ("project_delete", dict(gcp_project_id=ID)),
    ("project_update_acls", dict(gcp_project_id=ID, acls=[])),
    ("projects_available", dict(connection="c")),
    ("locations_available", dict(project_id="p")),
    ("iam_roles_available", dict(id=ID)),

    ("key_ring_add", dict(connection="c", project_id="p", key_rings=[])),
    ("key_ring_patch", dict(key_ring_id=ID, connection="c")),
    ("key_ring_get", dict(key_ring_id=ID)),
    ("key_ring_list", dict()),
    ("key_ring_action", dict(key_ring_id=ID, action="remove-key-ring")),
    ("key_ring_update_acls", dict(key_ring_id=ID, acls=[])),
    ("key_rings_available", dict(connection="c", project_id="p", location="l")),

    ("key_create", dict(key_ring="r", gcp_key_params={})),
    ("key_upload", dict(key_ring="r", gcp_key_params={}, source_key_id="s",
                        source_key_tier="local")),
    ("key_patch", dict(key_id=ID)),
    ("key_get", dict(key_id=ID)),
    ("key_list", dict()),
    ("key_policy_get", dict(key_id=ID)),
    ("key_policy_set", dict(key_id=ID)),
    ("key_version_create", dict(key_id=ID)),
    ("key_version_list", dict(key_id=ID)),
    ("key_version_get", dict(key_id=ID, version_id=VERSION)),

    ("report_create", dict(name="n", report_type="key-report", gcp_cloud_params=[])),
    ("report_get", dict(report_id=ID)),
    ("report_list", dict()),
    ("report_delete", dict(report_id=ID)),
    ("report_contents", dict(report_id=ID)),
    ("report_download", dict(report_id=ID)),

    ("sync_start", dict()),
    ("sync_get", dict(job_id=ID)),
    ("sync_list", dict()),
    ("sync_cancel", dict(job_id=ID)),

    ("update_all_versions_start", dict(key_id="k", operation="enable")),
    ("update_all_versions_get", dict(job_id=ID)),
]
CALLS += [("key_action", dict(key_id=ID, action=a))
          for a in sorted(cckm_gcp.KEY_ACTIONS)]
CALLS += [("key_version_action", dict(key_id=ID, version_id=VERSION, action=a))
          for a in sorted(cckm_gcp.KEY_VERSION_ACTIONS)]


def _label(name, kwargs):
    parts = ["%s=%s" % (k, v) for k, v in sorted(kwargs.items())
             if k in ("action", "operation")]
    return "%s(%s)" % (name, ",".join(parts) or "-")


IDS = [_label(name, kw) for name, kw in CALLS]


def _urls_from(monkeypatch, fn_name, kwargs):
    """Every URL the helper requests, with the query string stripped."""
    client = make_client()
    monkeypatch.setattr(cckm_gcp, "CipherTrustClient", lambda node: client)
    getattr(cckm_gcp, fn_name)(node=NODE, **kwargs)

    urls = []
    for verb in ("get", "post", "put", "patch", "delete"):
        for call in getattr(client, verb).call_args_list:
            if call[0]:
                urls.append(call[0][0].split("?")[0])
    return urls


def test_the_service_root_is_google_not_gcp():
    """The modules are named for the cloud; the API is not."""
    assert cckm_gcp.ROOT == "cckm/google"


@pytest.mark.parametrize("fn_name,kwargs", CALLS, ids=IDS)
def test_helper_targets_a_published_path(monkeypatch, fn_name, kwargs):
    urls = _urls_from(monkeypatch, fn_name, kwargs)
    assert urls, "%s made no request" % fn_name
    for url in urls:
        assert url in EXPECTED_PATHS, (
            "%s targets %r, which CCKM's Google Cloud API does not serve"
            % (fn_name, url))


def test_every_public_helper_is_covered():
    """A helper added without a case here would go unchecked."""
    import inspect

    public = {
        name for name, obj in vars(cckm_gcp).items()
        if inspect.isfunction(obj)
        and obj.__module__ == cckm_gcp.__name__
        and not name.startswith("_")
    }
    covered = {name for name, _kwargs in CALLS}
    assert not public - covered, (
        "request helpers with no endpoint check: %s" % sorted(public - covered))


def test_every_whitelisted_action_is_exercised():
    exercised = {kw["action"] for name, kw in CALLS if "action" in kw}
    declared = (cckm_gcp.KEY_ACTIONS | cckm_gcp.KEY_VERSION_ACTIONS
                | cckm_gcp.KEY_RING_ACTIONS)
    assert not declared - exercised, (
        "whitelisted actions with no endpoint check: %s"
        % sorted(declared - exercised))


class TestIdentifiersCannotEscapeTheirPath:
    """Ids come from playbooks. One containing ``/`` must stay in its segment."""

    def test_a_traversing_key_id_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_get",
                          dict(key_id="../../vault/keys2/admin"))
        assert urls == ["cckm/google/keys/..%2F..%2Fvault%2Fkeys2%2Fadmin"]

    def test_a_traversing_version_id_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_version_get",
                          dict(key_id="k", version_id="../../.."))
        assert urls == ["cckm/google/keys/k/versions/..%2F..%2F.."]


class TestUnsupportedNamesAreRejected:
    """Action and operation names form part of a URL or a payload contract."""

    @pytest.mark.parametrize("fn_name,kwargs", [
        ("key_action", dict(key_id=ID, action="destroy")),
        ("key_version_action", dict(key_id=ID, version_id=VERSION, action="rotate")),
        ("key_ring_action", dict(key_ring_id=ID, action="delete")),
    ])
    def test_an_unknown_action_is_refused(self, monkeypatch, fn_name, kwargs):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
            AnsibleCMParameterException,
        )
        with pytest.raises(AnsibleCMParameterException):
            _urls_from(monkeypatch, fn_name, kwargs)

    def test_an_unknown_bulk_operation_is_refused(self, monkeypatch):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
            AnsibleCMParameterException,
        )
        with pytest.raises(AnsibleCMParameterException):
            _urls_from(monkeypatch, "update_all_versions_start",
                       dict(key_id="k", operation="purge"))
