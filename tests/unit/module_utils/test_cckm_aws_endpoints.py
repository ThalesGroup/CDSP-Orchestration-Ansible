# -*- coding: utf-8 -*-
"""Every CCKM AWS request must reach a path the API actually serves.

The action-module contract checks the URL each ``op_type`` produces. This
checks the other direction: that the set of paths this collection can build
is a subset of the paths CCKM publishes, so a typo in an endpoint constant --
``custom-key-store`` for ``custom-key-stores``, ``bulk-job`` for ``bulkjob``
-- is caught here rather than by a 404 on a live manager.

The expected paths are written out rather than read from the swagger file:
the swagger is 8MB of vendor input that is not part of the collection, and a
test that reads it would prove only that the code agrees with whatever file
happens to be on disk.

Three of CCKM's AWS operations are deliberately absent from this file --
``DELETE`` on a KMS container, a policy template and a custom key store.
Deletes go through ``cm_resource_delete`` in this collection, and
``tests/unit/modules/test_resource_type_routing.py`` pins the path each of
those resource types reaches. ``DELETE`` on a key is reachable both ways: the
key module needs it for its own ``delete`` operation.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_aws,
)
from module_harness import make_client

# Every path CCKM's AWS service serves, as published in its API definition,
# with {id} placeholders filled in. Written out deliberately.
ID = "res-1"

EXPECTED_PATHS = frozenset([
    "cckm/aws/accounts",
    "cckm/aws/alias/verify",
    "cckm/aws/bulkjob",
    "cckm/aws/bulkjob/res-1",
    "cckm/aws/bulkjob/res-1/cancel",
    "cckm/aws/create-hyok-key",
    "cckm/aws/custom-key-stores",
    "cckm/aws/custom-key-stores/get-unused-cloudhsm-clusters",
    "cckm/aws/custom-key-stores/synchronization-jobs",
    "cckm/aws/custom-key-stores/synchronization-jobs/res-1",
    "cckm/aws/custom-key-stores/synchronization-jobs/res-1/cancel",
    "cckm/aws/custom-key-stores/res-1",
    "cckm/aws/custom-key-stores/res-1/block",
    "cckm/aws/custom-key-stores/res-1/connect",
    "cckm/aws/custom-key-stores/res-1/create-aws-key",
    "cckm/aws/custom-key-stores/res-1/credentials",
    "cckm/aws/custom-key-stores/res-1/credentials/res-1",
    "cckm/aws/custom-key-stores/res-1/disable-credential-rotation-job",
    "cckm/aws/custom-key-stores/res-1/disconnect",
    "cckm/aws/custom-key-stores/res-1/enable-credential-rotation-job",
    "cckm/aws/custom-key-stores/res-1/health",
    "cckm/aws/custom-key-stores/res-1/link",
    "cckm/aws/custom-key-stores/res-1/rotate-credential",
    "cckm/aws/custom-key-stores/res-1/unblock",
    "cckm/aws/get-all-regions",
    "cckm/aws/get-iam-roles",
    "cckm/aws/get-iam-users",
    "cckm/aws/get-log-groups",
    "cckm/aws/keys",
    "cckm/aws/keys/res-1",
    "cckm/aws/keys/res-1/add-alias",
    "cckm/aws/keys/res-1/add-tags",
    "cckm/aws/keys/res-1/block",
    "cckm/aws/keys/res-1/cancel-deletion",
    "cckm/aws/keys/res-1/delete-alias",
    "cckm/aws/keys/res-1/delete-material",
    "cckm/aws/keys/res-1/disable",
    "cckm/aws/keys/res-1/disable-auto-rotation",
    "cckm/aws/keys/res-1/disable-rotation-job",
    "cckm/aws/keys/res-1/download-public-key",
    "cckm/aws/keys/res-1/enable",
    "cckm/aws/keys/res-1/enable-auto-rotation",
    "cckm/aws/keys/res-1/enable-rotation-job",
    "cckm/aws/keys/res-1/get-key-rotation-status",
    "cckm/aws/keys/res-1/import-material",
    "cckm/aws/keys/res-1/link",
    "cckm/aws/keys/res-1/policy",
    "cckm/aws/keys/res-1/refresh",
    "cckm/aws/keys/res-1/remove-tags",
    "cckm/aws/keys/res-1/replicate-key",
    "cckm/aws/keys/res-1/rotate",
    "cckm/aws/keys/res-1/rotate-material",
    "cckm/aws/keys/res-1/rotations",
    "cckm/aws/keys/res-1/schedule-deletion",
    "cckm/aws/keys/res-1/unblock",
    "cckm/aws/keys/res-1/update-description",
    "cckm/aws/keys/res-1/update-primary-region",
    "cckm/aws/keys/res-1/versions",
    "cckm/aws/kms",
    "cckm/aws/kms/res-1",
    "cckm/aws/kms/res-1/archive",
    "cckm/aws/kms/res-1/recover",
    "cckm/aws/kms/res-1/update-acls",
    "cckm/aws/reports",
    "cckm/aws/reports/res-1",
    "cckm/aws/reports/res-1/contents",
    "cckm/aws/reports/res-1/download",
    "cckm/aws/synchronization-jobs",
    "cckm/aws/synchronization-jobs/res-1",
    "cckm/aws/synchronization-jobs/res-1/cancel",
    "cckm/aws/templates",
    "cckm/aws/templates/res-1",
    "cckm/aws/upload-key",
    "cckm/aws/xks-proxy-endpoints/res-1/kms/xks/v1/health",
    "cckm/aws/xks-proxy-endpoints/res-1/kms/xks/v1/keys/res-1/decrypt",
    "cckm/aws/xks-proxy-endpoints/res-1/kms/xks/v1/keys/res-1/encrypt",
    "cckm/aws/xks-proxy-endpoints/res-1/kms/xks/v1/keys/res-1/metadata",
])

NODE = {"server_ip": "cm.example.com", "user": "admin", "password": "p"}

# Every public helper, with arguments sufficient to build its URL.
CALLS = [
    ("kms_create", dict(name="n", account_id="1", connection="c",
                        regions=["us-east-1"])),
    ("kms_patch", dict(kms_id=ID)),
    ("kms_get", dict(kms_id=ID)),
    ("kms_list", dict()),
    ("kms_action", dict(kms_id=ID, action="archive")),
    ("kms_action", dict(kms_id=ID, action="recover")),
    ("kms_update_acls", dict(kms_id=ID, acls=[])),

    ("key_create", dict(kms="k", region="r")),
    ("key_upload", dict(kms="k", region="r", source_key_identifier="s")),
    ("key_create_hyok", dict()),
    ("key_create_in_custom_key_store",
     dict(custom_key_store_id=ID, aws_param={"alias": "a"})),
    ("key_replicate", dict(key_id=ID, replica_region="r")),
    ("key_get", dict(key_id=ID)),
    ("key_list", dict()),
    ("key_versions", dict(key_id=ID)),
    ("key_rotations", dict(key_id=ID)),
    ("key_download_public_key", dict(key_id=ID)),
    ("key_delete", dict(key_id=ID)),

    ("template_create", dict(name="n")),
    ("template_patch", dict(template_id=ID)),
    ("template_get", dict(template_id=ID)),
    ("template_list", dict()),

    ("custom_key_store_create",
     dict(name="n", kms="k", region="r", aws_param={})),
    ("custom_key_store_patch", dict(custom_key_store_id=ID)),
    ("custom_key_store_get", dict(custom_key_store_id=ID)),
    ("custom_key_store_list", dict()),
    ("custom_key_store_health", dict(custom_key_store_id=ID)),
    ("custom_key_store_credentials_list", dict(custom_key_store_id=ID)),
    ("custom_key_store_credential_get",
     dict(custom_key_store_id=ID, credential_id=ID)),
    ("custom_key_store_credential_delete",
     dict(custom_key_store_id=ID, credential_id=ID)),
    ("unused_cloudhsm_clusters", dict(kms="k", region="r")),

    ("sync_start", dict(scope="keys")),
    ("sync_start", dict(scope="custom-key-stores")),
    ("sync_list", dict(scope="keys")),
    ("sync_list", dict(scope="custom-key-stores")),
    ("sync_get", dict(scope="keys", job_id=ID)),
    ("sync_get", dict(scope="custom-key-stores", job_id=ID)),
    ("sync_cancel", dict(scope="keys", job_id=ID)),
    ("sync_cancel", dict(scope="custom-key-stores", job_id=ID)),

    ("bulkjob_create", dict(keys=[ID], operation="enablekey")),
    ("bulkjob_list", dict()),
    ("bulkjob_get", dict(job_id=ID)),
    ("bulkjob_cancel", dict(job_id=ID)),

    ("report_create", dict(name="n", cloud_watch_params=[])),
    ("report_list", dict()),
    ("report_get", dict(report_id=ID)),
    ("report_contents", dict(report_id=ID)),
    ("report_download", dict(report_id=ID)),
    ("report_delete", dict(report_id=ID)),

    ("accounts_list", dict(connection="c")),
    ("regions_list", dict(connection="c")),
    ("iam_roles_list", dict(kms="k")),
    ("iam_users_list", dict(kms="k")),
    ("log_groups_list", dict(kms="k", region="r")),
    ("verify_alias", dict(alias="a", region="r", kms="k")),

    ("xks_health", dict(keystore_id=ID, request_metadata={})),
    ("xks_key_metadata",
     dict(keystore_id=ID, xks_key_id=ID, request_metadata={})),
    ("xks_encrypt", dict(keystore_id=ID, xks_key_id=ID, plaintext="p",
                         encryption_algorithm="AES_GCM_256",
                         request_metadata={})),
    ("xks_decrypt", dict(keystore_id=ID, xks_key_id=ID, ciphertext="c",
                         encryption_algorithm="AES_GCM_256",
                         initialization_vector="iv", authentication_tag="t",
                         request_metadata={})),
]

# The two action dispatchers build a URL per action name, so every name in
# their whitelist is exercised -- that is where a hyphen/underscore slip in an
# action name would otherwise reach a live manager as a 404.
CALLS += [("key_action", dict(key_id=ID, action=action))
          for action in sorted(cckm_aws.KEY_ACTIONS)]
CALLS += [("custom_key_store_action",
           dict(custom_key_store_id=ID, action=action))
          for action in sorted(cckm_aws.CUSTOM_KEY_STORE_ACTIONS)]

IDS = ["%s(%s)" % (name, ",".join(sorted(kwargs))) for name, kwargs in CALLS]


def _urls_from(monkeypatch, fn_name, kwargs):
    """Every URL the helper requests, with the query string stripped."""
    client = make_client()
    monkeypatch.setattr(cckm_aws, "CipherTrustClient", lambda node: client)
    getattr(cckm_aws, fn_name)(node=NODE, **kwargs)

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
            "%s targets %r, which CCKM's AWS API does not serve" % (fn_name, url))


def test_every_public_helper_is_covered():
    """A helper added without a case here would go unchecked."""
    import inspect

    public = {
        name for name, obj in vars(cckm_aws).items()
        if inspect.isfunction(obj)
        and obj.__module__ == cckm_aws.__name__
        and not name.startswith("_")
        # payload helpers, not request helpers
        and name not in ("prune", "remap_keys", "aws_key_params")
    }
    covered = {name for name, _ in CALLS}
    assert not public - covered, (
        "request helpers with no endpoint check: %s" % sorted(public - covered))


class TestIdentifiersCannotEscapeTheirPath:
    """Ids come from playbooks. One containing ``/`` or ``?`` must stay inside
    its own path segment rather than redirecting the request."""

    def test_a_traversing_key_id_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_get",
                          dict(key_id="../../vault/keys2/admin"))
        assert urls == ["cckm/aws/keys/..%2F..%2Fvault%2Fkeys2%2Fadmin"]

    def test_a_traversing_action_target_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_action",
                          dict(key_id="a/b", action="disable"))
        assert urls == ["cckm/aws/keys/a%2Fb/disable"]

    def test_a_query_injecting_id_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "kms_get", dict(kms_id="a?b=c"))
        assert urls == ["cckm/aws/kms/a%3Fb%3Dc"]
