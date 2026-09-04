# -*- coding: utf-8 -*-
"""Every CCKM Azure request must reach a path the API actually serves.

The counterpart of ``test_cckm_aws_endpoints`` and written the same way: the
set of paths this collection can build must be a subset of the paths CCKM
publishes, so a typo in an endpoint constant -- ``bulkjob`` for ``bulkjobs``,
``synchronization-job`` for ``synchronization-jobs`` -- is caught here rather
than by a 404 on a live manager.

The expected paths are written out rather than read from the swagger file, for
the reason the AWS test gives: the swagger is vendor input that is not part of
the collection, and a test that read it would prove only that the code agrees
with whichever file happens to be on disk.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_azure,
)
from module_harness import make_client
from test_helpers import TEST_NODE as NODE

ID = "res-1"
BACKUP_ID = "bak-1"

# Every path CCKM's Azure service serves, with {id} placeholders filled in.
EXPECTED_PATHS = frozenset([
    "cckm/azure/add-vaults",
    "cckm/azure/bulkjobs",
    "cckm/azure/bulkjobs/res-1",
    "cckm/azure/bulkjobs/res-1/cancel",
    "cckm/azure/certificates",
    "cckm/azure/certificates/import",
    "cckm/azure/certificates/res-1",
    "cckm/azure/certificates/res-1/hard-delete",
    "cckm/azure/certificates/res-1/recover",
    "cckm/azure/certificates/res-1/restore",
    "cckm/azure/certificates/res-1/soft-delete",
    "cckm/azure/certificates/synchronization-jobs",
    "cckm/azure/certificates/synchronization-jobs/res-1",
    "cckm/azure/certificates/synchronization-jobs/res-1/cancel",
    "cckm/azure/get-managed-hsms",
    "cckm/azure/get-subscriptions",
    "cckm/azure/get-vaults",
    "cckm/azure/key-templates",
    "cckm/azure/key-templates/res-1",
    "cckm/azure/keys",
    "cckm/azure/keys/res-1",
    "cckm/azure/keys/res-1/backups",
    "cckm/azure/keys/res-1/backups/bak-1",
    "cckm/azure/keys/res-1/delete-backup",
    "cckm/azure/keys/res-1/disable-backup-job",
    "cckm/azure/keys/res-1/disable-rotation-job",
    "cckm/azure/keys/res-1/download-public-key",
    "cckm/azure/keys/res-1/enable-backup-job",
    "cckm/azure/keys/res-1/enable-rotation-job",
    "cckm/azure/keys/res-1/hard-delete",
    "cckm/azure/keys/res-1/recover",
    "cckm/azure/keys/res-1/refresh",
    "cckm/azure/keys/res-1/restore",
    "cckm/azure/keys/res-1/soft-delete",
    "cckm/azure/reports",
    "cckm/azure/reports/res-1",
    "cckm/azure/reports/res-1/contents",
    "cckm/azure/reports/res-1/download",
    "cckm/azure/secrets",
    "cckm/azure/secrets/res-1",
    "cckm/azure/secrets/res-1/hard-delete",
    "cckm/azure/secrets/res-1/recover",
    "cckm/azure/secrets/res-1/restore",
    "cckm/azure/secrets/res-1/soft-delete",
    "cckm/azure/secrets/synchronization-jobs",
    "cckm/azure/secrets/synchronization-jobs/res-1",
    "cckm/azure/secrets/synchronization-jobs/res-1/cancel",
    "cckm/azure/subscriptions",
    "cckm/azure/subscriptions/res-1",
    "cckm/azure/synchronization-jobs",
    "cckm/azure/synchronization-jobs/res-1",
    "cckm/azure/synchronization-jobs/res-1/cancel",
    "cckm/azure/upload-key",
    "cckm/azure/vaults",
    "cckm/azure/vaults/res-1",
    "cckm/azure/vaults/res-1/disable-rotation-job",
    "cckm/azure/vaults/res-1/enable-rotation-job",
    "cckm/azure/vaults/res-1/remove-vault",
    "cckm/azure/vaults/res-1/update-acls",
])

CALLS = [
    ("vault_add", dict(connection="c", subscription_id="s", vaults=[])),
    ("vault_patch", dict(vault_id=ID, connection="c")),
    ("vault_get", dict(vault_id=ID)),
    ("vault_list", dict()),
    ("vault_action", dict(vault_id=ID, action="enable-rotation-job")),
    ("vault_action", dict(vault_id=ID, action="disable-rotation-job")),
    ("vault_action", dict(vault_id=ID, action="remove-vault")),
    ("vault_update_acls", dict(vault_id=ID, acls=[])),
    ("vaults_available", dict(connection="c", subscription_id="s")),
    ("managed_hsms_available", dict(connection="c", subscription_id="s")),

    ("subscription_list", dict()),
    ("subscription_get", dict(subscription_id=ID)),
    ("subscription_delete", dict(subscription_id=ID)),
    ("subscriptions_available", dict(connection="c")),

    ("key_create", dict(key_name="k", key_vault="v", azure_param={"kty": "RSA"})),
    ("key_upload", dict(key_name="k", key_vault="v")),
    ("key_patch", dict(key_id=ID)),
    ("key_get", dict(key_id=ID)),
    ("key_list", dict()),
    ("key_action", dict(key_id=ID, action="soft-delete")),
    ("key_action", dict(key_id=ID, action="hard-delete")),
    ("key_action", dict(key_id=ID, action="recover")),
    ("key_action", dict(key_id=ID, action="restore")),
    ("key_action", dict(key_id=ID, action="refresh")),
    ("key_action", dict(key_id=ID, action="enable-rotation-job")),
    ("key_action", dict(key_id=ID, action="disable-rotation-job")),
    ("key_action", dict(key_id=ID, action="enable-backup-job")),
    ("key_action", dict(key_id=ID, action="disable-backup-job")),
    ("key_action", dict(key_id=ID, action="delete-backup")),
    ("key_download_public_key", dict(key_id=ID)),
    ("key_backup_create", dict(key_id=ID)),
    ("key_backup_list", dict(key_id=ID)),
    ("key_backup_get", dict(key_id=ID, backup_id=BACKUP_ID)),
    ("key_backup_patch", dict(key_id=ID, backup_id=BACKUP_ID)),
    ("key_backup_delete", dict(key_id=ID, backup_id=BACKUP_ID)),

    ("secret_create", dict(secret_name="s", key_vault="v",
                           azure_param={"value": "x"})),
    ("secret_patch", dict(secret_id=ID)),
    ("secret_get", dict(secret_id=ID)),
    ("secret_list", dict()),
    ("secret_delete", dict(secret_id=ID)),
    ("secret_action", dict(secret_id=ID, action="soft-delete")),
    ("secret_action", dict(secret_id=ID, action="hard-delete")),
    ("secret_action", dict(secret_id=ID, action="recover")),
    ("secret_action", dict(secret_id=ID, action="restore")),

    ("certificate_create", dict(cert_name="c", key_vault="v",
                                azure_param={"policy": {}})),
    ("certificate_import", dict(cert_name="c", key_vault="v")),
    ("certificate_patch", dict(certificate_id=ID)),
    ("certificate_get", dict(certificate_id=ID)),
    ("certificate_list", dict()),
    ("certificate_delete", dict(certificate_id=ID)),
    ("certificate_action", dict(certificate_id=ID, action="soft-delete")),
    ("certificate_action", dict(certificate_id=ID, action="hard-delete")),
    ("certificate_action", dict(certificate_id=ID, action="recover")),
    ("certificate_action", dict(certificate_id=ID, action="restore")),

    ("report_create", dict(name="n", report_type="key-report",
                           log_analytic_params=[])),
    ("report_get", dict(report_id=ID)),
    ("report_list", dict()),
    ("report_delete", dict(report_id=ID)),
    ("report_contents", dict(report_id=ID)),
    ("report_download", dict(report_id=ID)),

    ("bulkjob_create", dict(operation="delete-key-backups")),
    ("bulkjob_get", dict(job_id=ID)),
    ("bulkjob_list", dict()),
    ("bulkjob_delete", dict(job_id=ID)),
    ("bulkjob_cancel", dict(job_id=ID)),
]
for _scope in ("keys", "certificates", "secrets"):
    CALLS += [
        ("sync_start", dict(scope=_scope)),
        ("sync_get", dict(scope=_scope, job_id=ID)),
        ("sync_list", dict(scope=_scope)),
        ("sync_cancel", dict(scope=_scope, job_id=ID)),
    ]


def _label(name, kwargs):
    """A readable test id: the helper, plus whatever selects a variant."""
    parts = ["%s=%s" % (k, v) for k, v in sorted(kwargs.items())
             if k in ("action", "scope")]
    return "%s(%s)" % (name, ",".join(parts) or "-")


IDS = [_label(name, kw) for name, kw in CALLS]


def _urls_from(monkeypatch, fn_name, kwargs):
    """Every URL the helper requests, with the query string stripped."""
    client = make_client()
    monkeypatch.setattr(cckm_azure, "CipherTrustClient", lambda node: client)
    getattr(cckm_azure, fn_name)(node=NODE, **kwargs)

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
            "%s targets %r, which CCKM's Azure API does not serve"
            % (fn_name, url))


def test_every_public_helper_is_covered():
    """A helper added without a case here would go unchecked."""
    import inspect

    public = {
        name for name, obj in vars(cckm_azure).items()
        if inspect.isfunction(obj)
        and obj.__module__ == cckm_azure.__name__
        and not name.startswith("_")
    }
    covered = {name for name, _kwargs in CALLS}
    assert not public - covered, (
        "request helpers with no endpoint check: %s" % sorted(public - covered))


def test_every_action_in_a_whitelist_is_exercised():
    """A whitelisted action that no case covers could name a path that 404s."""
    exercised = {kw["action"] for name, kw in CALLS if "action" in kw}
    declared = (cckm_azure.VAULT_ACTIONS | cckm_azure.KEY_ACTIONS
                | cckm_azure.SECRET_ACTIONS | cckm_azure.CERTIFICATE_ACTIONS)
    assert not declared - exercised, (
        "whitelisted actions with no endpoint check: %s"
        % sorted(declared - exercised))


class TestIdentifiersCannotEscapeTheirPath:
    """Ids come from playbooks. One containing ``/`` or ``?`` must stay inside
    its own path segment rather than redirecting the request."""

    def test_a_traversing_key_id_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_get",
                          dict(key_id="../../vault/keys2/admin"))
        assert urls == ["cckm/azure/keys/..%2F..%2Fvault%2Fkeys2%2Fadmin"]

    def test_a_traversing_action_target_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_action",
                          dict(key_id="a/b", action="refresh"))
        assert urls == ["cckm/azure/keys/a%2Fb/refresh"]

    def test_a_traversing_backup_id_is_encoded(self, monkeypatch):
        urls = _urls_from(monkeypatch, "key_backup_get",
                          dict(key_id="k", backup_id="../../keys"))
        assert urls == ["cckm/azure/keys/k/backups/..%2F..%2Fkeys"]


class TestUnsupportedNamesAreRejected:
    """Action and scope names form part of a URL, so they are whitelisted."""

    @pytest.mark.parametrize("fn_name,kwargs", [
        ("key_action", dict(key_id=ID, action="purge")),
        ("secret_action", dict(secret_id=ID, action="refresh")),
        ("certificate_action", dict(certificate_id=ID, action="rotate")),
        ("vault_action", dict(vault_id=ID, action="delete")),
    ])
    def test_an_unknown_action_is_refused(self, monkeypatch, fn_name, kwargs):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
            AnsibleCMParameterException,
        )
        with pytest.raises(AnsibleCMParameterException):
            _urls_from(monkeypatch, fn_name, kwargs)

    def test_an_unknown_sync_scope_is_refused(self, monkeypatch):
        from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
            AnsibleCMParameterException,
        )
        with pytest.raises(AnsibleCMParameterException):
            _urls_from(monkeypatch, "sync_list", dict(scope="vaults"))
