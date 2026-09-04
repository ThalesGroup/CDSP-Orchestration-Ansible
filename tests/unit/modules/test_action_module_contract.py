# -*- coding: utf-8 -*-
"""Contract for the action-style modules.

These modules perform an operation rather than converging on a desired state,
so the contract is different from the save modules: the right verb must reach
the right endpoint, ``--check`` must not perform the action, and a CM error
must surface through ``fail_json``.

As with the save-module contract, only the HTTP client is faked -- the URL
under assertion is the one the collection would really request.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)
from module_harness import make_client, run_main


class Action(object):
    def __init__(self, module, params, verb, endpoint, writes=True,
                 get_response=None, label=None):
        self.module = module
        self.params = params
        self.verb = verb
        self.endpoint = endpoint
        self.writes = writes            # False for read-only operations
        self.get_response = get_response
        self.label = label or "{0}:{1}".format(
            module, params.get("op_type", "run"))

    def __repr__(self):
        return self.label


IFACE = "configs/interfaces/iface-1"

# CCKM AWS. The action name is part of the URL, and several of these are
# destructive in ways their neighbours are not -- schedule-deletion against
# AWS versus a DELETE of CCKM's own record, disable versus block -- so the
# path each op_type reaches is written out here rather than derived from the
# module's own tables.
AWS_KEY = "cckm/aws/keys/key-1"
AWS_CKS = "cckm/aws/custom-key-stores/cks-1"

_KEY_PARAMS = {"key_id": "key-1"}


def _key_action(op_type, endpoint, extra=None, verb="post", writes=True):
    params = dict(_KEY_PARAMS, op_type=op_type)
    params.update(extra or {})
    return Action("cckm_aws_key", params, verb, endpoint, writes=writes,
                  label="cckm_aws_key:" + op_type)


CCKM_AWS_ACTIONS = [
    # -- keys: creation and the operations that reach AWS ------------------
    Action("cckm_aws_key",
           {"op_type": "create", "kms": "aws-prod", "region": "us-east-1"},
           "post", "cckm/aws/keys", label="cckm_aws_key:create"),
    Action("cckm_aws_key",
           {"op_type": "upload", "kms": "aws-prod", "region": "us-east-1",
            "source_key_identifier": "src-1"},
           "post", "cckm/aws/upload-key", label="cckm_aws_key:upload"),
    Action("cckm_aws_key",
           {"op_type": "create_hyok"},
           "post", "cckm/aws/create-hyok-key", label="cckm_aws_key:create_hyok"),
    Action("cckm_aws_key",
           {"op_type": "create_in_custom_key_store",
            "custom_key_store_id": "cks-1",
            "aws_param": {"alias": "a"}},
           "post", AWS_CKS + "/create-aws-key",
           label="cckm_aws_key:create_in_custom_key_store"),

    # -- keys: per-key actions ---------------------------------------------
    _key_action("add_alias", AWS_KEY + "/add-alias", {"alias": "a"}),
    _key_action("delete_alias", AWS_KEY + "/delete-alias", {"alias": "a"}),
    _key_action("add_tags", AWS_KEY + "/add-tags",
                {"tags": [{"tag_key": "k", "tag_value": "v"}]}),
    _key_action("remove_tags", AWS_KEY + "/remove-tags", {"tag_keys": ["k"]}),
    _key_action("block", AWS_KEY + "/block"),
    _key_action("unblock", AWS_KEY + "/unblock"),
    _key_action("enable", AWS_KEY + "/enable"),
    _key_action("disable", AWS_KEY + "/disable"),
    _key_action("schedule_deletion", AWS_KEY + "/schedule-deletion", {"days": 30}),
    _key_action("cancel_deletion", AWS_KEY + "/cancel-deletion"),
    _key_action("delete_material", AWS_KEY + "/delete-material"),
    _key_action("import_material", AWS_KEY + "/import-material"),
    _key_action("rotate", AWS_KEY + "/rotate"),
    _key_action("rotate_material", AWS_KEY + "/rotate-material"),
    _key_action("enable_auto_rotation", AWS_KEY + "/enable-auto-rotation"),
    _key_action("disable_auto_rotation", AWS_KEY + "/disable-auto-rotation"),
    _key_action("enable_rotation_job", AWS_KEY + "/enable-rotation-job",
                {"job_config_id": "job-1"}),
    _key_action("disable_rotation_job", AWS_KEY + "/disable-rotation-job"),
    _key_action("refresh", AWS_KEY + "/refresh"),
    _key_action("link", AWS_KEY + "/link"),
    _key_action("update_policy", AWS_KEY + "/policy"),
    _key_action("update_description", AWS_KEY + "/update-description",
                {"description": "d"}),
    _key_action("update_primary_region", AWS_KEY + "/update-primary-region",
                {"primary_region": "us-east-1"}),
    _key_action("replicate", AWS_KEY + "/replicate-key",
                {"replica_region": "eu-west-1"}),
    # A DELETE of CCKM's record. Nothing in AWS is destroyed by this.
    _key_action("delete", AWS_KEY, verb="delete"),
    # Reads: they must not be treated as writes, so --check runs them.
    _key_action("get_rotation_status", AWS_KEY + "/get-key-rotation-status",
                writes=False),
    _key_action("download_public_key", AWS_KEY + "/download-public-key",
                verb="get", writes=False),

    # -- KMS containers -----------------------------------------------------
    Action("cckm_aws_kms",
           {"op_type": "create", "name": "aws-prod", "account_id": "1",
            "connection": "c", "regions": ["us-east-1"]},
           "post", "cckm/aws/kms", label="cckm_aws_kms:create"),
    Action("cckm_aws_kms", {"op_type": "archive", "kms_id": "kms-1"},
           "post", "cckm/aws/kms/kms-1/archive", label="cckm_aws_kms:archive"),
    Action("cckm_aws_kms", {"op_type": "recover", "kms_id": "kms-1"},
           "post", "cckm/aws/kms/kms-1/recover", label="cckm_aws_kms:recover"),
    Action("cckm_aws_kms",
           {"op_type": "update_acls", "kms_id": "kms-1",
            "acls": [{"group": "g", "actions": ["keycreate"]}]},
           "post", "cckm/aws/kms/kms-1/update-acls",
           label="cckm_aws_kms:update_acls"),

    # -- custom key stores --------------------------------------------------
    Action("cckm_aws_custom_key_store",
           {"op_type": "create", "name": "cks", "kms": "aws-prod",
            "region": "us-east-1", "aws_param": {"xks_proxy_uri_endpoint": "https://x"}},
           "post", "cckm/aws/custom-key-stores",
           label="cckm_aws_custom_key_store:create"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "connect", "custom_key_store_id": "cks-1"},
           "post", AWS_CKS + "/connect",
           label="cckm_aws_custom_key_store:connect"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "disconnect", "custom_key_store_id": "cks-1"},
           "post", AWS_CKS + "/disconnect",
           label="cckm_aws_custom_key_store:disconnect"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "block", "custom_key_store_id": "cks-1"},
           "post", AWS_CKS + "/block",
           label="cckm_aws_custom_key_store:block"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "unblock", "custom_key_store_id": "cks-1"},
           "post", AWS_CKS + "/unblock",
           label="cckm_aws_custom_key_store:unblock"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "link", "custom_key_store_id": "cks-1",
            "xks_proxy_uri_endpoint": "https://x"},
           "post", AWS_CKS + "/link",
           label="cckm_aws_custom_key_store:link"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "rotate_credential", "custom_key_store_id": "cks-1"},
           "post", AWS_CKS + "/rotate-credential",
           label="cckm_aws_custom_key_store:rotate_credential"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "enable_credential_rotation_job",
            "custom_key_store_id": "cks-1", "job_config_id": "job-1"},
           "post", AWS_CKS + "/enable-credential-rotation-job",
           label="cckm_aws_custom_key_store:enable_credential_rotation_job"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "disable_credential_rotation_job",
            "custom_key_store_id": "cks-1"},
           "post", AWS_CKS + "/disable-credential-rotation-job",
           label="cckm_aws_custom_key_store:disable_credential_rotation_job"),
    Action("cckm_aws_custom_key_store",
           {"op_type": "delete_credential", "custom_key_store_id": "cks-1",
            "credential_id": "cred-1"},
           "delete", AWS_CKS + "/credentials/cred-1",
           label="cckm_aws_custom_key_store:delete_credential"),

    # -- jobs ---------------------------------------------------------------
    Action("cckm_aws_synchronization_job",
           {"op_type": "create", "scope": "keys"},
           "post", "cckm/aws/synchronization-jobs",
           label="cckm_aws_synchronization_job:create-keys"),
    Action("cckm_aws_synchronization_job",
           {"op_type": "create", "scope": "custom-key-stores"},
           "post", "cckm/aws/custom-key-stores/synchronization-jobs",
           label="cckm_aws_synchronization_job:create-cks"),
    Action("cckm_aws_synchronization_job",
           {"op_type": "cancel", "scope": "keys", "job_id": "job-1"},
           "post", "cckm/aws/synchronization-jobs/job-1/cancel",
           label="cckm_aws_synchronization_job:cancel"),
    Action("cckm_aws_bulkjob",
           {"op_type": "create", "keys": ["key-1"], "operation": "disablekey"},
           "post", "cckm/aws/bulkjob", label="cckm_aws_bulkjob:create"),
    Action("cckm_aws_bulkjob", {"op_type": "cancel", "job_id": "job-1"},
           "post", "cckm/aws/bulkjob/job-1/cancel",
           label="cckm_aws_bulkjob:cancel"),
    Action("cckm_aws_report",
           {"op_type": "create", "name": "r",
            "cloud_watch_params": [{"kms": "aws-prod"}]},
           "post", "cckm/aws/reports", label="cckm_aws_report:create"),
    Action("cckm_aws_report", {"op_type": "delete", "report_id": "report-1"},
           "delete", "cckm/aws/reports/report-1",
           label="cckm_aws_report:delete"),

    # -- reads: none of these may be skipped under --check -----------------
    Action("cckm_aws_key_info", {"op_type": "get", "key_id": "key-1"},
           "get", AWS_KEY, writes=False, label="cckm_aws_key_info:get"),
    Action("cckm_aws_key_info", {"op_type": "versions", "key_id": "key-1"},
           "get", AWS_KEY + "/versions", writes=False,
           label="cckm_aws_key_info:versions"),
    Action("cckm_aws_key_info", {"op_type": "rotations", "key_id": "key-1"},
           "get", AWS_KEY + "/rotations", writes=False,
           label="cckm_aws_key_info:rotations"),
    Action("cckm_aws_kms_info", {"op_type": "get", "kms_id": "kms-1"},
           "get", "cckm/aws/kms/kms-1", writes=False,
           label="cckm_aws_kms_info:get"),
    Action("cckm_aws_policy_template_info",
           {"op_type": "get", "template_id": "tpl-1"},
           "get", "cckm/aws/templates/tpl-1", writes=False,
           label="cckm_aws_policy_template_info:get"),
    Action("cckm_aws_custom_key_store_info",
           {"op_type": "get", "custom_key_store_id": "cks-1"},
           "get", AWS_CKS, writes=False,
           label="cckm_aws_custom_key_store_info:get"),
    Action("cckm_aws_custom_key_store_info",
           {"op_type": "health", "custom_key_store_id": "cks-1"},
           "get", AWS_CKS + "/health", writes=False,
           label="cckm_aws_custom_key_store_info:health"),
    Action("cckm_aws_custom_key_store_info",
           {"op_type": "list_credentials", "custom_key_store_id": "cks-1"},
           "get", AWS_CKS + "/credentials", writes=False,
           label="cckm_aws_custom_key_store_info:list_credentials"),
    Action("cckm_aws_custom_key_store_info",
           {"op_type": "get_credential", "custom_key_store_id": "cks-1",
            "credential_id": "cred-1"},
           "get", AWS_CKS + "/credentials/cred-1", writes=False,
           label="cckm_aws_custom_key_store_info:get_credential"),
    Action("cckm_aws_bulkjob_info", {"op_type": "get", "job_id": "job-1"},
           "get", "cckm/aws/bulkjob/job-1", writes=False,
           label="cckm_aws_bulkjob_info:get"),
    Action("cckm_aws_synchronization_job_info",
           {"op_type": "get", "scope": "custom-key-stores", "job_id": "job-1"},
           "get", "cckm/aws/custom-key-stores/synchronization-jobs/job-1",
           writes=False, label="cckm_aws_synchronization_job_info:get-cks"),
    Action("cckm_aws_report_info", {"op_type": "get", "report_id": "report-1"},
           "get", "cckm/aws/reports/report-1", writes=False,
           label="cckm_aws_report_info:get"),
    Action("cckm_aws_report_info",
           {"op_type": "contents", "report_id": "report-1"},
           "get", "cckm/aws/reports/report-1/contents", writes=False,
           label="cckm_aws_report_info:contents"),
    Action("cckm_aws_report_info",
           {"op_type": "download", "report_id": "report-1"},
           "get", "cckm/aws/reports/report-1/download", writes=False,
           label="cckm_aws_report_info:download"),

    # Discovery. These POST because they carry a body, but they read AWS and
    # change nothing, so they too must run under --check.
    Action("cckm_aws_account_info",
           {"op_type": "accounts", "connection": "conn-1"},
           "post", "cckm/aws/accounts", writes=False,
           label="cckm_aws_account_info:accounts"),
    Action("cckm_aws_account_info",
           {"op_type": "regions", "connection": "conn-1"},
           "post", "cckm/aws/get-all-regions", writes=False,
           label="cckm_aws_account_info:regions"),
    Action("cckm_aws_account_info",
           {"op_type": "iam_roles", "kms": "aws-prod"},
           "post", "cckm/aws/get-iam-roles", writes=False,
           label="cckm_aws_account_info:iam_roles"),
    Action("cckm_aws_account_info",
           {"op_type": "iam_users", "kms": "aws-prod"},
           "post", "cckm/aws/get-iam-users", writes=False,
           label="cckm_aws_account_info:iam_users"),
    Action("cckm_aws_account_info",
           {"op_type": "log_groups", "kms": "aws-prod", "region": "us-east-1"},
           "post", "cckm/aws/get-log-groups", writes=False,
           label="cckm_aws_account_info:log_groups"),
    Action("cckm_aws_alias_info",
           {"alias": "a", "region": "us-east-1", "kms": "aws-prod"},
           "post", "cckm/aws/alias/verify", writes=False,
           label="cckm_aws_alias_info:verify"),
    Action("cckm_aws_cloudhsm_cluster_info",
           {"kms": "aws-prod", "region": "us-east-1"},
           "post", "cckm/aws/custom-key-stores/get-unused-cloudhsm-clusters",
           writes=False, label="cckm_aws_cloudhsm_cluster_info:list"),

    # XKS proxy: diagnostics against a local key store. None of them changes
    # state, so all four run under --check.
    Action("cckm_aws_xks_proxy",
           {"op_type": "health", "keystore_id": "cks-1",
            "request_metadata": {"kms_request_id": "req-1"}},
           "post", "cckm/aws/xks-proxy-endpoints/cks-1/kms/xks/v1/health",
           writes=False, label="cckm_aws_xks_proxy:health"),
    Action("cckm_aws_xks_proxy",
           {"op_type": "metadata", "keystore_id": "cks-1", "xks_key_id": "xks-1",
            "request_metadata": {"kms_request_id": "req-1"}},
           "post",
           "cckm/aws/xks-proxy-endpoints/cks-1/kms/xks/v1/keys/xks-1/metadata",
           writes=False, label="cckm_aws_xks_proxy:metadata"),
    Action("cckm_aws_xks_proxy",
           {"op_type": "encrypt", "keystore_id": "cks-1", "xks_key_id": "xks-1",
            "plaintext": "cGxhaW4=", "encryption_algorithm": "AES_GCM_256",
            "request_metadata": {"kms_request_id": "req-1"}},
           "post",
           "cckm/aws/xks-proxy-endpoints/cks-1/kms/xks/v1/keys/xks-1/encrypt",
           writes=False, label="cckm_aws_xks_proxy:encrypt"),
    Action("cckm_aws_xks_proxy",
           {"op_type": "decrypt", "keystore_id": "cks-1", "xks_key_id": "xks-1",
            "ciphertext": "Y2lwaGVy", "encryption_algorithm": "AES_GCM_256",
            "initialization_vector": "aXY=", "authentication_tag": "dGFn",
            "request_metadata": {"kms_request_id": "req-1"}},
           "post",
           "cckm/aws/xks-proxy-endpoints/cks-1/kms/xks/v1/keys/xks-1/decrypt",
           writes=False, label="cckm_aws_xks_proxy:decrypt"),

    # ---- CCKM Azure ---------------------------------------------------
    Action("cckm_azure_vault",
           {'op_type': 'add', 'connection': 'c', 'subscription_id': 's', 'vaults': []},
           "post", "cckm/azure/add-vaults"),
    Action("cckm_azure_vault",
           {'op_type': 'patch', 'vault_id': 'res-1', 'connection': 'c', 'cloud_key_backup_limit': 5},
           "patch", "cckm/azure/vaults/res-1"),
    Action("cckm_azure_vault",
           {'op_type': 'enable_rotation_job', 'vault_id': 'res-1', 'job_config_id': 'j'},
           "post", "cckm/azure/vaults/res-1/enable-rotation-job"),
    Action("cckm_azure_vault",
           {'op_type': 'disable_rotation_job', 'vault_id': 'res-1'},
           "post", "cckm/azure/vaults/res-1/disable-rotation-job"),
    Action("cckm_azure_vault",
           {'op_type': 'remove_vault', 'vault_id': 'res-1'},
           "post", "cckm/azure/vaults/res-1/remove-vault"),
    Action("cckm_azure_vault",
           {'op_type': 'update_acls', 'vault_id': 'res-1', 'acls': []},
           "post", "cckm/azure/vaults/res-1/update-acls"),
    Action("cckm_azure_key",
           {'op_type': 'create', 'key_name': 'k', 'key_vault': 'v', 'azure_param': {'kty': 'RSA'}},
           "post", "cckm/azure/keys"),
    Action("cckm_azure_key",
           {'op_type': 'upload', 'key_name': 'k', 'key_vault': 'v'},
           "post", "cckm/azure/upload-key"),
    Action("cckm_azure_key",
           {'op_type': 'patch', 'key_id': 'res-1', 'tags': {'a': 'b'}},
           "patch", "cckm/azure/keys/res-1"),
    Action("cckm_azure_key",
           {'op_type': 'soft_delete', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/soft-delete"),
    Action("cckm_azure_key",
           {'op_type': 'hard_delete', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/hard-delete"),
    Action("cckm_azure_key",
           {'op_type': 'recover', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/recover"),
    Action("cckm_azure_key",
           {'op_type': 'restore', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/restore"),
    Action("cckm_azure_key",
           {'op_type': 'refresh', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/refresh"),
    Action("cckm_azure_key",
           {'op_type': 'disable_rotation_job', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/disable-rotation-job"),
    Action("cckm_azure_key",
           {'op_type': 'disable_backup_job', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/disable-backup-job"),
    Action("cckm_azure_key",
           {'op_type': 'delete_backups', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/delete-backup"),
    Action("cckm_azure_key",
           {'op_type': 'enable_rotation_job', 'key_id': 'res-1', 'job_config_id': 'j', 'auto_rotate_key_source': 'native', 'auto_rotate_key_type': 'RSA'},
           "post", "cckm/azure/keys/res-1/enable-rotation-job"),
    Action("cckm_azure_key",
           {'op_type': 'enable_backup_job', 'key_id': 'res-1', 'backup_job_config_id': 'b'},
           "post", "cckm/azure/keys/res-1/enable-backup-job"),
    Action("cckm_azure_key",
           {'op_type': 'create_backup', 'key_id': 'res-1'},
           "post", "cckm/azure/keys/res-1/backups"),
    Action("cckm_azure_key",
           {'op_type': 'patch_backup', 'key_id': 'res-1', 'backup_id': 'b1'},
           "patch", "cckm/azure/keys/res-1/backups/b1"),
    Action("cckm_azure_key",
           {'op_type': 'delete_backup', 'key_id': 'res-1', 'backup_id': 'b1'},
           "delete", "cckm/azure/keys/res-1/backups/b1"),
    Action("cckm_azure_secret",
           {'op_type': 'create', 'secret_name': 's', 'key_vault': 'v', 'azure_param': {'value': 'x'}},
           "post", "cckm/azure/secrets"),
    Action("cckm_azure_secret",
           {'op_type': 'patch', 'secret_id': 'res-1', 'tags': {'a': 'b'}},
           "patch", "cckm/azure/secrets/res-1"),
    Action("cckm_azure_secret",
           {'op_type': 'delete', 'secret_id': 'res-1'},
           "delete", "cckm/azure/secrets/res-1"),
    Action("cckm_azure_secret",
           {'op_type': 'soft_delete', 'secret_id': 'res-1'},
           "post", "cckm/azure/secrets/res-1/soft-delete"),
    Action("cckm_azure_secret",
           {'op_type': 'hard_delete', 'secret_id': 'res-1'},
           "post", "cckm/azure/secrets/res-1/hard-delete"),
    Action("cckm_azure_secret",
           {'op_type': 'recover', 'secret_id': 'res-1'},
           "post", "cckm/azure/secrets/res-1/recover"),
    Action("cckm_azure_secret",
           {'op_type': 'restore', 'secret_id': 'res-1'},
           "post", "cckm/azure/secrets/res-1/restore"),
    Action("cckm_azure_certificate",
           {'op_type': 'create', 'cert_name': 'c', 'key_vault': 'v', 'azure_param': {'policy': {}}},
           "post", "cckm/azure/certificates"),
    Action("cckm_azure_certificate",
           {'op_type': 'import', 'cert_name': 'c', 'key_vault': 'v'},
           "post", "cckm/azure/certificates/import"),
    Action("cckm_azure_certificate",
           {'op_type': 'patch', 'certificate_id': 'res-1', 'tags': {'a': 'b'}},
           "patch", "cckm/azure/certificates/res-1"),
    Action("cckm_azure_certificate",
           {'op_type': 'delete', 'certificate_id': 'res-1'},
           "delete", "cckm/azure/certificates/res-1"),
    Action("cckm_azure_certificate",
           {'op_type': 'soft_delete', 'certificate_id': 'res-1'},
           "post", "cckm/azure/certificates/res-1/soft-delete"),
    Action("cckm_azure_certificate",
           {'op_type': 'hard_delete', 'certificate_id': 'res-1'},
           "post", "cckm/azure/certificates/res-1/hard-delete"),
    Action("cckm_azure_certificate",
           {'op_type': 'recover', 'certificate_id': 'res-1'},
           "post", "cckm/azure/certificates/res-1/recover"),
    Action("cckm_azure_certificate",
           {'op_type': 'restore', 'certificate_id': 'res-1'},
           "post", "cckm/azure/certificates/res-1/restore"),
    Action("cckm_azure_subscription",
           {'op_type': 'delete', 'subscription_id': 'res-1'},
           "delete", "cckm/azure/subscriptions/res-1"),
    Action("cckm_azure_report",
           {'op_type': 'create', 'name': 'n', 'report_type': 'key-report', 'log_analytic_params': []},
           "post", "cckm/azure/reports"),
    Action("cckm_azure_report",
           {'op_type': 'delete', 'report_id': 'res-1'},
           "delete", "cckm/azure/reports/res-1"),
    Action("cckm_azure_bulkjob",
           {'op_type': 'create', 'operation': 'delete-key-backups'},
           "post", "cckm/azure/bulkjobs"),
    Action("cckm_azure_bulkjob",
           {'op_type': 'cancel', 'job_id': 'res-1'},
           "post", "cckm/azure/bulkjobs/res-1/cancel"),
    Action("cckm_azure_bulkjob",
           {'op_type': 'delete', 'job_id': 'res-1'},
           "delete", "cckm/azure/bulkjobs/res-1"),
    Action("cckm_azure_synchronization_job",
           {'op_type': 'start', 'scope': 'keys', 'synchronize_all': True},
           "post", "cckm/azure/synchronization-jobs",
           label="cckm_azure_synchronization_job:start-keys"),
    Action("cckm_azure_synchronization_job",
           {'op_type': 'cancel', 'scope': 'keys', 'job_id': 'res-1'},
           "post", "cckm/azure/synchronization-jobs/res-1/cancel",
           label="cckm_azure_synchronization_job:cancel-keys"),
    Action("cckm_azure_synchronization_job",
           {'op_type': 'start', 'scope': 'certificates', 'synchronize_all': True},
           "post", "cckm/azure/certificates/synchronization-jobs",
           label="cckm_azure_synchronization_job:start-certificates"),
    Action("cckm_azure_synchronization_job",
           {'op_type': 'cancel', 'scope': 'certificates', 'job_id': 'res-1'},
           "post", "cckm/azure/certificates/synchronization-jobs/res-1/cancel",
           label="cckm_azure_synchronization_job:cancel-certificates"),
    Action("cckm_azure_synchronization_job",
           {'op_type': 'start', 'scope': 'secrets', 'synchronize_all': True},
           "post", "cckm/azure/secrets/synchronization-jobs",
           label="cckm_azure_synchronization_job:start-secrets"),
    Action("cckm_azure_synchronization_job",
           {'op_type': 'cancel', 'scope': 'secrets', 'job_id': 'res-1'},
           "post", "cckm/azure/secrets/synchronization-jobs/res-1/cancel",
           label="cckm_azure_synchronization_job:cancel-secrets"),
    Action("cckm_azure_vault_info",
           {'op_type': 'list'},
           "get", "cckm/azure/vaults",
           writes=False),
    Action("cckm_azure_vault_info",
           {'op_type': 'get', 'vault_id': 'res-1'},
           "get", "cckm/azure/vaults/res-1",
           writes=False),
    Action("cckm_azure_vault_info",
           {'op_type': 'available', 'connection': 'c', 'subscription_id': 's'},
           "post", "cckm/azure/get-vaults",
           writes=False),
    Action("cckm_azure_vault_info",
           {'op_type': 'managed_hsms', 'connection': 'c', 'subscription_id': 's'},
           "post", "cckm/azure/get-managed-hsms",
           writes=False),
    Action("cckm_azure_key_info",
           {'op_type': 'list'},
           "get", "cckm/azure/keys",
           writes=False),
    Action("cckm_azure_key_info",
           {'op_type': 'get', 'key_id': 'res-1'},
           "get", "cckm/azure/keys/res-1",
           writes=False),
    Action("cckm_azure_key_info",
           {'op_type': 'list_backups', 'key_id': 'res-1'},
           "get", "cckm/azure/keys/res-1/backups",
           writes=False),
    Action("cckm_azure_key_info",
           {'op_type': 'get_backup', 'key_id': 'res-1', 'backup_id': 'b1'},
           "get", "cckm/azure/keys/res-1/backups/b1",
           writes=False),
    Action("cckm_azure_key_info",
           {'op_type': 'download_public_key', 'key_id': 'res-1'},
           "get", "cckm/azure/keys/res-1/download-public-key",
           writes=False),
    Action("cckm_azure_secret_info",
           {'op_type': 'list'},
           "get", "cckm/azure/secrets",
           writes=False),
    Action("cckm_azure_secret_info",
           {'op_type': 'get', 'secret_id': 'res-1'},
           "get", "cckm/azure/secrets/res-1",
           writes=False),
    Action("cckm_azure_certificate_info",
           {'op_type': 'list'},
           "get", "cckm/azure/certificates",
           writes=False),
    Action("cckm_azure_certificate_info",
           {'op_type': 'get', 'certificate_id': 'res-1'},
           "get", "cckm/azure/certificates/res-1",
           writes=False),
    Action("cckm_azure_subscription_info",
           {'op_type': 'list'},
           "get", "cckm/azure/subscriptions",
           writes=False),
    Action("cckm_azure_subscription_info",
           {'op_type': 'get', 'subscription_id': 'res-1'},
           "get", "cckm/azure/subscriptions/res-1",
           writes=False),
    Action("cckm_azure_subscription_info",
           {'op_type': 'available', 'connection': 'c'},
           "post", "cckm/azure/get-subscriptions",
           writes=False),
    Action("cckm_azure_report_info",
           {'op_type': 'list'},
           "get", "cckm/azure/reports",
           writes=False),
    Action("cckm_azure_report_info",
           {'op_type': 'get', 'report_id': 'res-1'},
           "get", "cckm/azure/reports/res-1",
           writes=False),
    Action("cckm_azure_report_info",
           {'op_type': 'contents', 'report_id': 'res-1'},
           "get", "cckm/azure/reports/res-1/contents",
           writes=False),
    Action("cckm_azure_report_info",
           {'op_type': 'download', 'report_id': 'res-1'},
           "get", "cckm/azure/reports/res-1/download",
           writes=False),
    Action("cckm_azure_bulkjob_info",
           {'op_type': 'list'},
           "get", "cckm/azure/bulkjobs",
           writes=False),
    Action("cckm_azure_bulkjob_info",
           {'op_type': 'get', 'job_id': 'res-1'},
           "get", "cckm/azure/bulkjobs/res-1",
           writes=False),
    Action("cckm_azure_synchronization_job_info",
           {'op_type': 'list', 'scope': 'keys'},
           "get", "cckm/azure/synchronization-jobs",
           writes=False),
    Action("cckm_azure_synchronization_job_info",
           {'op_type': 'get', 'scope': 'keys', 'job_id': 'res-1'},
           "get", "cckm/azure/synchronization-jobs/res-1",
           writes=False),

    # ---- CCKM Google Cloud --------------------------------------------
    Action("cckm_gcp_project",
           {'op_type': 'create', 'project_id': 'p'},
           "post", "cckm/google/projects"),
    Action("cckm_gcp_project",
           {'op_type': 'patch', 'gcp_project_id': 'res-1', 'enable_success_audit_event': True},
           "patch", "cckm/google/projects/res-1"),
    Action("cckm_gcp_project",
           {'op_type': 'delete', 'gcp_project_id': 'res-1'},
           "delete", "cckm/google/projects/res-1"),
    Action("cckm_gcp_project",
           {'op_type': 'update_acls', 'gcp_project_id': 'res-1', 'acls': []},
           "post", "cckm/google/projects/res-1/update-acls"),
    Action("cckm_gcp_key_ring",
           {'op_type': 'add', 'connection': 'c', 'project_id': 'p', 'key_rings': []},
           "post", "cckm/google/add-key-rings"),
    Action("cckm_gcp_key_ring",
           {'op_type': 'patch', 'key_ring_id': 'res-1', 'connection': 'c'},
           "patch", "cckm/google/key-rings/res-1"),
    Action("cckm_gcp_key_ring",
           {'op_type': 'update_acls', 'key_ring_id': 'res-1', 'acls': []},
           "post", "cckm/google/key-rings/res-1/update-acls"),
    Action("cckm_gcp_key_ring",
           {'op_type': 'remove', 'key_ring_id': 'res-1'},
           "post", "cckm/google/key-rings/res-1/remove-key-ring"),
    Action("cckm_gcp_key",
           {'op_type': 'create', 'key_ring': 'r', 'gcp_key_params': {'key_name': 'k'}},
           "post", "cckm/google/keys"),
    Action("cckm_gcp_key",
           {'op_type': 'upload', 'key_ring': 'r', 'gcp_key_params': {'key_name': 'k'}, 'source_key_id': 's', 'source_key_tier': 'local'},
           "post", "cckm/google/upload-key"),
    Action("cckm_gcp_key",
           {'op_type': 'patch', 'key_id': 'res-1', 'rotation_period': '90d'},
           "patch", "cckm/google/keys/res-1"),
    Action("cckm_gcp_key",
           {'op_type': 'set_policy', 'key_id': 'res-1', 'bindings': []},
           "post", "cckm/google/keys/res-1/policy"),
    Action("cckm_gcp_key",
           {'op_type': 'refresh', 'key_id': 'res-1'},
           "post", "cckm/google/keys/res-1/refresh"),
    Action("cckm_gcp_key",
           {'op_type': 'enable_auto_rotation',
            'key_id': 'res-1',
            'job_config_id': 'j',
            'auto_rotate_key_source': 'native',
            'auto_rotate_algorithm': 'HMAC_SHA256'},
           "post", "cckm/google/keys/res-1/enable-auto-rotation"),
    Action("cckm_gcp_key",
           {'op_type': 'disable_auto_rotation', 'key_id': 'res-1'},
           "post", "cckm/google/keys/res-1/disable-auto-rotation"),
    Action("cckm_gcp_key",
           {'op_type': 'create_version', 'key_id': 'res-1'},
           "post", "cckm/google/keys/res-1/versions"),
    Action("cckm_gcp_key",
           {'op_type': 'enable_version', 'key_id': 'res-1', 'version_id': 'ver-1'},
           "post", "cckm/google/keys/res-1/versions/ver-1/enable"),
    Action("cckm_gcp_key",
           {'op_type': 'disable_version', 'key_id': 'res-1', 'version_id': 'ver-1'},
           "post", "cckm/google/keys/res-1/versions/ver-1/disable"),
    Action("cckm_gcp_key",
           {'op_type': 'schedule_destroy_version', 'key_id': 'res-1', 'version_id': 'ver-1'},
           "post", "cckm/google/keys/res-1/versions/ver-1/schedule-destroy"),
    Action("cckm_gcp_key",
           {'op_type': 'cancel_schedule_destroy_version', 'key_id': 'res-1', 'version_id': 'ver-1'},
           "post", "cckm/google/keys/res-1/versions/ver-1/cancel-schedule-destroy"),
    Action("cckm_gcp_key",
           {'op_type': 'refresh_version', 'key_id': 'res-1', 'version_id': 'ver-1'},
           "post", "cckm/google/keys/res-1/versions/ver-1/refresh"),
    Action("cckm_gcp_key",
           {'op_type': 're_import_version', 'key_id': 'res-1', 'version_id': 'ver-1'},
           "post", "cckm/google/keys/res-1/versions/ver-1/re-import"),
    Action("cckm_gcp_key",
           {'op_type': 'download_public_key', 'key_id': 'res-1', 'version_id': 'ver-1'},
           "post", "cckm/google/keys/res-1/versions/ver-1/download-public-key"),
    Action("cckm_gcp_report",
           {'op_type': 'create', 'name': 'n', 'report_type': 'key-report', 'gcp_cloud_params': []},
           "post", "cckm/google/reports"),
    Action("cckm_gcp_report",
           {'op_type': 'delete', 'report_id': 'res-1'},
           "delete", "cckm/google/reports/res-1"),
    Action("cckm_gcp_synchronization_job",
           {'op_type': 'start', 'synchronize_all': True},
           "post", "cckm/google/synchronization-jobs"),
    Action("cckm_gcp_synchronization_job",
           {'op_type': 'cancel', 'job_id': 'res-1'},
           "post", "cckm/google/synchronization-jobs/res-1/cancel"),
    Action("cckm_gcp_update_all_versions_job",
           {'op_type': 'start', 'key_id': 'k', 'operation': 'disable'},
           "post", "cckm/google/update-all-versions-jobs"),
    Action("cckm_gcp_project_info",
           {'op_type': 'list'},
           "get", "cckm/google/projects",
           writes=False),
    Action("cckm_gcp_project_info",
           {'op_type': 'get', 'gcp_project_id': 'res-1'},
           "get", "cckm/google/projects/res-1",
           writes=False),
    Action("cckm_gcp_project_info",
           {'op_type': 'available', 'connection': 'c'},
           "post", "cckm/google/get-projects",
           writes=False),
    Action("cckm_gcp_project_info",
           {'op_type': 'locations', 'project_id': 'p'},
           "post", "cckm/google/get-locations",
           writes=False),
    Action("cckm_gcp_project_info",
           {'op_type': 'iam_roles', 'key_ring_id': 'res-1'},
           "post", "cckm/google/get-iam-roles",
           writes=False),
    Action("cckm_gcp_key_ring_info",
           {'op_type': 'list'},
           "get", "cckm/google/key-rings",
           writes=False),
    Action("cckm_gcp_key_ring_info",
           {'op_type': 'get', 'key_ring_id': 'res-1'},
           "get", "cckm/google/key-rings/res-1",
           writes=False),
    Action("cckm_gcp_key_ring_info",
           {'op_type': 'available', 'connection': 'c', 'project_id': 'p', 'location': 'l'},
           "post", "cckm/google/get-key-rings",
           writes=False),
    Action("cckm_gcp_key_info",
           {'op_type': 'list'},
           "get", "cckm/google/keys",
           writes=False),
    Action("cckm_gcp_key_info",
           {'op_type': 'get', 'key_id': 'res-1'},
           "get", "cckm/google/keys/res-1",
           writes=False),
    Action("cckm_gcp_key_info",
           {'op_type': 'list_versions', 'key_id': 'res-1'},
           "get", "cckm/google/keys/res-1/versions",
           writes=False),
    Action("cckm_gcp_key_info",
           {'op_type': 'get_version', 'key_id': 'res-1', 'version_id': 'ver-1'},
           "get", "cckm/google/keys/res-1/versions/ver-1",
           writes=False),
    Action("cckm_gcp_key_info",
           {'op_type': 'get_policy', 'key_id': 'res-1'},
           "get", "cckm/google/keys/res-1/policy",
           writes=False),
    Action("cckm_gcp_report_info",
           {'op_type': 'list'},
           "get", "cckm/google/reports",
           writes=False),
    Action("cckm_gcp_report_info",
           {'op_type': 'get', 'report_id': 'res-1'},
           "get", "cckm/google/reports/res-1",
           writes=False),
    Action("cckm_gcp_report_info",
           {'op_type': 'contents', 'report_id': 'res-1'},
           "get", "cckm/google/reports/res-1/contents",
           writes=False),
    Action("cckm_gcp_report_info",
           {'op_type': 'download', 'report_id': 'res-1'},
           "get", "cckm/google/reports/res-1/download",
           writes=False),
    Action("cckm_gcp_synchronization_job_info",
           {'op_type': 'list'},
           "get", "cckm/google/synchronization-jobs",
           writes=False),
    Action("cckm_gcp_synchronization_job_info",
           {'op_type': 'get', 'job_id': 'res-1'},
           "get", "cckm/google/synchronization-jobs/res-1",
           writes=False),
    Action("cckm_gcp_update_all_versions_job_info",
           {'op_type': 'get', 'job_id': 'res-1'},
           "get", "cckm/google/update-all-versions-jobs/res-1",
           writes=False),
]

ACTIONS = CCKM_AWS_ACTIONS + [
    Action("cm_services", {"op_type": "restart"},
           "post", "system/services/restart"),

    Action("group_add_remove_object",
           {"op_type": "add", "object_type": "user",
            "name": "grp-1", "object_id": "usr-1"},
           "post", "usermgmt/groups/grp-1/users/usr-1",
           get_response=CMApiException(message="not a member", api_error_code=404),
           label="group_add_remove_object:add-user"),
    Action("group_add_remove_object",
           {"op_type": "add", "object_type": "client",
            "name": "grp-1", "object_id": "cli-1"},
           "post", "client-management/groups/grp-1/clients/cli-1",
           get_response=CMApiException(message="not a member", api_error_code=404),
           label="group_add_remove_object:add-client"),
    Action("group_add_remove_object",
           {"op_type": "remove", "object_type": "user",
            "name": "grp-1", "object_id": "usr-1"},
           "delete", "usermgmt/groups/grp-1/users/usr-1"),
    Action("group_add_remove_object",
           {"op_type": "remove", "object_type": "client",
            "name": "grp-1", "object_id": "cli-1"},
           "delete", "client-management/groups/grp-1/clients/cli-1"),

    Action("interface_actions",
           {"op_type": "enable", "interface_id": "iface-1"},
           "post", IFACE + "/enable"),
    Action("interface_actions",
           {"op_type": "disable", "interface_id": "iface-1"},
           "post", IFACE + "/disable"),
    Action("interface_actions",
           {"op_type": "get_certificate", "interface_id": "iface-1"},
           "get", IFACE + "/certificate", writes=False),
    Action("interface_actions",
           {"op_type": "restore-default-tls-ciphers", "interface_id": "iface-1"},
           "post", IFACE + "/restore-default-tls-ciphers"),
    Action("interface_actions",
           {"op_type": "auto-gen-server-cert", "interface_id": "iface-1"},
           "post", IFACE + "/auto-gen-server-cert"),

    # Testing a stored connection is a read of the cloud provider's state:
    # it changes nothing in CipherTrust Manager, so it is not exempted from
    # running under --check.
    Action("connection_test", {"cloud": "aws", "connection_id": "conn-1"},
           "post", "connectionmgmt/services/aws/connections/conn-1/test",
           writes=False, label="connection_test:aws"),
    Action("connection_test", {"cloud": "azure", "connection_id": "conn-1"},
           "post", "connectionmgmt/services/azure/connections/conn-1/test",
           writes=False, label="connection_test:azure"),
    Action("connection_test", {"cloud": "gcp", "connection_id": "conn-1"},
           "post", "connectionmgmt/services/gcp/connections/conn-1/test",
           writes=False, label="connection_test:gcp"),
    Action("connection_test", {"cloud": "oci", "connection_id": "conn-1"},
           "post", "connectionmgmt/services/oci/connections/conn-1/test",
           writes=False, label="connection_test:oci"),

    Action("license_create", {"license_string": "LICENSE-BLOB"},
           "post", "licensing/licenses"),
    Action("license_trial_action",
           {"action_type": "activate", "trialId": "trial-1"},
           "post", "licensing/trials/trial-1/activate",
           label="license_trial_action:activate"),
    Action("license_trial_action",
           {"action_type": "deactivate", "trialId": "trial-1"},
           "post", "licensing/trials/trial-1/deactivate",
           label="license_trial_action:deactivate"),

    Action("license_trial_get", {"name": "trial"},
           "get", "licensing/trials", writes=False,
           get_response={"resources": [{"id": "trial-1", "status": "active"}]}),
    Action("licensing_lockdata_get", {},
           "get", "licensing/lockdata", writes=False),

    Action("cm_regtoken", {"op_type": "create", "name_prefix": "node"},
           "post", "client-management/regtokens"),

    Action("cm_cluster", {"op_type": "new"}, "post", "cluster/new",
           label="cm_cluster:new"),

    # resource_type selects the endpoint; check one of each family
    Action("cm_resource_delete",
           {"resource_type": "keys", "key": "key-1"},
           "delete", "vault/keys2/key-1", label="cm_resource_delete:keys"),
    Action("cm_resource_delete",
           {"resource_type": "users", "key": "usr-1"},
           "delete", "usermgmt/users/usr-1", label="cm_resource_delete:users"),

    Action("cm_resource_delete",
           {"resource_type": "cluster"},
           "delete", "cluster", label="cm_resource_delete:cluster"),

    Action("cm_resource_get_id_from_name",
           {"resource_type": "keys", "query_param": "name",
            "query_param_value": "my-key"},
           "get", "vault/keys2/?skip=0&limit=1&name=my-key", writes=False,
           get_response={"resources": [{"id": "key-1", "name": "my-key"}]},
           label="cm_resource_get_id_from_name:keys"),
]

WRITE_ACTIONS = [a for a in ACTIONS if a.writes]

all_actions = pytest.mark.parametrize(
    "action", ACTIONS, ids=[a.label for a in ACTIONS]
)
write_actions = pytest.mark.parametrize(
    "action", WRITE_ACTIONS, ids=[a.label for a in WRITE_ACTIONS]
)


def _client_for(action):
    return make_client(get=action.get_response)


@all_actions
class TestActionReachesTheRightEndpoint:

    def test_calls_expected_verb_and_endpoint(self, action):
        client = _client_for(action)
        result = run_main(action.module, action.params, client=client)

        assert not result.failed, result.msg
        called = getattr(client, action.verb)
        assert called.called, (
            "expected a %s; saw %s" % (action.verb.upper(), result.write_calls())
        )
        urls = [call[0][0] for call in called.call_args_list if call[0]]
        assert action.endpoint in urls, (
            "expected %s %s, saw %s" % (action.verb.upper(), action.endpoint, urls)
        )

    def test_api_error_becomes_fail_json(self, action):
        # PATCH is here too: an operation that patches without reading first
        # never touches the other verbs, so leaving it out let such an
        # operation pass this test without surfacing the error at all.
        client = make_client(
            get=CMApiException(message="Forbidden", api_error_code=403),
            post=CMApiException(message="Forbidden", api_error_code=403),
            patch_response=CMApiException(message="Forbidden", api_error_code=403),
            delete=CMApiException(message="Forbidden", api_error_code=403),
        )
        result = run_main(action.module, action.params, client=client)

        assert result.failed, "a CM error must fail the module cleanly"
        assert "403" in result.msg


@write_actions
class TestCheckModeMakesNoChange:

    def test_check_mode_does_not_act(self, action):
        client = _client_for(action)
        result = run_main(action.module, action.params,
                          client=client, check_mode=True)

        assert not result.failed, result.msg
        assert result.changed is True, "an action module reports changed in check mode"
        assert not result.wrote(), (
            "check mode performed a write: %s" % (result.write_calls(),)
        )


class TestResourceDeleteTargetsTheResource:
    """cm_resource_delete is documented as "delete resource using ID".

    Every keyed resource type must delete <endpoint>/<key> and never the bare
    collection endpoint; a missing key must be reported rather than silently
    widening the request.
    """

    @pytest.mark.parametrize("resource_type,endpoint", [
        ("keys", "vault/keys2"),
        ("users", "usermgmt/users"),
        ("interfaces", "configs/interfaces"),
        ("dpg-policies", "data-protection/dpg-policies"),
        ("access-policies", "data-protection/access-policies"),
    ])
    def test_deletes_the_named_resource_only(self, resource_type, endpoint):
        client = make_client()
        result = run_main("cm_resource_delete",
                          {"resource_type": resource_type, "key": "res-1"},
                          client=client)

        assert not result.failed, result.msg
        urls = [call[0][0] for call in client.delete.call_args_list if call[0]]
        assert urls == [endpoint + "/res-1"], (
            "must delete one resource, not the %s collection" % endpoint
        )

    def test_cluster_deletes_the_singleton_without_a_key(self):
        """resource_type: cluster has no per-resource id -- DELETE /cluster."""
        client = make_client()
        result = run_main("cm_resource_delete", {"resource_type": "cluster"},
                          client=client)

        assert not result.failed, result.msg
        urls = [call[0][0] for call in client.delete.call_args_list if call[0]]
        assert urls == ["cluster"]

    def test_missing_key_fails_in_check_mode_too(self):
        """--check must predict the failure a real run would hit."""
        client = make_client()
        result = run_main("cm_resource_delete", {"resource_type": "keys"},
                          client=client, check_mode=True)

        assert result.failed, "check mode reported success for a task that cannot run"
        assert "key" in result.msg
        assert not client.delete.called

    def test_missing_key_is_reported(self):
        client = make_client()
        result = run_main("cm_resource_delete",
                          {"resource_type": "keys"}, client=client)

        assert result.failed
        assert "key" in result.msg
        assert not client.delete.called, "no request may be sent without a key"


class TestGroupMembershipIsIdempotent:
    """Membership is addressable, so add and remove can report changed
    honestly instead of always claiming one."""

    MEMBER = {"op_type": "add", "object_type": "user",
              "name": "grp-1", "object_id": "usr-1"}
    NON_MEMBER = {"op_type": "remove", "object_type": "user",
                  "name": "grp-1", "object_id": "usr-1"}
    ABSENT = CMApiException(message="not a member", api_error_code=404)

    def test_adding_an_existing_member_makes_no_change(self):
        client = make_client(get={"id": "usr-1"})
        result = run_main("group_add_remove_object", self.MEMBER, client=client)

        assert not result.failed, result.msg
        assert result.changed is False
        assert not client.post.called, "re-added a user who is already a member"

    def test_adding_a_new_member_reports_changed(self):
        client = make_client(get=self.ABSENT)
        result = run_main("group_add_remove_object", self.MEMBER, client=client)

        assert result.changed is True
        assert client.post.called

    def test_removing_an_absent_member_makes_no_change(self):
        client = make_client(get=self.ABSENT)
        result = run_main("group_add_remove_object", self.NON_MEMBER, client=client)

        assert not result.failed, result.msg
        assert result.changed is False
        assert not client.delete.called, "deleted a membership that does not exist"

    def test_removing_an_existing_member_reports_changed(self):
        client = make_client(get={"id": "usr-1"})
        result = run_main("group_add_remove_object", self.NON_MEMBER, client=client)

        assert result.changed is True
        assert client.delete.called

    def test_acts_when_membership_cannot_be_determined(self):
        """A CM that will not answer must not cause the operation to be skipped."""
        client = make_client(
            get=CMApiException(message="method not allowed", api_error_code=405)
        )
        result = run_main("group_add_remove_object", self.MEMBER, client=client)

        assert result.changed is True
        assert client.post.called


class TestDeleteIsIdempotent:
    """Deleting something that is already gone is not a change, and must not
    fail the play. The resource is addressable at the URL the DELETE targets,
    so that is what decides."""

    PARAMS = {"resource_type": "keys", "key": "key-1"}
    ABSENT = CMApiException(message="not found", api_error_code=404)

    def test_deleting_an_existing_resource_reports_changed(self):
        client = make_client(get={"id": "key-1"})
        result = run_main("cm_resource_delete", self.PARAMS, client=client)

        assert not result.failed, result.msg
        assert result.changed is True
        assert client.delete.called

    def test_deleting_an_absent_resource_makes_no_change(self):
        client = make_client(get=self.ABSENT)
        result = run_main("cm_resource_delete", self.PARAMS, client=client)

        assert not result.failed, (
            "deleting an absent resource must not fail the play: %s" % result.msg
        )
        assert result.changed is False
        assert not client.delete.called

    def test_check_mode_does_not_delete(self):
        client = make_client(get={"id": "key-1"})
        result = run_main("cm_resource_delete", self.PARAMS,
                          client=client, check_mode=True)

        assert result.changed is True
        assert not client.delete.called

    def test_check_mode_predicts_no_change_for_an_absent_resource(self):
        client = make_client(get=self.ABSENT)
        result = run_main("cm_resource_delete", self.PARAMS,
                          client=client, check_mode=True)

        assert result.changed is False
        assert not client.delete.called

    def test_acts_when_existence_cannot_be_determined(self):
        client = make_client(
            get=CMApiException(message="forbidden", api_error_code=403)
        )
        result = run_main("cm_resource_delete", self.PARAMS, client=client)

        assert result.changed is True
        assert client.delete.called

    def test_cluster_delete_is_still_performed(self):
        """The cluster singleton has no addressable resource to test."""
        client = make_client()
        result = run_main("cm_resource_delete", {"resource_type": "cluster"},
                          client=client)

        assert result.changed is True
        assert client.delete.call_args[0][0] == "cluster"
