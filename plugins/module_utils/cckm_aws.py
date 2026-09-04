# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""CCKM's AWS service in CipherTrust Manager.

CCKM (CipherTrust Cloud Key Manager) manages AWS KMS keys from CipherTrust
Manager. Its AWS API is organised around a few resources, each with the same
shape -- a collection under ``cckm/aws/<resource>`` supporting create, list,
get, update and delete, plus a set of per-resource action endpoints:

``kms``
    An *AWS account container*: the AWS account, the connection used to reach
    it, and the regions CCKM manages within it. Everything else hangs off a
    KMS.
``keys``
    AWS KMS keys, whether created by CCKM, uploaded from a key source, or
    discovered by synchronisation.
``templates``
    Key policy templates, applied to keys instead of an inline policy.
``custom-key-stores``
    AWS custom key stores, backed either by CloudHSM or -- for an external key
    store (XKS) -- by CipherTrust Manager or a Luna HSM.
``reports`` / ``bulkjob`` / ``synchronization-jobs``
    Asynchronous jobs. Each is started with a POST and then polled.

Two conventions in this file are worth stating once:

* **Action endpoints are validated against a whitelist.** The action name is
  interpolated into the URL, and the modules constrain it with ``choices``, so
  a value reaching the guard came from inside the collection rather than from
  a playbook. The check is what keeps that guarantee true after an edit.
* **Payloads are pruned recursively.** ``AnsibleModule`` fills every suboption
  a playbook did not set with ``None``, so a nested ``aws_param`` arrives full
  of nulls. ``build_request_payload`` only drops nulls at the top level, and
  AWS reads an explicit null as a request to clear the field, so nested
  structures are pruned here before they are sent.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    build_request_payload,
    quote_segment,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_common import (
    build_query as _query,
    guard as _guard,
    prune,
    remap_keys,
)

# -- endpoints --------------------------------------------------------------

ROOT = "cckm/aws"
KMS = ROOT + "/kms"
KEYS = ROOT + "/keys"
TEMPLATES = ROOT + "/templates"
CUSTOM_KEY_STORES = ROOT + "/custom-key-stores"
REPORTS = ROOT + "/reports"
BULKJOB = ROOT + "/bulkjob"

# Two independent synchronisation services exist: one for keys and one for
# custom key stores. They share a request and response shape, so the modules
# select between them by name rather than duplicating the four operations.
SYNC_SCOPES = {
    "keys": ROOT + "/synchronization-jobs",
    "custom-key-stores": CUSTOM_KEY_STORES + "/synchronization-jobs",
}


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

# Key parameters, as the modules spell them -> as AWS spells them.
AWS_KEY_PARAM_MAP = {
    "alias": "Alias",
    "description": "Description",
    "key_usage": "KeyUsage",
    "customer_master_key_spec": "CustomerMasterKeySpec",
    "origin": "Origin",
    "policy": "Policy",
    "bypass_policy_lockout_safety_check": "BypassPolicyLockoutSafetyCheck",
    "multi_region": "MultiRegion",
    "valid_to": "ValidTo",
    "tags": "Tags",
}

_TAG_MAP = {"tag_key": "TagKey", "tag_value": "TagValue"}


def aws_key_params(params):
    """Translate a module's ``aws_param`` into the AWS-cased payload."""
    if not isinstance(params, dict):
        return None
    translated = dict(params)
    tags = translated.get("tags")
    if isinstance(tags, list):
        converted = [remap_keys(tag, _TAG_MAP) for tag in tags if tag]
        translated["tags"] = [tag for tag in converted if tag] or None
    return prune(remap_keys(translated, AWS_KEY_PARAM_MAP))


def _payload(fields):
    """JSON body for *fields*, with nested nulls removed."""
    return build_request_payload(prune(fields) or {})


def _sync_root(scope):
    return SYNC_SCOPES[_guard(scope, SYNC_SCOPES, "scope")]


# ---------------------------------------------------------------------------
# KMS -- the AWS account container
# ---------------------------------------------------------------------------

def kms_create(node, name, account_id, connection, regions,
               assume_role_arn=None, assume_role_external_id=None):
    """Add an AWS account container to CCKM."""
    client = CipherTrustClient(node)
    return client.post(KMS, data=_payload(dict(
        name=name,
        account_id=account_id,
        connection=connection,
        regions=regions,
        assume_role_arn=assume_role_arn,
        assume_role_external_id=assume_role_external_id,
    )))


def kms_patch(node, kms_id, connection=None, regions=None,
              assume_role_arn=None, assume_role_external_id=None):
    """Update an AWS account container. The name cannot be changed."""
    client = CipherTrustClient(node)
    return client.patch(KMS + "/" + quote_segment(kms_id), data=_payload(dict(
        connection=connection,
        regions=regions,
        assume_role_arn=assume_role_arn,
        assume_role_external_id=assume_role_external_id,
    )))


def kms_get(node, kms_id):
    client = CipherTrustClient(node)
    return client.get(KMS + "/" + quote_segment(kms_id))


def kms_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(KMS + _query(filters or {}))


KMS_ACTIONS = frozenset(["archive", "recover"])


def kms_action(node, kms_id, action):
    """Archive or recover an AWS account container."""
    client = CipherTrustClient(node)
    _guard(action, KMS_ACTIONS, "action")
    return client.post(KMS + "/" + quote_segment(kms_id) + "/" + action)


def kms_update_acls(node, kms_id, acls):
    """Replace the user/group access control list on a KMS container."""
    client = CipherTrustClient(node)
    return client.post(
        KMS + "/" + quote_segment(kms_id) + "/update-acls",
        data=_payload(dict(acls=acls)),
    )


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def key_create(node, kms, region, aws_param=None, policytemplate=None,
               key_users=None, key_users_roles=None, key_admins=None,
               key_admins_roles=None, external_accounts=None):
    """Create an AWS KMS key."""
    client = CipherTrustClient(node)
    return client.post(KEYS, data=_payload(dict(
        kms=kms,
        region=region,
        aws_param=aws_key_params(aws_param),
        policytemplate=policytemplate,
        key_users=key_users,
        key_users_roles=key_users_roles,
        key_admins=key_admins,
        key_admins_roles=key_admins_roles,
        external_accounts=external_accounts,
    )))


def key_upload(node, kms, region, source_key_identifier, source_key_tier=None,
               key_expiration=None, aws_param=None, policytemplate=None,
               key_users=None, key_users_roles=None, key_admins=None,
               key_admins_roles=None, external_accounts=None):
    """Upload key material from a key source into AWS KMS (BYOK)."""
    client = CipherTrustClient(node)
    return client.post(ROOT + "/upload-key", data=_payload(dict(
        kms=kms,
        region=region,
        source_key_identifier=source_key_identifier,
        source_key_tier=source_key_tier,
        key_expiration=key_expiration,
        aws_param=aws_key_params(aws_param),
        policytemplate=policytemplate,
        key_users=key_users,
        key_users_roles=key_users_roles,
        key_admins=key_admins,
        key_admins_roles=key_admins_roles,
        external_accounts=external_accounts,
    )))


def key_create_hyok(node, local_hosted_params=None, aws_param=None,
                    policytemplate=None, key_users=None, key_users_roles=None,
                    key_admins=None, key_admins_roles=None,
                    external_accounts=None):
    """Create an AWS HYOK (hold your own key) key in a local key store."""
    client = CipherTrustClient(node)
    return client.post(ROOT + "/create-hyok-key", data=_payload(dict(
        local_hosted_params=local_hosted_params,
        aws_param=aws_key_params(aws_param),
        policytemplate=policytemplate,
        key_users=key_users,
        key_users_roles=key_users_roles,
        key_admins=key_admins,
        key_admins_roles=key_admins_roles,
        external_accounts=external_accounts,
    )))


def key_create_in_custom_key_store(node, custom_key_store_id, aws_param,
                                   policytemplate=None, key_users=None,
                                   key_users_roles=None, key_admins=None,
                                   key_admins_roles=None,
                                   external_accounts=None):
    """Create a KMS key inside a CloudHSM-backed custom key store."""
    client = CipherTrustClient(node)
    return client.post(
        CUSTOM_KEY_STORES + "/" + quote_segment(custom_key_store_id)
        + "/create-aws-key",
        data=_payload(dict(
            aws_param=aws_key_params(aws_param),
            policytemplate=policytemplate,
            key_users=key_users,
            key_users_roles=key_users_roles,
            key_admins=key_admins,
            key_admins_roles=key_admins_roles,
            external_accounts=external_accounts,
        )),
    )


def key_replicate(node, key_id, replica_region, aws_param=None,
                  policytemplate=None, key_users=None, key_users_roles=None,
                  key_admins=None, key_admins_roles=None,
                  external_accounts=None):
    """Replicate a multi-region primary key into another region."""
    client = CipherTrustClient(node)
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/replicate-key",
        data=_payload(dict(
            replica_region=replica_region,
            aws_param=aws_key_params(aws_param),
            policytemplate=policytemplate,
            key_users=key_users,
            key_users_roles=key_users_roles,
            key_admins=key_admins,
            key_admins_roles=key_admins_roles,
            external_accounts=external_accounts,
        )),
    )


def key_get(node, key_id):
    client = CipherTrustClient(node)
    return client.get(KEYS + "/" + quote_segment(key_id))


def key_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(KEYS + _query(filters or {}))


def key_versions(node, key_id, filters=None):
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/versions" + _query(filters or {})
    )


def key_rotations(node, key_id, filters=None):
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/rotations" + _query(filters or {})
    )


def key_download_public_key(node, key_id):
    """Download the public half of an asymmetric AWS key."""
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/download-public-key"
    )


# Per-key action endpoints. All are POST; the ones that take a body are
# driven by the module that owns them.
KEY_ACTIONS = frozenset([
    "add-alias",
    "add-tags",
    "block",
    "cancel-deletion",
    "delete-alias",
    "delete-material",
    "disable",
    "disable-auto-rotation",
    "disable-rotation-job",
    "enable",
    "enable-auto-rotation",
    "enable-rotation-job",
    "get-key-rotation-status",
    "import-material",
    "link",
    "policy",
    "refresh",
    "remove-tags",
    "rotate",
    "rotate-material",
    "schedule-deletion",
    "unblock",
    "update-description",
    "update-primary-region",
])


def key_action(node, key_id, action, fields=None):
    """Perform a per-key action.

    *action* is interpolated into the URL and is therefore checked against
    :data:`KEY_ACTIONS`; the modules constrain it with ``choices`` as well.
    """
    client = CipherTrustClient(node)
    _guard(action, KEY_ACTIONS, "action")
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/" + action,
        data=_payload(fields) if fields else None,
    )


def key_delete(node, key_id):
    """Remove the key record from CCKM. The AWS key itself is not deleted."""
    client = CipherTrustClient(node)
    return client.delete(KEYS + "/" + quote_segment(key_id))


# ---------------------------------------------------------------------------
# Key policy templates
# ---------------------------------------------------------------------------

def template_create(node, name, kms=None, account_id=None, policy=None,
                    external_accounts=None, key_admins=None,
                    key_admins_roles=None, key_users=None,
                    key_users_roles=None):
    client = CipherTrustClient(node)
    return client.post(TEMPLATES, data=_payload(dict(
        name=name,
        kms=kms,
        account_id=account_id,
        policy=policy,
        external_accounts=external_accounts,
        key_admins=key_admins,
        key_admins_roles=key_admins_roles,
        key_users=key_users,
        key_users_roles=key_users_roles,
    )))


def template_patch(node, template_id, policy=None, external_accounts=None,
                   key_admins=None, key_admins_roles=None, key_users=None,
                   key_users_roles=None, auto_push=None):
    client = CipherTrustClient(node)
    return client.patch(
        TEMPLATES + "/" + quote_segment(template_id),
        data=_payload(dict(
            policy=policy,
            external_accounts=external_accounts,
            key_admins=key_admins,
            key_admins_roles=key_admins_roles,
            key_users=key_users,
            key_users_roles=key_users_roles,
            auto_push=auto_push,
        )),
    )


def template_get(node, template_id):
    client = CipherTrustClient(node)
    return client.get(TEMPLATES + "/" + quote_segment(template_id))


def template_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(TEMPLATES + _query(filters or {}))


# ---------------------------------------------------------------------------
# Custom key stores
# ---------------------------------------------------------------------------

def custom_key_store_create(node, name, kms, region, aws_param,
                            local_hosted_params=None, linked_state=None,
                            enable_success_audit_event=None):
    client = CipherTrustClient(node)
    return client.post(CUSTOM_KEY_STORES, data=_payload(dict(
        name=name,
        kms=kms,
        region=region,
        aws_param=aws_param,
        local_hosted_params=local_hosted_params,
        linked_state=linked_state,
        enable_success_audit_event=enable_success_audit_event,
    )))


def custom_key_store_patch(node, custom_key_store_id, name=None,
                           aws_param=None, local_hosted_params=None,
                           enable_success_audit_event=None):
    client = CipherTrustClient(node)
    return client.patch(
        CUSTOM_KEY_STORES + "/" + quote_segment(custom_key_store_id),
        data=_payload(dict(
            name=name,
            aws_param=aws_param,
            local_hosted_params=local_hosted_params,
            enable_success_audit_event=enable_success_audit_event,
        )),
    )


def custom_key_store_get(node, custom_key_store_id):
    client = CipherTrustClient(node)
    return client.get(
        CUSTOM_KEY_STORES + "/" + quote_segment(custom_key_store_id)
    )


def custom_key_store_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(CUSTOM_KEY_STORES + _query(filters or {}))


def custom_key_store_health(node, custom_key_store_id):
    client = CipherTrustClient(node)
    return client.get(
        CUSTOM_KEY_STORES + "/" + quote_segment(custom_key_store_id) + "/health"
    )


CUSTOM_KEY_STORE_ACTIONS = frozenset([
    "block",
    "connect",
    "disable-credential-rotation-job",
    "disconnect",
    "enable-credential-rotation-job",
    "link",
    "rotate-credential",
    "unblock",
])


def custom_key_store_action(node, custom_key_store_id, action, fields=None):
    client = CipherTrustClient(node)
    _guard(action, CUSTOM_KEY_STORE_ACTIONS, "action")
    return client.post(
        CUSTOM_KEY_STORES + "/" + quote_segment(custom_key_store_id)
        + "/" + action,
        data=_payload(fields) if fields else None,
    )


def custom_key_store_credentials_list(node, custom_key_store_id, filters=None):
    client = CipherTrustClient(node)
    return client.get(
        CUSTOM_KEY_STORES + "/" + quote_segment(custom_key_store_id)
        + "/credentials" + _query(filters or {})
    )


def _credential_path(custom_key_store_id, credential_id):
    return (CUSTOM_KEY_STORES + "/" + quote_segment(custom_key_store_id)
            + "/credentials/" + quote_segment(credential_id))


def custom_key_store_credential_get(node, custom_key_store_id, credential_id):
    client = CipherTrustClient(node)
    return client.get(_credential_path(custom_key_store_id, credential_id))


def custom_key_store_credential_delete(node, custom_key_store_id,
                                       credential_id):
    client = CipherTrustClient(node)
    return client.delete(_credential_path(custom_key_store_id, credential_id))


def unused_cloudhsm_clusters(node, kms, region):
    """List CloudHSM clusters in *region* not yet backing a custom key store."""
    client = CipherTrustClient(node)
    return client.post(
        CUSTOM_KEY_STORES + "/get-unused-cloudhsm-clusters",
        data=_payload(dict(kms=kms, region=region)),
    )


# ---------------------------------------------------------------------------
# Jobs: synchronisation, bulk operations, reports
# ---------------------------------------------------------------------------

def sync_start(node, scope, kms=None, regions=None, synchronize_all=None):
    """Start a synchronisation job for keys or for custom key stores."""
    client = CipherTrustClient(node)
    return client.post(_sync_root(scope), data=_payload(dict(
        kms=kms,
        regions=regions,
        synchronize_all=synchronize_all,
    )))


def sync_list(node, scope, filters=None):
    client = CipherTrustClient(node)
    return client.get(_sync_root(scope) + _query(filters or {}))


def sync_get(node, scope, job_id):
    client = CipherTrustClient(node)
    return client.get(_sync_root(scope) + "/" + quote_segment(job_id))


def sync_cancel(node, scope, job_id):
    client = CipherTrustClient(node)
    return client.post(
        _sync_root(scope) + "/" + quote_segment(job_id) + "/cancel"
    )


def bulkjob_create(node, keys, operation, days=None, policy_template_id=None):
    """Start a bulk operation over a list of key ids."""
    client = CipherTrustClient(node)
    return client.post(BULKJOB, data=_payload(dict(
        keys=keys,
        operation=operation,
        days=days,
        policy_template_id=policy_template_id,
    )))


def bulkjob_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(BULKJOB + _query(filters or {}))


def bulkjob_get(node, job_id):
    client = CipherTrustClient(node)
    return client.get(BULKJOB + "/" + quote_segment(job_id))


def bulkjob_cancel(node, job_id):
    client = CipherTrustClient(node)
    return client.post(BULKJOB + "/" + quote_segment(job_id) + "/cancel")


def report_create(node, name, cloud_watch_params, start_time=None,
                  end_time=None, report_type=None):
    client = CipherTrustClient(node)
    return client.post(REPORTS, data=_payload(dict(
        name=name,
        cloud_watch_params=cloud_watch_params,
        start_time=start_time,
        end_time=end_time,
        report_type=report_type,
    )))


def report_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(REPORTS + _query(filters or {}))


def report_get(node, report_id):
    client = CipherTrustClient(node)
    return client.get(REPORTS + "/" + quote_segment(report_id))


def report_contents(node, report_id, filters=None):
    client = CipherTrustClient(node)
    return client.get(
        REPORTS + "/" + quote_segment(report_id) + "/contents"
        + _query(filters or {})
    )


def report_download(node, report_id):
    """Download a report as CSV. Returns the raw body, not a dict."""
    client = CipherTrustClient(node)
    return client.get(REPORTS + "/" + quote_segment(report_id) + "/download")


def report_delete(node, report_id):
    client = CipherTrustClient(node)
    return client.delete(REPORTS + "/" + quote_segment(report_id))


# ---------------------------------------------------------------------------
# Discovery
#
# These read from AWS through a connection or a KMS container. They are POST
# because they carry a request body, but they change nothing -- in CCKM or in
# AWS -- so the modules that use them run unchanged under --check.
# ---------------------------------------------------------------------------

def accounts_list(node, connection, assume_role_arn=None,
                  assume_role_external_id=None):
    client = CipherTrustClient(node)
    return client.post(ROOT + "/accounts", data=_payload(dict(
        connection=connection,
        assume_role_arn=assume_role_arn,
        assume_role_external_id=assume_role_external_id,
    )))


def regions_list(node, connection):
    client = CipherTrustClient(node)
    return client.post(
        ROOT + "/get-all-regions",
        data=_payload(dict(connection=connection)),
    )


def iam_roles_list(node, kms, path_prefix=None, max_items=None, marker=None):
    client = CipherTrustClient(node)
    return client.post(ROOT + "/get-iam-roles", data=_payload(dict(
        kms=kms, path_prefix=path_prefix, max_items=max_items, marker=marker,
    )))


def iam_users_list(node, kms, path_prefix=None, max_items=None, marker=None):
    client = CipherTrustClient(node)
    return client.post(ROOT + "/get-iam-users", data=_payload(dict(
        kms=kms, path_prefix=path_prefix, max_items=max_items, marker=marker,
    )))


def log_groups_list(node, kms, region, cloud_watch_params=None):
    client = CipherTrustClient(node)
    return client.post(ROOT + "/get-log-groups", data=_payload(dict(
        kms=kms, region=region, cloud_watch_params=cloud_watch_params,
    )))


def verify_alias(node, alias, region, kms):
    """Check whether *alias* is already in use in *region*."""
    client = CipherTrustClient(node)
    return client.post(ROOT + "/alias/verify", data=_payload(dict(
        alias=alias, region=region, kms=kms,
    )))


# ---------------------------------------------------------------------------
# XKS proxy endpoints
#
# CipherTrust Manager serves the AWS External Key Store proxy API for a
# locally-hosted custom key store. AWS KMS is the intended caller; these are
# exposed so an operator can exercise the endpoint AWS will use.
# ---------------------------------------------------------------------------

def _xks_root(keystore_id):
    return (ROOT + "/xks-proxy-endpoints/" + quote_segment(keystore_id)
            + "/kms/xks/v1")


def xks_health(node, keystore_id, request_metadata):
    client = CipherTrustClient(node)
    return client.post(
        _xks_root(keystore_id) + "/health",
        data=_payload(dict(requestMetadata=request_metadata)),
    )


def xks_key_metadata(node, keystore_id, xks_key_id, request_metadata):
    client = CipherTrustClient(node)
    return client.post(
        _xks_root(keystore_id) + "/keys/" + quote_segment(xks_key_id)
        + "/metadata",
        data=_payload(dict(requestMetadata=request_metadata)),
    )


def xks_encrypt(node, keystore_id, xks_key_id, plaintext, encryption_algorithm,
                request_metadata, additional_authenticated_data=None,
                ciphertext_data_integrity_value_algorithm=None):
    client = CipherTrustClient(node)
    return client.post(
        _xks_root(keystore_id) + "/keys/" + quote_segment(xks_key_id)
        + "/encrypt",
        data=_payload(dict(
            plaintext=plaintext,
            encryptionAlgorithm=encryption_algorithm,
            additionalAuthenticatedData=additional_authenticated_data,
            ciphertextDataIntegrityValueAlgorithm=(
                ciphertext_data_integrity_value_algorithm
            ),
            requestMetadata=request_metadata,
        )),
    )


def xks_decrypt(node, keystore_id, xks_key_id, ciphertext,
                encryption_algorithm, initialization_vector,
                authentication_tag, request_metadata,
                additional_authenticated_data=None):
    client = CipherTrustClient(node)
    return client.post(
        _xks_root(keystore_id) + "/keys/" + quote_segment(xks_key_id)
        + "/decrypt",
        data=_payload(dict(
            ciphertext=ciphertext,
            encryptionAlgorithm=encryption_algorithm,
            initializationVector=initialization_vector,
            authenticationTag=authentication_tag,
            additionalAuthenticatedData=additional_authenticated_data,
            requestMetadata=request_metadata,
        )),
    )
