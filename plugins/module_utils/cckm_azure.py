# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""CCKM's Azure service in CipherTrust Manager.

CCKM manages Azure Key Vault material from CipherTrust Manager. Its Azure API
is organised much like the AWS one, so this module mirrors ``cckm_aws``:

``vaults``
    An Azure key vault (or managed HSM) that CCKM has been told about.
    Everything else hangs off a vault. Unlike AWS, a vault is not *created*
    here -- it already exists in Azure and is *added* to CCKM with
    ``add-vaults``, after discovering the candidates with ``get-vaults``.
``keys`` / ``secrets`` / ``certificates``
    The three kinds of vault object CCKM manages. All three share a shape:
    create, list, get, update, the Azure soft-delete lifecycle
    (``soft-delete``, ``recover``, ``hard-delete``, ``restore``) and their own
    synchronisation service.
``subscriptions``
    Azure subscriptions reachable through a connection, discovered with
    ``get-subscriptions``.
``reports`` / ``bulkjobs`` / ``synchronization-jobs``
    Asynchronous jobs. Each is started with a POST and then polled.

The conventions here are the ones ``cckm_aws`` established, for the same
reasons: action names that form part of a URL are validated against a
whitelist, and payloads are pruned recursively because ``AnsibleModule``
materialises every declared suboption as ``None`` and Azure reads an explicit
null as a request to clear a field.

One Azure-specific wrinkle: the swagger definition writes the ``kty`` enum as
prose -- ``EC- "Soft" Elliptic Curve key.`` -- so the accepted values are the
tokens before the first ``-`` separator, spelled out in :data:`KEY_TYPES`
rather than copied from the definition.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_common import (
    build_query,
    guard,
    prune,
    remap_keys,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    build_request_payload,
    quote_segment,
)

# -- endpoints --------------------------------------------------------------

ROOT = "cckm/azure"
VAULTS = ROOT + "/vaults"
KEYS = ROOT + "/keys"
SECRETS = ROOT + "/secrets"
CERTIFICATES = ROOT + "/certificates"
REPORTS = ROOT + "/reports"
BULKJOBS = ROOT + "/bulkjobs"
SUBSCRIPTIONS = ROOT + "/subscriptions"

# Discovery endpoints. Each is a POST that reads from Azure through a
# connection and returns what it finds; nothing is stored.
ADD_VAULTS = ROOT + "/add-vaults"
GET_VAULTS = ROOT + "/get-vaults"
GET_MANAGED_HSMS = ROOT + "/get-managed-hsms"
GET_SUBSCRIPTIONS = ROOT + "/get-subscriptions"
UPLOAD_KEY = ROOT + "/upload-key"

# Three independent synchronisation services, one per kind of vault object.
# They share a request and response shape, so the modules select between them
# by name rather than duplicating the four operations.
SYNC_SCOPES = {
    "keys": ROOT + "/synchronization-jobs",
    "certificates": CERTIFICATES + "/synchronization-jobs",
    "secrets": SECRETS + "/synchronization-jobs",
}

# Azure key types. Written out rather than taken from the swagger definition,
# whose enum entries are prose descriptions with the value as a prefix.
KEY_TYPES = ("EC", "EC-HSM", "RSA", "RSA-HSM")
KEY_CURVES = ("P-256", "P-384", "P-521", "SECP256K1")
KEY_SIZES = (2048, 3072, 4096)


def _payload(fields):
    """JSON body for *fields*, with nested nulls removed."""
    return build_request_payload(prune(fields) or {})


def _sync_root(scope):
    return SYNC_SCOPES[guard(scope, SYNC_SCOPES, "scope")]


# ---------------------------------------------------------------------------
# Vaults -- the Azure key vault container
# ---------------------------------------------------------------------------

VAULT_ACTIONS = frozenset([
    "enable-rotation-job",
    "disable-rotation-job",
    "remove-vault",
])


def vault_add(node, connection, subscription_id, vaults,
              cloud_key_backup_limit=None):
    """Add one or more existing Azure vaults to CCKM."""
    client = CipherTrustClient(node)
    return client.post(ADD_VAULTS, data=_payload(dict(
        connection=connection,
        subscription_id=subscription_id,
        vaults=vaults,
        cloud_key_backup_limit=cloud_key_backup_limit,
    )))


def vault_patch(node, vault_id, connection, cloud_key_backup_limit=None):
    """Update a vault CCKM already knows about."""
    client = CipherTrustClient(node)
    return client.patch(
        VAULTS + "/" + quote_segment(vault_id),
        data=_payload(dict(
            connection=connection,
            cloud_key_backup_limit=cloud_key_backup_limit,
        )),
    )


def vault_get(node, vault_id):
    client = CipherTrustClient(node)
    return client.get(VAULTS + "/" + quote_segment(vault_id))


def vault_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(VAULTS + build_query(filters or {}))


def vault_action(node, vault_id, action, fields=None):
    """Run a vault action: rotation job control, or removal from CCKM."""
    client = CipherTrustClient(node)
    guard(action, VAULT_ACTIONS, "action")
    return client.post(
        VAULTS + "/" + quote_segment(vault_id) + "/" + action,
        data=_payload(fields) if fields else None,
    )


def vault_update_acls(node, vault_id, acls):
    """Replace the user/group access control list on a vault."""
    client = CipherTrustClient(node)
    return client.post(
        VAULTS + "/" + quote_segment(vault_id) + "/update-acls",
        data=_payload(dict(acls=acls)),
    )


def vaults_available(node, connection, subscription_id, limit=None,
                     next_link=None):
    """List the vaults visible in Azure, before any are added to CCKM."""
    client = CipherTrustClient(node)
    return client.post(GET_VAULTS, data=_payload(dict(
        connection=connection,
        subscription_id=subscription_id,
        limit=limit,
        nextLink=next_link,
    )))


def managed_hsms_available(node, connection, subscription_id, limit=None,
                           next_link=None):
    """List the managed HSMs visible in Azure."""
    client = CipherTrustClient(node)
    return client.post(GET_MANAGED_HSMS, data=_payload(dict(
        connection=connection,
        subscription_id=subscription_id,
        limit=limit,
        nextLink=next_link,
    )))


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------

def subscription_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(SUBSCRIPTIONS + build_query(filters or {}))


def subscription_get(node, subscription_id):
    client = CipherTrustClient(node)
    return client.get(SUBSCRIPTIONS + "/" + quote_segment(subscription_id))


def subscription_delete(node, subscription_id):
    client = CipherTrustClient(node)
    return client.delete(SUBSCRIPTIONS + "/" + quote_segment(subscription_id))


def subscriptions_available(node, connection):
    """List the subscriptions a connection can reach."""
    client = CipherTrustClient(node)
    return client.post(GET_SUBSCRIPTIONS,
                       data=_payload(dict(connection=connection)))


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

KEY_ACTIONS = frozenset([
    "soft-delete",
    "hard-delete",
    "recover",
    "restore",
    "refresh",
    "enable-rotation-job",
    "disable-rotation-job",
    "enable-backup-job",
    "disable-backup-job",
    "delete-backup",
])


def key_create(node, key_name, key_vault, azure_param, exportable=None,
               release_policy=None):
    client = CipherTrustClient(node)
    return client.post(KEYS, data=_payload(dict(
        key_name=key_name,
        key_vault=key_vault,
        azure_param=azure_param,
        exportable=exportable,
        release_policy=release_policy,
    )))


def key_upload(node, key_name, key_vault, azure_param=None,
               local_key_identifier=None, source_key_tier=None, pfx=None,
               password=None, luna_key_identifier=None,
               dsm_key_identifier=None, external_cm_key_identifier=None,
               kek_kid=None, exportable=None, release_policy=None):
    """Upload key material from a source CipherTrust Manager can reach."""
    client = CipherTrustClient(node)
    return client.post(UPLOAD_KEY, data=_payload(dict(
        key_name=key_name,
        key_vault=key_vault,
        azure_param=azure_param,
        local_key_identifier=local_key_identifier,
        source_key_tier=source_key_tier,
        pfx=pfx,
        password=password,
        luna_key_identifier=luna_key_identifier,
        dsm_key_identifier=dsm_key_identifier,
        external_cm_key_identifier=external_cm_key_identifier,
        kek_kid=kek_kid,
        exportable=exportable,
        release_policy=release_policy,
    )))


def key_patch(node, key_id, attributes=None, tags=None, key_ops=None):
    client = CipherTrustClient(node)
    return client.patch(
        KEYS + "/" + quote_segment(key_id),
        data=_payload(dict(attributes=attributes, tags=tags, key_ops=key_ops)),
    )


def key_get(node, key_id):
    client = CipherTrustClient(node)
    return client.get(KEYS + "/" + quote_segment(key_id))


def key_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(KEYS + build_query(filters or {}))


def key_action(node, key_id, action, fields=None):
    client = CipherTrustClient(node)
    guard(action, KEY_ACTIONS, "action")
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/" + action,
        data=_payload(fields) if fields else None,
    )


def key_download_public_key(node, key_id):
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/download-public-key")


# -- key backups ------------------------------------------------------------

def key_backup_create(node, key_id, name=None, description=None):
    client = CipherTrustClient(node)
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/backups",
        data=_payload(dict(name=name, description=description)),
    )


def key_backup_list(node, key_id, filters=None):
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/backups"
        + build_query(filters or {}))


def key_backup_get(node, key_id, backup_id):
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/backups/"
        + quote_segment(backup_id))


def key_backup_patch(node, key_id, backup_id, name=None, description=None):
    client = CipherTrustClient(node)
    return client.patch(
        KEYS + "/" + quote_segment(key_id) + "/backups/"
        + quote_segment(backup_id),
        data=_payload(dict(name=name, description=description)),
    )


def key_backup_delete(node, key_id, backup_id):
    client = CipherTrustClient(node)
    return client.delete(
        KEYS + "/" + quote_segment(key_id) + "/backups/"
        + quote_segment(backup_id))


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

SECRET_ACTIONS = frozenset([
    "soft-delete", "hard-delete", "recover", "restore",
])


# Azure spells this field contentType. This collection normalises every option
# name to snake_case, so it arrives as content_type and has to be translated
# back before it is sent.
_SECRET_PARAM_MAP = {"content_type": "contentType"}


def secret_create(node, secret_name, key_vault, azure_param):
    client = CipherTrustClient(node)
    return client.post(SECRETS, data=_payload(dict(
        secret_name=secret_name,
        key_vault=key_vault,
        azure_param=remap_keys(azure_param, _SECRET_PARAM_MAP),
    )))


def secret_patch(node, secret_id, attributes=None, tags=None,
                 content_type=None):
    client = CipherTrustClient(node)
    return client.patch(
        SECRETS + "/" + quote_segment(secret_id),
        data=_payload(dict(attributes=attributes, tags=tags,
                           contentType=content_type)),
    )


def secret_get(node, secret_id):
    client = CipherTrustClient(node)
    return client.get(SECRETS + "/" + quote_segment(secret_id))


def secret_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(SECRETS + build_query(filters or {}))


def secret_delete(node, secret_id):
    client = CipherTrustClient(node)
    return client.delete(SECRETS + "/" + quote_segment(secret_id))


def secret_action(node, secret_id, action, fields=None):
    client = CipherTrustClient(node)
    guard(action, SECRET_ACTIONS, "action")
    return client.post(
        SECRETS + "/" + quote_segment(secret_id) + "/" + action,
        data=_payload(fields) if fields else None,
    )


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

CERTIFICATE_ACTIONS = frozenset([
    "soft-delete", "hard-delete", "recover", "restore",
])


def certificate_create(node, cert_name, key_vault, azure_param):
    client = CipherTrustClient(node)
    return client.post(CERTIFICATES, data=_payload(dict(
        cert_name=cert_name,
        key_vault=key_vault,
        azure_param=azure_param,
    )))


def certificate_import(node, cert_name, key_vault, caid=None,
                       source_cert_identifier=None, private_key_pem=None,
                       certificate=None, password=None, azure_param=None):
    """Import an existing certificate into an Azure vault."""
    client = CipherTrustClient(node)
    return client.post(CERTIFICATES + "/import", data=_payload(dict(
        cert_name=cert_name,
        key_vault=key_vault,
        caid=caid,
        source_cert_identifier=source_cert_identifier,
        private_key_pem=private_key_pem,
        certificate=certificate,
        password=password,
        azure_param=azure_param,
    )))


def certificate_patch(node, certificate_id, attributes=None, tags=None):
    client = CipherTrustClient(node)
    return client.patch(
        CERTIFICATES + "/" + quote_segment(certificate_id),
        data=_payload(dict(attributes=attributes, tags=tags)),
    )


def certificate_get(node, certificate_id):
    client = CipherTrustClient(node)
    return client.get(CERTIFICATES + "/" + quote_segment(certificate_id))


def certificate_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(CERTIFICATES + build_query(filters or {}))


def certificate_delete(node, certificate_id):
    client = CipherTrustClient(node)
    return client.delete(CERTIFICATES + "/" + quote_segment(certificate_id))


def certificate_action(node, certificate_id, action, fields=None):
    client = CipherTrustClient(node)
    guard(action, CERTIFICATE_ACTIONS, "action")
    return client.post(
        CERTIFICATES + "/" + quote_segment(certificate_id) + "/" + action,
        data=_payload(fields) if fields else None,
    )


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

REPORT_TYPES = ("service-report", "key-report", "key-aging")


def report_create(node, name, report_type, log_analytic_params,
                  start_time=None, end_time=None):
    client = CipherTrustClient(node)
    return client.post(REPORTS, data=_payload(dict(
        name=name,
        report_type=report_type,
        log_analytic_params=log_analytic_params,
        start_time=start_time,
        end_time=end_time,
    )))


def report_get(node, report_id):
    client = CipherTrustClient(node)
    return client.get(REPORTS + "/" + quote_segment(report_id))


def report_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(REPORTS + build_query(filters or {}))


def report_delete(node, report_id):
    client = CipherTrustClient(node)
    return client.delete(REPORTS + "/" + quote_segment(report_id))


def report_contents(node, report_id):
    client = CipherTrustClient(node)
    return client.get(REPORTS + "/" + quote_segment(report_id) + "/contents")


def report_download(node, report_id):
    client = CipherTrustClient(node)
    return client.get(REPORTS + "/" + quote_segment(report_id) + "/download")


# ---------------------------------------------------------------------------
# Bulk jobs
# ---------------------------------------------------------------------------

BULKJOB_OPERATIONS = ("delete-key-backups",)


def bulkjob_create(node, operation, delete_key_backups_param=None):
    client = CipherTrustClient(node)
    return client.post(BULKJOBS, data=_payload(dict(
        operation=operation,
        delete_key_backups_param=delete_key_backups_param,
    )))


def bulkjob_get(node, job_id):
    client = CipherTrustClient(node)
    return client.get(BULKJOBS + "/" + quote_segment(job_id))


def bulkjob_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(BULKJOBS + build_query(filters or {}))


def bulkjob_delete(node, job_id):
    client = CipherTrustClient(node)
    return client.delete(BULKJOBS + "/" + quote_segment(job_id))


def bulkjob_cancel(node, job_id):
    client = CipherTrustClient(node)
    return client.post(BULKJOBS + "/" + quote_segment(job_id) + "/cancel")


# ---------------------------------------------------------------------------
# Synchronisation jobs
# ---------------------------------------------------------------------------

def sync_start(node, scope, key_vaults=None, synchronize_all=None,
               take_cloud_key_backup=None):
    client = CipherTrustClient(node)
    return client.post(_sync_root(scope), data=_payload(dict(
        key_vaults=key_vaults,
        synchronize_all=synchronize_all,
        take_cloud_key_backup=take_cloud_key_backup,
    )))


def sync_get(node, scope, job_id):
    client = CipherTrustClient(node)
    return client.get(_sync_root(scope) + "/" + quote_segment(job_id))


def sync_list(node, scope, filters=None):
    client = CipherTrustClient(node)
    return client.get(_sync_root(scope) + build_query(filters or {}))


def sync_cancel(node, scope, job_id):
    client = CipherTrustClient(node)
    return client.post(
        _sync_root(scope) + "/" + quote_segment(job_id) + "/cancel")
