# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""CCKM's Google Cloud service in CipherTrust Manager.

CCKM manages Google Cloud KMS keys from CipherTrust Manager. The service is
organised like the AWS and Azure ones, so this module mirrors ``cckm_aws`` and
``cckm_azure``:

``projects``
    A Google Cloud project, and the connection used to reach it. Everything
    else hangs off a project.
``key-rings``
    A Cloud KMS key ring. Like an Azure vault, a key ring is not created here
    -- it already exists in Google Cloud and is *added* to CCKM with
    ``add-key-rings``, after discovering the candidates with
    ``get-key-rings``.
``keys``
    Cloud KMS CryptoKeys, their versions, and their IAM policy. Google's model
    puts the material in *versions*, so most of the lifecycle -- enable,
    disable, schedule destruction, re-import -- acts on a version rather than
    on the key.
``reports`` / ``synchronization-jobs`` / ``update-all-versions-jobs``
    Asynchronous jobs. Each is started with a POST and then polled.

Two things about this service are worth stating once.

**The API prefix is ``cckm/google``, not ``cckm/gcp``.** The modules are named
for the cloud, as the AWS and Azure ones are; the URL is not.

**One algorithm value in the API definition carries prose.** The definition
writes ``EC_SIGN_SECP256K1_SHA256 (Only for protection level = HSM)`` as an
enum entry, so :data:`KEY_ALGORITHMS` spells the accepted values out rather
than copying them, exactly as ``cckm_azure`` does for ``kty``.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cckm_common import (
    build_query,
    guard,
    prune,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    build_request_payload,
    quote_segment,
)

# -- endpoints --------------------------------------------------------------

ROOT = "cckm/google"
PROJECTS = ROOT + "/projects"
KEY_RINGS = ROOT + "/key-rings"
KEYS = ROOT + "/keys"
REPORTS = ROOT + "/reports"
SYNC_JOBS = ROOT + "/synchronization-jobs"
UPDATE_ALL_VERSIONS_JOBS = ROOT + "/update-all-versions-jobs"

# Discovery and bulk-add endpoints. Each is a POST that reads from Google
# Cloud through a connection; only add-key-rings stores anything.
ADD_KEY_RINGS = ROOT + "/add-key-rings"
GET_KEY_RINGS = ROOT + "/get-key-rings"
GET_PROJECTS = ROOT + "/get-projects"
GET_LOCATIONS = ROOT + "/get-locations"
GET_IAM_ROLES = ROOT + "/get-iam-roles"
UPLOAD_KEY = ROOT + "/upload-key"

# Cloud KMS algorithms. Written out rather than taken from the API definition,
# whose EC_SIGN_SECP256K1_SHA256 entry carries a parenthesised note.
KEY_ALGORITHMS = (
    "RSA_SIGN_PSS_2048_SHA256",
    "RSA_SIGN_PSS_3072_SHA256",
    "RSA_SIGN_PSS_4096_SHA256",
    "RSA_SIGN_PSS_4096_SHA512",
    "RSA_SIGN_PKCS1_2048_SHA256",
    "RSA_SIGN_PKCS1_3072_SHA256",
    "RSA_SIGN_PKCS1_4096_SHA256",
    "RSA_SIGN_PKCS1_4096_SHA512",
    "RSA_DECRYPT_OAEP_2048_SHA256",
    "RSA_DECRYPT_OAEP_3072_SHA256",
    "RSA_DECRYPT_OAEP_4096_SHA256",
    "RSA_DECRYPT_OAEP_4096_SHA512",
    "EC_SIGN_P256_SHA256",
    "EC_SIGN_P384_SHA384",
    "EC_SIGN_SECP256K1_SHA256",
    "GOOGLE_SYMMETRIC_ENCRYPTION",
    "HMAC_SHA256",
)
KEY_PURPOSES = ("ENCRYPT_DECRYPT", "ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "MAC")
PROTECTION_LEVELS = ("SOFTWARE", "HSM")
VERSION_BULK_OPERATIONS = ("enable", "disable", "schedule_destroy", "cancel_destroy")
REPORT_TYPES = ("key-report", "key-aging")


def _payload(fields):
    """JSON body for *fields*, with nested nulls removed."""
    return build_request_payload(prune(fields) or {})


# ---------------------------------------------------------------------------
# Projects -- the Google Cloud container
# ---------------------------------------------------------------------------

def project_create(node, project_id, connection=None,
                   enable_success_audit_event=None):
    client = CipherTrustClient(node)
    return client.post(PROJECTS, data=_payload(dict(
        project_id=project_id,
        connection=connection,
        enable_success_audit_event=enable_success_audit_event,
    )))


def project_patch(node, gcp_project_id, enable_success_audit_event=None):
    client = CipherTrustClient(node)
    return client.patch(
        PROJECTS + "/" + quote_segment(gcp_project_id),
        data=_payload(dict(
            enable_success_audit_event=enable_success_audit_event)),
    )


def project_get(node, gcp_project_id):
    client = CipherTrustClient(node)
    return client.get(PROJECTS + "/" + quote_segment(gcp_project_id))


def project_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(PROJECTS + build_query(filters or {}))


def project_delete(node, gcp_project_id):
    client = CipherTrustClient(node)
    return client.delete(PROJECTS + "/" + quote_segment(gcp_project_id))


def project_update_acls(node, gcp_project_id, acls):
    client = CipherTrustClient(node)
    return client.post(
        PROJECTS + "/" + quote_segment(gcp_project_id) + "/update-acls",
        data=_payload(dict(acls=acls)),
    )


def projects_available(node, connection, page_size=None, page_token=None):
    """List the Google Cloud projects a connection can reach."""
    client = CipherTrustClient(node)
    return client.post(GET_PROJECTS, data=_payload(dict(
        connection=connection, page_size=page_size, page_token=page_token)))


def locations_available(node, project_id, connection=None, page_size=None,
                        page_token=None):
    """List the Cloud KMS locations available in a project."""
    client = CipherTrustClient(node)
    return client.post(GET_LOCATIONS, data=_payload(dict(
        project_id=project_id, connection=connection,
        page_size=page_size, page_token=page_token)))


def iam_roles_available(node, id=None, key_id=None):
    """List the IAM roles that can be granted on a key ring or a key."""
    client = CipherTrustClient(node)
    return client.post(GET_IAM_ROLES,
                       data=_payload(dict(id=id, key_id=key_id)))


# ---------------------------------------------------------------------------
# Key rings
# ---------------------------------------------------------------------------

KEY_RING_ACTIONS = frozenset(["remove-key-ring"])


def key_ring_add(node, connection, project_id, key_rings):
    """Add one or more existing Cloud KMS key rings to CCKM."""
    client = CipherTrustClient(node)
    return client.post(ADD_KEY_RINGS, data=_payload(dict(
        connection=connection, project_id=project_id, key_rings=key_rings)))


def key_ring_patch(node, key_ring_id, connection):
    client = CipherTrustClient(node)
    return client.patch(
        KEY_RINGS + "/" + quote_segment(key_ring_id),
        data=_payload(dict(connection=connection)),
    )


def key_ring_get(node, key_ring_id):
    client = CipherTrustClient(node)
    return client.get(KEY_RINGS + "/" + quote_segment(key_ring_id))


def key_ring_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(KEY_RINGS + build_query(filters or {}))


def key_ring_action(node, key_ring_id, action, fields=None):
    client = CipherTrustClient(node)
    guard(action, KEY_RING_ACTIONS, "action")
    return client.post(
        KEY_RINGS + "/" + quote_segment(key_ring_id) + "/" + action,
        data=_payload(fields) if fields else None,
    )


def key_ring_update_acls(node, key_ring_id, acls):
    client = CipherTrustClient(node)
    return client.post(
        KEY_RINGS + "/" + quote_segment(key_ring_id) + "/update-acls",
        data=_payload(dict(acls=acls)),
    )


def key_rings_available(node, connection, project_id, location,
                        page_size=None, page_token=None):
    """List the key rings visible in a project's location."""
    client = CipherTrustClient(node)
    return client.post(GET_KEY_RINGS, data=_payload(dict(
        connection=connection, project_id=project_id, location=location,
        page_size=page_size, page_token=page_token)))


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

KEY_ACTIONS = frozenset([
    "refresh",
    "enable-auto-rotation",
    "disable-auto-rotation",
])

# Google puts key material in versions, so most of the lifecycle acts here.
KEY_VERSION_ACTIONS = frozenset([
    "enable",
    "disable",
    "schedule-destroy",
    "cancel-schedule-destroy",
    "refresh",
    "re-import",
    "download-public-key",
])


def key_create(node, key_ring, gcp_key_params):
    client = CipherTrustClient(node)
    return client.post(KEYS, data=_payload(dict(
        key_ring=key_ring, gcp_key_params=gcp_key_params)))


def key_upload(node, key_ring, gcp_key_params, source_key_id,
               source_key_tier):
    """Create a key in Cloud KMS from material CipherTrust Manager holds."""
    client = CipherTrustClient(node)
    return client.post(UPLOAD_KEY, data=_payload(dict(
        key_ring=key_ring,
        gcp_key_params=gcp_key_params,
        source_key_id=source_key_id,
        source_key_tier=source_key_tier,
    )))


def key_patch(node, key_id, primary_version_id=None, next_rotation_time=None,
              rotation_period=None, labels=None,
              version_template_algorithm=None):
    client = CipherTrustClient(node)
    return client.patch(
        KEYS + "/" + quote_segment(key_id),
        data=_payload(dict(
            primary_version_id=primary_version_id,
            next_rotation_time=next_rotation_time,
            rotation_period=rotation_period,
            labels=labels,
            version_template_algorithm=version_template_algorithm,
        )),
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


def key_policy_get(node, key_id):
    client = CipherTrustClient(node)
    return client.get(KEYS + "/" + quote_segment(key_id) + "/policy")


def key_policy_set(node, key_id, bindings=None, etag=None, version=None):
    client = CipherTrustClient(node)
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/policy",
        data=_payload(dict(bindings=bindings, etag=etag, version=version)),
    )


# -- key versions -----------------------------------------------------------

def key_version_create(node, key_id, source_key_tier=None, source_key_id=None,
                       algorithm=None, is_native=None):
    client = CipherTrustClient(node)
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/versions",
        data=_payload(dict(
            source_key_tier=source_key_tier,
            source_key_id=source_key_id,
            algorithm=algorithm,
            is_native=is_native,
        )),
    )


def key_version_list(node, key_id, filters=None):
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/versions"
        + build_query(filters or {}))


def key_version_get(node, key_id, version_id):
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/versions/"
        + quote_segment(version_id))


def key_version_action(node, key_id, version_id, action, fields=None):
    client = CipherTrustClient(node)
    guard(action, KEY_VERSION_ACTIONS, "action")
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/versions/"
        + quote_segment(version_id) + "/" + action,
        data=_payload(fields) if fields else None,
    )


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def report_create(node, name, report_type, gcp_cloud_params,
                  start_time=None, end_time=None):
    client = CipherTrustClient(node)
    return client.post(REPORTS, data=_payload(dict(
        name=name,
        report_type=report_type,
        gcp_cloud_params=gcp_cloud_params,
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


def report_contents(node, report_id, filters=None):
    client = CipherTrustClient(node)
    return client.get(
        REPORTS + "/" + quote_segment(report_id) + "/contents"
        + build_query(filters or {}))


def report_download(node, report_id):
    client = CipherTrustClient(node)
    return client.get(REPORTS + "/" + quote_segment(report_id) + "/download")


# ---------------------------------------------------------------------------
# Synchronisation jobs
# ---------------------------------------------------------------------------

def sync_start(node, key_rings=None, synchronize_all=None):
    client = CipherTrustClient(node)
    return client.post(SYNC_JOBS, data=_payload(dict(
        key_rings=key_rings, synchronize_all=synchronize_all)))


def sync_get(node, job_id):
    client = CipherTrustClient(node)
    return client.get(SYNC_JOBS + "/" + quote_segment(job_id))


def sync_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(SYNC_JOBS + build_query(filters or {}))


def sync_cancel(node, job_id):
    client = CipherTrustClient(node)
    return client.post(SYNC_JOBS + "/" + quote_segment(job_id) + "/cancel")


# ---------------------------------------------------------------------------
# Update-all-versions jobs
#
# Google's key lifecycle acts on versions, so enabling or destroying every
# version of a key is its own job rather than an operation on the key.
# ---------------------------------------------------------------------------

def update_all_versions_start(node, key_id, operation):
    client = CipherTrustClient(node)
    guard(operation, VERSION_BULK_OPERATIONS, "operation")
    return client.post(UPDATE_ALL_VERSIONS_JOBS, data=_payload(dict(
        key_id=key_id, operation=operation)))


def update_all_versions_get(node, job_id):
    client = CipherTrustClient(node)
    return client.get(
        UPDATE_ALL_VERSIONS_JOBS + "/" + quote_segment(job_id))
