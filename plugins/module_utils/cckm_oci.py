# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""CCKM's Oracle Cloud Infrastructure service in CipherTrust Manager.

CCKM manages OCI Vault keys from CipherTrust Manager. The service follows the
same shape as the AWS, Azure and Google Cloud ones, with OCI's own containment
model on top:

``tenancy``
    An OCI tenancy, and the connection used to reach it. Everything else hangs
    off a tenancy.
``compartments``
    OCI compartments within a tenancy. Keys and vaults live in one.
``vaults``
    OCI Vaults. A vault is either *added* from OCI with ``add-vaults``, or
    created as an **external vault** -- one whose key material stays in
    CipherTrust Manager and which OCI reaches over an endpoint. External
    vaults are why ``issuers`` exist.
``issuers``
    OIDC issuers that authenticate OCI's calls into an external vault.
``keys``
    OCI Vault keys and their versions. Deletion is deferred: a key or version
    is *scheduled* for deletion some number of days ahead, and can be
    cancelled until then.
``reports`` / ``synchronization-jobs``
    Asynchronous jobs. Each is started with a POST and then polled.

One quirk of this API is load-bearing: **the GET for a single key version ends
in a trailing slash** (``keys/{id}/versions/{version}/``), while every sibling
path does not. :func:`key_version_get` keeps it deliberately.
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

ROOT = "cckm/oci"
TENANCY = ROOT + "/tenancy"
COMPARTMENTS = ROOT + "/compartments"
VAULTS = ROOT + "/vaults"
KEYS = ROOT + "/keys"
ISSUERS = ROOT + "/issuers"
REPORTS = ROOT + "/reports"
SYNC_JOBS = ROOT + "/synchronization-jobs"

# Discovery and bulk-add endpoints.
ADD_TENANCY = ROOT + "/add-tenancy"
ADD_COMPARTMENTS = ROOT + "/add-compartments"
ADD_VAULTS = ROOT + "/add-vaults"
CREATE_EXTERNAL_VAULT = ROOT + "/create-external-vault"
CREATE_EXTERNAL_KEY = ROOT + "/create-external-key"
UPLOAD_KEY = ROOT + "/upload-key"
GET_COMPARTMENTS = ROOT + "/get-compartments"
GET_VAULTS = ROOT + "/get-vaults"
GET_SUBSCRIBED_REGIONS = ROOT + "/get-subscribed-regions"
GET_DEFINED_TAGS = ROOT + "/get-defined-tags"
LIST_BUCKETS = ROOT + "/storage/list-buckets"

KEY_ALGORITHMS = ("AES", "RSA", "ECDSA")
CURVE_IDS = ("NIST_P256", "NIST_P384", "NIST_P521")
PROTECTION_MODES = ("HSM", "SOFTWARE")
REPORT_TYPES = ("key-report", "key-rotation", "key-aging")


def _payload(fields):
    """JSON body for *fields*, with nested nulls removed."""
    return build_request_payload(prune(fields) or {})


# ---------------------------------------------------------------------------
# Tenancy
# ---------------------------------------------------------------------------

def tenancy_add(node, tenancy_ocid=None, tenancy=None, connection=None):
    """Register an OCI tenancy with CCKM."""
    client = CipherTrustClient(node)
    return client.post(ADD_TENANCY, data=_payload(dict(
        tenancy_ocid=tenancy_ocid, tenancy=tenancy, connection=connection)))


def tenancy_get(node, tenancy_id):
    client = CipherTrustClient(node)
    return client.get(TENANCY + "/" + quote_segment(tenancy_id))


def tenancy_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(TENANCY + build_query(filters or {}))


def tenancy_delete(node, tenancy_id):
    client = CipherTrustClient(node)
    return client.delete(TENANCY + "/" + quote_segment(tenancy_id))


def subscribed_regions(node, connection):
    """List the OCI regions a tenancy is subscribed to."""
    client = CipherTrustClient(node)
    return client.post(GET_SUBSCRIBED_REGIONS,
                       data=_payload(dict(connection=connection)))


# ---------------------------------------------------------------------------
# Compartments
# ---------------------------------------------------------------------------

def compartment_add(node, connection, compartment_id):
    """Add one or more OCI compartments to CCKM.

    *compartment_id* is a list of OCIDs, as the API names it.
    """
    client = CipherTrustClient(node)
    return client.post(ADD_COMPARTMENTS, data=_payload(dict(
        connection=connection, compartment_id=compartment_id)))


def compartment_get(node, compartment_id):
    client = CipherTrustClient(node)
    return client.get(COMPARTMENTS + "/" + quote_segment(compartment_id))


def compartment_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(COMPARTMENTS + build_query(filters or {}))


def compartment_delete(node, compartment_id):
    client = CipherTrustClient(node)
    return client.delete(COMPARTMENTS + "/" + quote_segment(compartment_id))


def compartments_available(node, connection, limit=None, oci_next_page=None):
    """List the compartments a connection can reach."""
    client = CipherTrustClient(node)
    return client.post(GET_COMPARTMENTS, data=_payload(dict(
        connection=connection, limit=limit, ociNextPage=oci_next_page)))


def defined_tags_available(node, connection, limit=None, oci_next_page=None):
    """List the defined tags available in the tenancy."""
    client = CipherTrustClient(node)
    return client.post(GET_DEFINED_TAGS, data=_payload(dict(
        connection=connection, limit=limit, ociNextPage=oci_next_page)))


def buckets_available(node, connection, compartment_id, limit=None,
                      oci_next_page=None):
    """List the Object Storage buckets a compartment holds.

    A bucket is where an added vault's backups are written, so this is read
    before ``vault_add``.
    """
    client = CipherTrustClient(node)
    return client.post(LIST_BUCKETS, data=_payload(dict(
        connection=connection, compartment_id=compartment_id,
        limit=limit, ociNextPage=oci_next_page)))


# ---------------------------------------------------------------------------
# Vaults
# ---------------------------------------------------------------------------

VAULT_ACTIONS = frozenset(["block", "unblock"])


def vault_add(node, connection, region, vault_id, bucket_name=None,
              bucket_namespace=None):
    """Add one or more existing OCI vaults to CCKM.

    *vault_id* is a list of OCIDs, as the API names it.
    """
    client = CipherTrustClient(node)
    return client.post(ADD_VAULTS, data=_payload(dict(
        connection=connection, region=region, vault_id=vault_id,
        bucket_name=bucket_name, bucket_namespace=bucket_namespace)))


def vault_create_external(node, vault_name, endpoint_url_hostname,
                          client_application_id, issuer_id, connection=None,
                          tenancy=None, endpoint_url_port=None, policy=None,
                          source_key_tier=None, partition_id=None,
                          enable_success_audit_event=None):
    """Create an external vault, whose material stays in CipherTrust Manager."""
    client = CipherTrustClient(node)
    return client.post(CREATE_EXTERNAL_VAULT, data=_payload(dict(
        vault_name=vault_name,
        endpoint_url_hostname=endpoint_url_hostname,
        client_application_id=client_application_id,
        issuer_id=issuer_id,
        connection=connection,
        tenancy=tenancy,
        endpoint_url_port=endpoint_url_port,
        policy=policy,
        source_key_tier=source_key_tier,
        partition_id=partition_id,
        enable_success_audit_event=enable_success_audit_event,
    )))


def vault_patch(node, vault_id, connection=None, bucket_name=None,
                bucket_namespace=None, vault_name=None, issuer_id=None,
                endpoint_url_hostname=None, endpoint_url_port=None,
                policy=None, enable_success_audit_event=None):
    client = CipherTrustClient(node)
    return client.patch(
        VAULTS + "/" + quote_segment(vault_id),
        data=_payload(dict(
            connection=connection,
            bucket_name=bucket_name,
            bucket_namespace=bucket_namespace,
            vault_name=vault_name,
            issuer_id=issuer_id,
            endpoint_url_hostname=endpoint_url_hostname,
            endpoint_url_port=endpoint_url_port,
            policy=policy,
            enable_success_audit_event=enable_success_audit_event,
        )),
    )


def vault_get(node, vault_id):
    client = CipherTrustClient(node)
    return client.get(VAULTS + "/" + quote_segment(vault_id))


def vault_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(VAULTS + build_query(filters or {}))


def vault_delete(node, vault_id):
    client = CipherTrustClient(node)
    return client.delete(VAULTS + "/" + quote_segment(vault_id))


def vault_action(node, vault_id, action):
    client = CipherTrustClient(node)
    guard(action, VAULT_ACTIONS, "action")
    return client.post(VAULTS + "/" + quote_segment(vault_id) + "/" + action)


def vault_update_acls(node, vault_id, acls):
    client = CipherTrustClient(node)
    return client.post(
        VAULTS + "/" + quote_segment(vault_id) + "/update-acls",
        data=_payload(dict(acls=acls)),
    )


def vaults_available(node, connection, compartment_id, region, limit=None,
                     oci_next_page=None):
    """List the vaults visible in a compartment and region."""
    client = CipherTrustClient(node)
    return client.post(GET_VAULTS, data=_payload(dict(
        connection=connection, compartment_id=compartment_id, region=region,
        limit=limit, ociNextPage=oci_next_page)))


# ---------------------------------------------------------------------------
# Issuers -- OIDC identity for external vaults
# ---------------------------------------------------------------------------

def issuer_create(node, name, jwks_uri_protected, openid_config_url=None,
                  issuer=None, jwks_uri=None, client_id=None,
                  client_secret=None, regional_jwks_uris=None,
                  regional_open_id_config_urls=None):
    client = CipherTrustClient(node)
    return client.post(ISSUERS, data=_payload(dict(
        name=name,
        jwks_uri_protected=jwks_uri_protected,
        openid_config_url=openid_config_url,
        issuer=issuer,
        jwks_uri=jwks_uri,
        client_id=client_id,
        client_secret=client_secret,
        regional_jwks_uris=regional_jwks_uris,
        regional_open_id_config_urls=regional_open_id_config_urls,
    )))


def issuer_patch(node, issuer_id, name=None, jwks_uri_protected=None,
                 client_id=None, client_secret=None, regional_jwks_uris=None,
                 regional_open_id_config_urls=None):
    client = CipherTrustClient(node)
    return client.patch(
        ISSUERS + "/" + quote_segment(issuer_id),
        data=_payload(dict(
            name=name,
            jwks_uri_protected=jwks_uri_protected,
            client_id=client_id,
            client_secret=client_secret,
            regional_jwks_uris=regional_jwks_uris,
            regional_open_id_config_urls=regional_open_id_config_urls,
        )),
    )


def issuer_get(node, issuer_id):
    client = CipherTrustClient(node)
    return client.get(ISSUERS + "/" + quote_segment(issuer_id))


def issuer_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(ISSUERS + build_query(filters or {}))


def issuer_delete(node, issuer_id):
    client = CipherTrustClient(node)
    return client.delete(ISSUERS + "/" + quote_segment(issuer_id))


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

KEY_ACTIONS = frozenset([
    "block",
    "unblock",
    "enable",
    "disable",
    "refresh",
    "restore",
    "schedule-deletion",
    "cancel-deletion",
    "change-compartment",
    "delete-backup",
    "enable-auto-rotation",
    "disable-auto-rotation",
])

KEY_VERSION_ACTIONS = frozenset(["schedule-deletion", "cancel-deletion"])


def key_create(node, vault, name, algorithm, length, protection_mode,
               compartment_id, curve_id=None, defined_tags=None,
               freeform_tags=None):
    client = CipherTrustClient(node)
    return client.post(KEYS, data=_payload(dict(
        vault=vault,
        name=name,
        algorithm=algorithm,
        length=length,
        protection_mode=protection_mode,
        compartment_id=compartment_id,
        curve_id=curve_id,
        defined_tags=defined_tags,
        freeform_tags=freeform_tags,
    )))


def key_upload(node, vault, name, protection_mode, compartment_id,
               source_key_identifier, source_key_tier, defined_tags=None,
               freeform_tags=None):
    client = CipherTrustClient(node)
    return client.post(UPLOAD_KEY, data=_payload(dict(
        vault=vault,
        name=name,
        protection_mode=protection_mode,
        compartment_id=compartment_id,
        source_key_identifier=source_key_identifier,
        source_key_tier=source_key_tier,
        defined_tags=defined_tags,
        freeform_tags=freeform_tags,
    )))


def key_create_external(node, vault, name, source_key_identifier,
                        source_key_tier, policy=None):
    """Create a key in an external vault, backed by CipherTrust Manager."""
    client = CipherTrustClient(node)
    return client.post(CREATE_EXTERNAL_KEY, data=_payload(dict(
        vault=vault,
        name=name,
        source_key_identifier=source_key_identifier,
        source_key_tier=source_key_tier,
        policy=policy,
    )))


def key_patch(node, key_id, display_name=None, defined_tags=None,
              freeform_tags=None, name=None, policy=None):
    client = CipherTrustClient(node)
    return client.patch(
        KEYS + "/" + quote_segment(key_id),
        data=_payload(dict(
            display_name=display_name,
            defined_tags=defined_tags,
            freeform_tags=freeform_tags,
            name=name,
            policy=policy,
        )),
    )


def key_get(node, key_id):
    client = CipherTrustClient(node)
    return client.get(KEYS + "/" + quote_segment(key_id))


def key_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(KEYS + build_query(filters or {}))


def key_delete(node, key_id):
    client = CipherTrustClient(node)
    return client.delete(KEYS + "/" + quote_segment(key_id))


def key_action(node, key_id, action, fields=None):
    client = CipherTrustClient(node)
    guard(action, KEY_ACTIONS, "action")
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/" + action,
        data=_payload(fields) if fields else None,
    )


# -- key versions -----------------------------------------------------------

def key_version_create(node, key_id, is_native, source_key_tier=None,
                       source_key_identifier=None):
    client = CipherTrustClient(node)
    return client.post(
        KEYS + "/" + quote_segment(key_id) + "/versions",
        data=_payload(dict(
            is_native=is_native,
            source_key_tier=source_key_tier,
            source_key_identifier=source_key_identifier,
        )),
    )


def key_version_list(node, key_id, filters=None):
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/versions"
        + build_query(filters or {}))


def key_version_get(node, key_id, version_id):
    """Read one key version.

    The trailing slash is not a typo: CCKM serves this single path as
    ``keys/{id}/versions/{version}/`` while every sibling path has none.
    """
    client = CipherTrustClient(node)
    return client.get(
        KEYS + "/" + quote_segment(key_id) + "/versions/"
        + quote_segment(version_id) + "/")


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

def report_create(node, name, report_type, oci_params, start_time=None,
                  end_time=None):
    client = CipherTrustClient(node)
    return client.post(REPORTS, data=_payload(dict(
        name=name,
        report_type=report_type,
        oci_params=oci_params,
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
# Synchronisation jobs
# ---------------------------------------------------------------------------

def sync_start(node, vaults=None, synchronize_all=None):
    client = CipherTrustClient(node)
    return client.post(SYNC_JOBS, data=_payload(dict(
        vaults=vaults, synchronize_all=synchronize_all)))


def sync_get(node, job_id):
    client = CipherTrustClient(node)
    return client.get(SYNC_JOBS + "/" + quote_segment(job_id))


def sync_list(node, filters=None):
    client = CipherTrustClient(node)
    return client.get(SYNC_JOBS + build_query(filters or {}))


def sync_cancel(node, job_id):
    client = CipherTrustClient(node)
    return client.post(SYNC_JOBS + "/" + quote_segment(job_id) + "/cancel")
