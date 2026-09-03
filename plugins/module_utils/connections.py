# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""Cloud connections in CipherTrust Manager's connection manager.

The connection-manager API is symmetric across cloud providers: every
provider exposes the same six operations under
``connectionmgmt/services/<provider>/connections``, differing only in the
fields a connection carries.  These helpers therefore take the provider as an
argument rather than being duplicated four times; the per-provider field sets
live in the modules, where the argument spec documents and validates them.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    CipherTrustClient,
    build_request_payload,
    quote_segment,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    AnsibleCMParameterException,
)


# Providers this collection supports connections for.  CipherTrust Manager's
# connection manager also serves non-cloud services (LDAP, SMB, Luna HSM,
# Hadoop, log forwarders and others); those have their own field sets and are
# not covered here.
SUPPORTED_CLOUDS = ("aws", "azure", "gcp", "oci")


def _service_path(cloud):
    """Return the connections collection path for *cloud*.

    Guards the provider name because it is interpolated into the URL. The
    modules constrain it with ``choices``, so reaching this error means a
    caller inside the collection passed something unexpected.
    """
    return _cloud_root(cloud) + "/connections"


def _cloud_root(cloud):
    """Return the service root for *cloud*, rejecting anything unexpected.

    The provider name is interpolated into the URL, and the modules constrain
    it with ``choices``, so reaching this error means a caller inside the
    collection passed something the API does not serve.
    """
    if cloud not in SUPPORTED_CLOUDS:
        raise AnsibleCMParameterException(
            message="unsupported cloud for a connection",
            parameter="cloud",
            valid_values=", ".join(SUPPORTED_CLOUDS),
        )
    return "connectionmgmt/services/" + cloud


def create(node, cloud, **fields):
    """Create a cloud connection."""
    client = CipherTrustClient(node)
    return client.post(
        _service_path(cloud),
        data=build_request_payload(fields),
    )


def patch(node, cloud, connection_id, **fields):
    """Update an existing cloud connection.

    *connection_id* accepts the connection's id or its name; CipherTrust
    Manager resolves either on this path.
    """
    client = CipherTrustClient(node)
    return client.patch(
        _service_path(cloud) + "/" + quote_segment(connection_id),
        data=build_request_payload(fields),
    )


def test_existing(node, cloud, connection_id):
    """Ask CipherTrust Manager to test a stored connection's credentials."""
    client = CipherTrustClient(node)
    return client.post(
        _service_path(cloud) + "/" + quote_segment(connection_id) + "/test",
    )


def test_parameters(node, cloud, **fields):
    """Test credentials without storing them.

    Posts to the provider's ``connection-test`` endpoint, which validates a
    candidate set of credentials and returns the result without creating a
    connection.
    """
    client = CipherTrustClient(node)
    return client.post(
        _cloud_root(cloud) + "/connection-test",
        data=build_request_payload(fields),
    )


# ---------------------------------------------------------------------------
# Reading a test result
#
# CipherTrust Manager answers a failed connection test with HTTP 200 and a
# body saying the connection did not work, rather than an error status. Every
# module that tests a connection has to make the same judgement, so the
# decision lives here rather than being restated five times.
# ---------------------------------------------------------------------------

def test_failed(response):
    """True when CipherTrust Manager reported the test as unsuccessful.

    Only an explicit ``false`` counts. A response that omits the field --
    an older manager, or a change in shape -- is not read as a failure,
    because inventing one would be as wrong as missing one.
    """
    return (response or {}).get("connection_ok") is False


def test_error(response):
    """Why the test failed, as reported by the cloud provider."""
    return (response or {}).get("connection_error") or "no reason given"
