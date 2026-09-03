# -*- coding: utf-8 -*-
"""Unit tests for plugins/module_utils/connections.py

The connection-manager API is symmetric across providers, so these tests
assert the URL each helper builds for every supported cloud rather than
testing one provider and assuming the rest follow.
"""

import json

import pytest
from unittest.mock import MagicMock, patch

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    connections,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    AnsibleCMParameterException,
)

from test_helpers import TEST_NODE

CLOUDS = ["aws", "azure", "gcp", "oci"]


@pytest.fixture
def client():
    """Patch the client class connections.py builds, and hand back the instance."""
    instance = MagicMock(name="CipherTrustClient")
    instance.post.return_value = {"id": "conn-1"}
    instance.patch.return_value = {"id": "conn-1"}
    with patch.object(connections, "CipherTrustClient", return_value=instance):
        yield instance


class TestSupportedClouds:
    def test_only_the_four_cloud_providers(self):
        """The connection manager also serves LDAP, SMB, Luna and others.

        Those have different field sets and are not covered by these modules,
        so they must not be reachable through this path.
        """
        assert connections.SUPPORTED_CLOUDS == ("aws", "azure", "gcp", "oci")

    @pytest.mark.parametrize("cloud", CLOUDS)
    def test_service_path_per_cloud(self, cloud):
        assert connections._service_path(cloud) == (
            "connectionmgmt/services/%s/connections" % cloud
        )

    @pytest.mark.parametrize("bad", ["ldap", "smb", "luna-network", "", "AWS",
                                     "../../vault/keys2"])
    def test_rejects_anything_not_a_supported_cloud(self, bad):
        """The provider is interpolated into the URL, so it must be constrained."""
        with pytest.raises(AnsibleCMParameterException):
            connections._service_path(bad)

    def test_rejects_none(self):
        with pytest.raises(AnsibleCMParameterException):
            connections._service_path(None)


class TestCreate:
    @pytest.mark.parametrize("cloud", CLOUDS)
    def test_posts_to_the_provider_collection(self, cloud, client):
        connections.create(TEST_NODE, cloud, name="c1", description="d")
        endpoint = client.post.call_args[0][0]
        assert endpoint == "connectionmgmt/services/%s/connections" % cloud

    @pytest.mark.parametrize("cloud", CLOUDS)
    def test_sends_only_the_fields_supplied(self, cloud, client):
        """build_request_payload drops None, so an unset option is not sent."""
        connections.create(TEST_NODE, cloud, name="c1", description=None)
        body = json.loads(client.post.call_args[1]["data"])
        assert body == {"name": "c1"}

    def test_returns_the_api_response(self, client):
        client.post.return_value = {"id": "conn-9", "name": "c1"}
        assert connections.create(TEST_NODE, "aws", name="c1")["id"] == "conn-9"


class TestPatch:
    @pytest.mark.parametrize("cloud", CLOUDS)
    def test_patches_the_addressed_connection(self, cloud, client):
        connections.patch(TEST_NODE, cloud, "conn-1", description="new")
        endpoint = client.patch.call_args[0][0]
        assert endpoint == (
            "connectionmgmt/services/%s/connections/conn-1" % cloud
        )

    def test_identifier_is_percent_encoded(self, client):
        """A name is accepted as the identifier, and a name may contain
        characters that would otherwise change the URL's shape."""
        connections.patch(TEST_NODE, "aws", "prod/../../cluster", description="x")
        endpoint = client.patch.call_args[0][0]
        assert "prod%2F..%2F..%2Fcluster" in endpoint
        assert "/cluster" not in endpoint.replace("%2F", "")

    def test_name_with_a_space_is_encoded(self, client):
        connections.patch(TEST_NODE, "azure", "my connection", description="x")
        assert "my%20connection" in client.patch.call_args[0][0]


class TestTestExisting:
    @pytest.mark.parametrize("cloud", CLOUDS)
    def test_posts_to_the_test_subresource(self, cloud, client):
        connections.test_existing(TEST_NODE, cloud, "conn-1")
        endpoint = client.post.call_args[0][0]
        assert endpoint == (
            "connectionmgmt/services/%s/connections/conn-1/test" % cloud
        )

    def test_sends_no_body(self, client):
        """Testing a stored connection needs no payload; CM already has the
        credentials."""
        connections.test_existing(TEST_NODE, "gcp", "conn-1")
        assert "data" not in client.post.call_args[1]

    def test_identifier_is_encoded(self, client):
        connections.test_existing(TEST_NODE, "aws", "a b/c")
        assert "a%20b%2Fc/test" in client.post.call_args[0][0]


class TestTestParameters:
    @pytest.mark.parametrize("cloud", CLOUDS)
    def test_posts_to_the_connection_test_endpoint(self, cloud, client):
        """This endpoint sits on the service root, not under connections."""
        connections.test_parameters(TEST_NODE, cloud, access_key_id="AKIA")
        endpoint = client.post.call_args[0][0]
        assert endpoint == "connectionmgmt/services/%s/connection-test" % cloud
        assert "/connections" not in endpoint

    def test_rejects_an_unsupported_cloud(self):
        with pytest.raises(AnsibleCMParameterException):
            connections.test_parameters(TEST_NODE, "ldap", user="u")

    def test_sends_the_candidate_credentials(self, client):
        connections.test_parameters(
            TEST_NODE, "aws", access_key_id="AKIA", secret_access_key="s"
        )
        body = json.loads(client.post.call_args[1]["data"])
        assert body == {"access_key_id": "AKIA", "secret_access_key": "s"}
