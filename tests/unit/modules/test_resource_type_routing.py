# -*- coding: utf-8 -*-
"""``resource_type`` must route to the right CipherTrust endpoint.

``cm_resource_delete`` and ``cm_resource_get_id_from_name`` translate a
resource_type into an API path with a long if/elif chain. A wrong entry sends
a request -- including a DELETE -- to the wrong collection, so the mapping is
stated here independently of the implementation rather than derived from it.
"""

import pytest

from module_harness import make_client, run_main

# resource_type -> API path. Written out deliberately; do not generate this
# from the module source, or the test would only prove it agrees with itself.
ENDPOINTS = {
    "keys": "vault/keys2",
    "interfaces": "configs/interfaces",
    "users": "usermgmt/users",
    "client-profiles": "data-protection/client-profiles",
    "dpg-policies": "data-protection/dpg-policies",
    "access-policies": "data-protection/access-policies",
    "user-sets": "data-protection/user-sets",
    "character-sets": "data-protection/character-sets",
    "masking-formats": "data-protection/masking-formats",
    "resourceset": "transparent-encryption/resourcesets",
    "signatureset": "transparent-encryption/signaturesets",
    "userset": "transparent-encryption/usersets",
    "processset": "transparent-encryption/processsets",
    "cte-policy": "transparent-encryption/policies",
    "cte-client-group": "transparent-encryption/clientgroups",
    "csigroup": "transparent-encryption/csigroups",
    "azure-key-vault": "cckm/azure/vaults",
    "azure-secret": "cckm/azure/secrets",
    "azure-certificate": "cckm/azure/certificates",
    "azure-key": "cckm/azure/keys",
}

DELETE_ONLY = {
    "protection-policies": "data-protection/protection-policies",
    # Cloud connections are deletable but are not resolvable by name through
    # cm_resource_get_id_from_name, so they belong here rather than above.
    "aws-connection": "connectionmgmt/services/aws/connections",
    "azure-connection": "connectionmgmt/services/azure/connections",
    "gcp-connection": "connectionmgmt/services/gcp/connections",
    "oci-connection": "connectionmgmt/services/oci/connections",
}
GET_ONLY = {"cte-client": "transparent-encryption/clients"}

DELETE_ENDPOINTS = dict(ENDPOINTS, **DELETE_ONLY)
GET_ENDPOINTS = dict(ENDPOINTS, **GET_ONLY)


@pytest.mark.parametrize("resource_type,endpoint",
                         sorted(DELETE_ENDPOINTS.items()))
def test_delete_targets_the_right_collection(resource_type, endpoint):
    client = make_client()
    result = run_main("cm_resource_delete",
                      {"resource_type": resource_type, "key": "res-1"},
                      client=client)

    assert not result.failed, result.msg
    urls = [call[0][0] for call in client.delete.call_args_list if call[0]]
    assert urls == [endpoint + "/res-1"]


@pytest.mark.parametrize("resource_type,endpoint",
                         sorted(GET_ENDPOINTS.items()))
def test_lookup_queries_the_right_collection(resource_type, endpoint):
    # CM returns user_id for users and id elsewhere; supply both so this
    # test is about routing, not about the id field name.
    client = make_client(get={"resources": [
        {"id": "res-1", "user_id": "local|res-1", "name": "thing"},
    ]})
    result = run_main("cm_resource_get_id_from_name",
                      {"resource_type": resource_type,
                       "query_param": "name",
                       "query_param_value": "thing"},
                      client=client)

    assert not result.failed, result.msg
    urls = [call[0][0] for call in client.get.call_args_list if call[0]]
    assert len(urls) == 1
    assert urls[0].startswith(endpoint + "/?")
    assert "name=thing" in urls[0]


def test_unsupported_resource_type_is_rejected():
    client = make_client()
    result = run_main("cm_resource_delete",
                      {"resource_type": "not-a-thing", "key": "res-1"},
                      client=client)

    assert result.failed
    assert not client.delete.called, "an unknown type must not reach the API"


def test_missing_id_field_fails_cleanly():
    """A resource without the expected id field must not raise KeyError."""
    client = make_client(get={"resources": [{"name": "thing"}]})
    result = run_main("cm_resource_get_id_from_name",
                      {"resource_type": "users",
                       "query_param": "name",
                       "query_param_value": "thing"},
                      client=client)

    assert result.failed
    assert "user_id" in result.msg
