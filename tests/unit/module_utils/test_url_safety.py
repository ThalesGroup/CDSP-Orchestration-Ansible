# -*- coding: utf-8 -*-
"""Values from playbooks must not be able to reshape the request URL.

Resource names and identifiers are user input. Before these helpers existed
they were concatenated into paths and query strings verbatim, so a name
containing ``&`` injected extra query parameters into the idempotency lookup,
an id containing ``../`` walked the request out of its collection, and an
ordinary space produced a malformed request.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    _build_query_string,
    quote_query_value,
    quote_segment,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    find_resource_by_query,
    idempotent_patch,
)
from module_harness import make_client, run_main


class TestQuoteSegment:

    @pytest.mark.parametrize("raw,expected", [
        ("../../usermgmt/users/admin", "..%2F..%2Fusermgmt%2Fusers%2Fadmin"),
        ("finance team", "finance%20team"),
        ("a/b", "a%2Fb"),
        ("a?b", "a%3Fb"),
        ("a#b", "a%23b"),
        ("a&b", "a%26b"),
        ("plain-name", "plain-name"),
    ])
    def test_encodes_everything_that_could_change_the_path(self, raw, expected):
        assert quote_segment(raw) == expected

    def test_none_becomes_empty(self):
        assert quote_segment(None) == ""

    def test_non_string_values_are_coerced(self):
        assert quote_segment(42) == "42"


class TestQuoteQueryValue:

    def test_keeps_list_separators(self):
        """CM accepts comma-separated index lists; the comma stays literal."""
        assert quote_query_value("0,1,2") == "0,1,2"

    def test_encodes_parameter_injection(self):
        assert quote_query_value("0&limit=1000") == "0%26limit%3D1000"


class TestBuildQueryString:

    def test_values_are_encoded(self):
        query = _build_query_string({"name": "team&limit=1000"})
        assert query == "?name=team%26limit%3D1000"

    def test_omits_none(self):
        assert _build_query_string({"a": 1, "b": None}) == "?a=1"

    def test_empty_is_empty(self):
        assert _build_query_string({}) == ""


class TestLookupsCannotBeSteered:

    def test_name_cannot_inject_query_parameters(self):
        client = make_client(get={"resources": []})
        find_resource_by_query(client, "usermgmt/groups", "name",
                               "team&limit=1000&skip=5")

        url = client.get.call_args[0][0]
        assert url.count("limit=") == 1, url
        assert url.count("skip=") == 1, url

    def test_resource_id_cannot_traverse_out_of_its_collection(self):
        module = make_client()          # any object with check_mode/_diff
        module.check_mode = False
        module._diff = False
        client = make_client(get={})
        idempotent_patch(module, client, endpoint="vault/keys2",
                         resource_id="../../usermgmt/users/admin",
                         patch_fn=lambda **kw: {}, patch_kwargs={"node": {}})

        url = client.get.call_args[0][0]
        assert url.startswith("vault/keys2/")
        assert "/usermgmt/" not in url, url


class TestEndToEndThroughModules:
    """The same three cases, driven through a real module."""

    def test_create_lookup_encodes_the_name(self):
        client = make_client(get={"resources": []})
        run_main("group_save",
                 {"op_type": "create", "name": "team&limit=1000&x=y"},
                 client=client)

        url = client.get.call_args[0][0]
        assert "&x=y" not in url
        assert url.count("limit=") == 1

    def test_delete_encodes_a_traversal_attempt(self):
        client = make_client()
        run_main("cm_resource_delete",
                 {"resource_type": "keys", "key": "../../usermgmt/users/admin"},
                 client=client)

        url = client.delete.call_args[0][0]
        assert url == "vault/keys2/..%2F..%2Fusermgmt%2Fusers%2Fadmin"

    def test_a_name_with_a_space_is_encoded(self):
        client = make_client(get={"resources": []})
        run_main("group_save", {"op_type": "create", "name": "finance team"},
                 client=client)

        assert " " not in client.get.call_args[0][0]
