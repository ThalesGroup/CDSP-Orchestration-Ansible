# -*- coding: utf-8 -*-
"""The idempotency machinery CCKM's AWS resources needed.

Three additions, each answering a way the existing comparison reported a
change that was not one -- the failure mode that makes a module re-send the
same request for ever and makes ``--check`` useless:

* **Response aliases.** CCKM accepts ``key_admins`` and answers with
  ``key-admins``.
* **Subset comparison.** A PATCH merges into a sub-object, and CM returns far
  more of it than a playbook sets.
* **Multi-field lookup.** An AWS alias is unique only within one region of one
  account, so "does this key already exist?" is not a single-field question.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    _differs_as_subset,
    find_resource_by_filters,
    resource_needs_update,
)
from module_harness import make_client


class TestResponseAliases:

    def test_a_field_reported_under_another_name_is_not_a_change(self):
        current = {"key-admins": ["alice"]}
        desired = {"key_admins": ["alice"]}
        assert not resource_needs_update(
            current, desired, response_aliases={"key_admins": "key-admins"})

    def test_a_real_difference_under_the_alias_is_still_seen(self):
        current = {"key-admins": ["alice"]}
        desired = {"key_admins": ["bob"]}
        assert resource_needs_update(
            current, desired, response_aliases={"key_admins": "key-admins"})

    def test_the_canonical_name_wins_when_both_are_present(self):
        """If CM ever reports both, the exact name is the authority."""
        current = {"key_admins": ["alice"], "key-admins": ["stale"]}
        desired = {"key_admins": ["alice"]}
        assert not resource_needs_update(
            current, desired, response_aliases={"key_admins": "key-admins"})

    def test_absent_under_either_name_is_a_change(self):
        assert resource_needs_update(
            {"name": "cks"}, {"key_admins": ["alice"]},
            response_aliases={"key_admins": "key-admins"})


class TestSubsetComparison:

    def test_extra_fields_in_the_response_are_not_a_change(self):
        """CM returns connection_state and the XKS URI path; a playbook sets
        neither, and a PATCH would not clear them."""
        current = {"aws_param": {
            "xks_proxy_uri_endpoint": "https://xks.example.com",
            "connection_state": "CONNECTED",
            "xks_proxy_uri_path": "/api/v1/...",
        }}
        desired = {"aws_param": {
            "xks_proxy_uri_endpoint": "https://xks.example.com"}}
        assert not resource_needs_update(
            current, desired, subset_fields=("aws_param",))

    def test_a_changed_nested_value_is_seen(self):
        current = {"aws_param": {"xks_proxy_uri_endpoint": "https://old"}}
        desired = {"aws_param": {"xks_proxy_uri_endpoint": "https://new"}}
        assert resource_needs_update(
            current, desired, subset_fields=("aws_param",))

    def test_a_nested_field_the_response_lacks_is_a_change(self):
        current = {"aws_param": {"connection_state": "CONNECTED"}}
        desired = {"aws_param": {"xks_proxy_uri_endpoint": "https://x"}}
        assert resource_needs_update(
            current, desired, subset_fields=("aws_param",))

    def test_without_the_option_extra_fields_do_report_a_change(self):
        """The default stays exact equality -- this is opt-in."""
        current = {"aws_param": {"a": 1, "b": 2}}
        desired = {"aws_param": {"a": 1}}
        assert resource_needs_update(current, desired)

    def test_a_list_is_compared_whole(self):
        """A PATCH replaces a list rather than merging into it."""
        assert _differs_as_subset(["a", "b"], ["a"])
        assert not _differs_as_subset(["a", "b"], ["a", "b"])

    def test_nested_nulls_in_the_desired_state_are_ignored(self):
        """AnsibleModule fills unset suboptions with None; those are not
        requests to clear anything."""
        current = {"aws_param": {"xks_proxy_uri_endpoint": "https://x"}}
        desired = {"aws_param": {"xks_proxy_uri_endpoint": "https://x",
                                 "cloud_hsm_cluster_id": None}}
        assert not resource_needs_update(
            current, desired, subset_fields=("aws_param",))

    def test_a_scalar_where_a_dict_is_wanted_is_a_change(self):
        assert _differs_as_subset("not-a-dict", {"a": 1})


class TestFindResourceByFilters:

    KEY = {"id": "key-1", "region": "us-east-1", "kms": "aws-prod"}

    def test_sends_every_filter(self):
        client = make_client(get={"resources": [self.KEY]})
        find_resource_by_filters(
            client, "cckm/aws/keys",
            filters={"alias": "payments", "region": "us-east-1",
                     "kms": "aws-prod"})

        url = client.get.call_args[0][0]
        assert "alias=payments" in url
        assert "region=us-east-1" in url
        assert "kms=aws-prod" in url

    def test_returns_the_match(self):
        client = make_client(get={"resources": [self.KEY]})
        found = find_resource_by_filters(
            client, "cckm/aws/keys",
            filters={"region": "us-east-1", "kms": "aws-prod"},
            confirm_fields=("region", "kms"))
        assert found == self.KEY

    def test_an_ignored_filter_is_not_taken_as_a_match(self):
        """CM answers an unsupported filter by ignoring it and returning the
        first resource in the collection. Adopting that would have a create
        silently do nothing -- or adopt a key from the wrong region."""
        wrong_region = dict(self.KEY, region="eu-west-1")
        client = make_client(get={"resources": [wrong_region]})
        found = find_resource_by_filters(
            client, "cckm/aws/keys",
            filters={"region": "us-east-1", "kms": "aws-prod"},
            confirm_fields=("region", "kms"))
        assert found is None

    def test_no_results_is_no_match(self):
        client = make_client(get={"resources": []})
        assert find_resource_by_filters(
            client, "cckm/aws/keys", filters={"kms": "aws-prod"}) is None

    def test_no_filters_means_no_lookup(self):
        """Without a filter the query would match the whole collection, and
        the first key in it is not 'the key this task would create'."""
        client = make_client(get={"resources": [self.KEY]})
        assert find_resource_by_filters(
            client, "cckm/aws/keys", filters={"alias": None}) is None
        assert not client.get.called

    def test_a_404_means_absent(self):
        client = make_client(
            get=CMApiException(message="not found", api_error_code=404))
        assert find_resource_by_filters(
            client, "cckm/aws/keys", filters={"kms": "aws-prod"}) is None

    def test_any_other_error_propagates(self):
        """A 403 read as 'absent' would lead straight to a duplicate key."""
        client = make_client(
            get=CMApiException(message="forbidden", api_error_code=403))
        with pytest.raises(CMApiException):
            find_resource_by_filters(
                client, "cckm/aws/keys", filters={"kms": "aws-prod"})
