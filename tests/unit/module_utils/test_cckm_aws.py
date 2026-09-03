# -*- coding: utf-8 -*-
"""The CCKM AWS request layer.

Three things here are easy to get wrong in ways no live test would catch
quickly, so they are pinned down directly:

* **Nested nulls.** ``AnsibleModule`` materialises every declared suboption,
  so a playbook that sets one field of ``aws_param`` produces a dict full of
  ``None``. AWS reads an explicit ``Description: null`` as a request to clear
  the description, so sending those nulls quietly changes the key.
* **Multi-valued filters.** CCKM declares them ``collectionFormat: multi``.
  A comma-joined value is not an error -- it is one filter whose value happens
  to contain a comma, which silently matches nothing.
* **The action whitelist.** Action names are interpolated into the URL.
"""

import json

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_aws,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    AnsibleCMParameterException,
)


class TestPrune:

    def test_drops_nulls_at_the_top_level(self):
        assert cckm_aws.prune({"a": 1, "b": None}) == {"a": 1}

    def test_drops_nulls_inside_a_nested_dict(self):
        """The case AnsibleModule creates on every task with suboptions."""
        pruned = cckm_aws.prune(
            {"aws_param": {"Alias": "payments", "Description": None,
                           "KeyUsage": None}}
        )
        assert pruned == {"aws_param": {"Alias": "payments"}}

    def test_drops_a_dict_that_is_empty_after_pruning(self):
        """An untouched aws_param must vanish, not be sent as {}."""
        assert cckm_aws.prune({"aws_param": {"Alias": None}}) is None

    def test_prunes_inside_a_list_of_dicts(self):
        pruned = cckm_aws.prune(
            {"Tags": [{"TagKey": "env", "TagValue": None}]}
        )
        assert pruned == {"Tags": [{"TagKey": "env"}]}

    def test_keeps_false_and_zero(self):
        """False is a value a playbook chose; only None means 'unset'."""
        assert cckm_aws.prune(
            {"blocked": False, "days": 0, "name": ""}
        ) == {"blocked": False, "days": 0, "name": ""}

    def test_keeps_a_nested_false(self):
        assert cckm_aws.prune(
            {"local_hosted_params": {"blocked": False, "partition_id": None}}
        ) == {"local_hosted_params": {"blocked": False}}


class TestAwsKeyParams:
    """The modules spell key parameters snake_case; AWS spells them
    PascalCase, and rejects anything else."""

    def test_translates_field_names(self):
        assert cckm_aws.aws_key_params({
            "alias": "payments",
            "customer_master_key_spec": "RSA_4096",
            "bypass_policy_lockout_safety_check": True,
        }) == {
            "Alias": "payments",
            "CustomerMasterKeySpec": "RSA_4096",
            "BypassPolicyLockoutSafetyCheck": True,
        }

    def test_translates_tags(self):
        assert cckm_aws.aws_key_params({
            "tags": [{"tag_key": "env", "tag_value": "prod"}],
        }) == {"Tags": [{"TagKey": "env", "TagValue": "prod"}]}

    def test_drops_the_nulls_ansible_supplies(self):
        assert cckm_aws.aws_key_params({
            "alias": "payments", "description": None, "origin": None,
            "tags": None,
        }) == {"Alias": "payments"}

    def test_an_untouched_param_block_becomes_nothing(self):
        assert cckm_aws.aws_key_params({"alias": None}) is None
        assert cckm_aws.aws_key_params(None) is None


class TestQueryBuilding:

    def test_a_list_repeats_the_key(self):
        """collectionFormat: multi -- not a comma-joined value."""
        query = cckm_aws._query({"region": ["us-east-1", "eu-west-1"]})
        assert query == "?region=us-east-1&region=eu-west-1"

    def test_booleans_are_lowercased(self):
        """?enabled=True is not what the API reads as true."""
        assert cckm_aws._query({"enabled": True}) == "?enabled=true"
        assert cckm_aws._query({"enabled": False}) == "?enabled=false"

    def test_nulls_are_omitted(self):
        assert cckm_aws._query({"a": 1, "b": None}) == "?a=1"

    def test_no_filters_gives_no_query_string(self):
        assert cckm_aws._query({}) == ""

    def test_values_are_encoded(self):
        """A filter value must not be able to add another parameter."""
        query = cckm_aws._query({"alias": "a&limit=1000"})
        assert query == "?alias=a%26limit%3D1000"

    def test_zero_is_kept(self):
        """skip=0 is a real value, not an absent one."""
        assert cckm_aws._query({"skip": 0}) == "?skip=0"


class TestActionWhitelists:
    """Action names reach the URL, so an unknown one is refused rather than
    requested."""

    @pytest.mark.parametrize("action", sorted(cckm_aws.KEY_ACTIONS))
    def test_every_declared_key_action_is_accepted(self, action):
        assert cckm_aws._guard(action, cckm_aws.KEY_ACTIONS, "action") == action

    def test_an_unknown_key_action_is_refused(self):
        with pytest.raises(AnsibleCMParameterException):
            cckm_aws._guard("../../vault/keys2", cckm_aws.KEY_ACTIONS, "action")

    def test_an_unknown_sync_scope_is_refused(self):
        with pytest.raises(AnsibleCMParameterException):
            cckm_aws._sync_root("everything")

    def test_the_two_sync_scopes_are_different_services(self):
        assert (cckm_aws._sync_root("keys")
                != cckm_aws._sync_root("custom-key-stores"))


class TestPayload:

    def test_builds_json_with_nested_nulls_removed(self):
        body = json.loads(cckm_aws._payload({
            "kms": "aws-prod",
            "region": None,
            "aws_param": {"Alias": "a", "Description": None},
        }))
        assert body == {"kms": "aws-prod", "aws_param": {"Alias": "a"}}

    def test_an_entirely_empty_payload_is_an_empty_object(self):
        assert json.loads(cckm_aws._payload({"a": None})) == {}
