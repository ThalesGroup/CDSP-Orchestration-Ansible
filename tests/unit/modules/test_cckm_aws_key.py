# -*- coding: utf-8 -*-
"""``cckm_aws_key``: the behaviour the generic contracts cannot state.

The action contract already checks that each op_type reaches the right URL.
What is specific to this module is what goes *in* the request, and what
counts as "this key already exists" -- an AWS alias is unique only within one
region of one account, and an AWS key has no other user-chosen name.

Only the HTTP client is faked; the payload asserted on is the one the
collection would really send.
"""

import json

import pytest

from module_harness import make_client, run_main

KEY = {"id": "key-1", "region": "us-east-1", "kms": "aws-prod"}


def _create(**extra):
    params = {"op_type": "create", "kms": "aws-prod", "region": "us-east-1"}
    params.update(extra)
    return params


def _posted(client):
    """The body of the last POST, decoded."""
    data = client.post.call_args[1].get("data")
    return json.loads(data) if data else {}


class TestCreateIdempotency:

    def test_creates_when_no_key_holds_the_alias(self):
        client = make_client(get={"resources": []})
        result = run_main("cckm_aws_key",
                          _create(aws_param={"alias": "payments"}),
                          client=client)

        assert not result.failed, result.msg
        assert result.changed is True
        assert client.post.called

    def test_second_run_reports_no_change(self):
        client = make_client(get={"resources": [KEY]})
        result = run_main("cckm_aws_key",
                          _create(aws_param={"alias": "payments"}),
                          client=client)

        assert not result.failed, result.msg
        assert result.changed is False
        assert not result.wrote(), (
            "an existing key must not be created again: %s" % (result.write_calls(),))
        assert result.kwargs["response"] == KEY

    def test_the_lookup_is_scoped_to_region_and_account(self):
        """An alias is unique within one region of one account, so all three
        have to be asked for -- otherwise a key in another region is adopted
        and no key is created where one was wanted."""
        client = make_client(get={"resources": []})
        run_main("cckm_aws_key", _create(aws_param={"alias": "payments"}),
                 client=client)

        url = client.get.call_args[0][0]
        assert "alias=payments" in url
        assert "region=us-east-1" in url
        assert "kms=aws-prod" in url

    def test_a_same_named_key_in_another_region_is_not_adopted(self):
        elsewhere = dict(KEY, region="eu-west-1")
        client = make_client(get={"resources": [elsewhere]})
        result = run_main("cckm_aws_key",
                          _create(aws_param={"alias": "payments"}),
                          client=client)

        assert result.changed is True
        assert client.post.called, "a key was wanted in us-east-1 and none was created"

    def test_without_an_alias_the_create_proceeds(self):
        """An AWS key has no other user-chosen name, so there is nothing to
        match on and nothing to look up."""
        client = make_client()
        result = run_main("cckm_aws_key", _create(), client=client)

        assert result.changed is True
        assert client.post.called
        assert not client.get.called, "nothing to look a nameless key up by"

    def test_check_mode_does_not_create(self):
        client = make_client(get={"resources": []})
        result = run_main("cckm_aws_key",
                          _create(aws_param={"alias": "payments"}),
                          client=client, check_mode=True)

        assert result.changed is True
        assert not result.wrote(), "check mode must not write"

    def test_upload_is_idempotent_on_the_same_alias(self):
        client = make_client(get={"resources": [KEY]})
        result = run_main("cckm_aws_key",
                          {"op_type": "upload", "kms": "aws-prod",
                           "region": "us-east-1", "source_key_identifier": "src-1",
                           "aws_param": {"alias": "payments"}},
                          client=client)

        assert result.changed is False
        assert not result.wrote()


class TestPayloadTranslation:

    def test_key_parameters_are_sent_in_the_casing_aws_requires(self):
        client = make_client(get={"resources": []})
        run_main("cckm_aws_key", _create(aws_param={
            "alias": "payments",
            "description": "Encrypts the payments table",
            "customer_master_key_spec": "RSA_4096",
            "key_usage": "SIGN_VERIFY",
            "multi_region": True,
        }), client=client)

        assert _posted(client)["aws_param"] == {
            "Alias": "payments",
            "Description": "Encrypts the payments table",
            "CustomerMasterKeySpec": "RSA_4096",
            "KeyUsage": "SIGN_VERIFY",
            "MultiRegion": True,
        }

    def test_tags_are_translated(self):
        client = make_client(get={"resources": []})
        run_main("cckm_aws_key", _create(aws_param={
            "alias": "payments",
            "tags": [{"tag_key": "env", "tag_value": "prod"}],
        }), client=client)

        assert _posted(client)["aws_param"]["Tags"] == [
            {"TagKey": "env", "TagValue": "prod"}]

    def test_unset_suboptions_are_not_sent(self):
        """AnsibleModule fills every unset suboption with None, and AWS reads
        an explicit null as a request to clear the field."""
        client = make_client(get={"resources": []})
        run_main("cckm_aws_key", _create(aws_param={
            "alias": "payments", "description": None, "origin": None,
        }), client=client)

        assert _posted(client)["aws_param"] == {"Alias": "payments"}

    def test_add_tags_uses_the_snake_case_this_endpoint_wants(self):
        """Unlike aws_param.Tags on a create, this endpoint takes tag_key."""
        client = make_client()
        run_main("cckm_aws_key",
                 {"op_type": "add_tags", "key_id": "key-1",
                  "tags": [{"tag_key": "env", "tag_value": "prod"}]},
                 client=client)

        assert _posted(client) == {
            "tags": [{"tag_key": "env", "tag_value": "prod"}]}

    def test_remove_tags_sends_bare_keys(self):
        """This endpoint takes a list of tag keys, not key/value pairs."""
        client = make_client()
        run_main("cckm_aws_key",
                 {"op_type": "remove_tags", "key_id": "key-1",
                  "tag_keys": ["env", "cost-centre"]},
                 client=client)

        assert _posted(client) == {"tags": ["env", "cost-centre"]}

    def test_update_primary_region_uses_the_pascal_case_field(self):
        client = make_client()
        run_main("cckm_aws_key",
                 {"op_type": "update_primary_region", "key_id": "key-1",
                  "primary_region": "eu-west-1"},
                 client=client)

        assert _posted(client) == {"PrimaryRegion": "eu-west-1"}

    def test_schedule_deletion_carries_the_waiting_period(self):
        client = make_client()
        run_main("cckm_aws_key",
                 {"op_type": "schedule_deletion", "key_id": "key-1", "days": 30},
                 client=client)

        assert _posted(client) == {"days": 30}


class TestReadsAreNotWrites:
    """Two operations only read. Treating them as writes would make --check
    skip them and report a change that never happens."""

    @pytest.mark.parametrize("op_type", ["get_rotation_status",
                                         "download_public_key"])
    def test_reports_no_change(self, op_type):
        client = make_client()
        result = run_main("cckm_aws_key",
                          {"op_type": op_type, "key_id": "key-1"},
                          client=client)

        assert not result.failed, result.msg
        assert result.changed is False

    @pytest.mark.parametrize("op_type", ["get_rotation_status",
                                         "download_public_key"])
    def test_still_runs_under_check_mode(self, op_type):
        client = make_client()
        result = run_main("cckm_aws_key",
                          {"op_type": op_type, "key_id": "key-1"},
                          client=client, check_mode=True)

        assert not result.failed, result.msg
        assert result.kwargs.get("response") is not None


class TestDestructiveOperationsHonourCheckMode:
    """These destroy keys, or the data encrypted under them. --check must
    never perform one."""

    @pytest.mark.parametrize("params", [
        {"op_type": "schedule_deletion", "key_id": "key-1", "days": 7},
        {"op_type": "delete", "key_id": "key-1"},
        {"op_type": "delete_material", "key_id": "key-1"},
        {"op_type": "disable", "key_id": "key-1"},
        {"op_type": "rotate", "key_id": "key-1"},
    ], ids=lambda p: p["op_type"])
    def test_check_mode_does_not_act(self, params):
        client = make_client()
        result = run_main("cckm_aws_key", params, client=client,
                          check_mode=True)

        assert not result.failed, result.msg
        assert result.changed is True
        assert not result.wrote(), (
            "check mode performed a destructive action: %s" % (result.write_calls(),))
