# -*- coding: utf-8 -*-
"""Contract for the action-style modules.

These modules perform an operation rather than converging on a desired state,
so the contract is different from the save modules: the right verb must reach
the right endpoint, ``--check`` must not perform the action, and a CM error
must surface through ``fail_json``.

As with the save-module contract, only the HTTP client is faked -- the URL
under assertion is the one the collection would really request.
"""

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)
from module_harness import make_client, run_main


class Action(object):
    def __init__(self, module, params, verb, endpoint, writes=True,
                 get_response=None, label=None):
        self.module = module
        self.params = params
        self.verb = verb
        self.endpoint = endpoint
        self.writes = writes            # False for read-only operations
        self.get_response = get_response
        self.label = label or "{0}:{1}".format(
            module, params.get("op_type", "run"))

    def __repr__(self):
        return self.label


IFACE = "configs/interfaces/iface-1"

ACTIONS = [
    Action("cm_services", {"op_type": "restart"},
           "post", "system/services/restart"),

    Action("group_add_remove_object",
           {"op_type": "add", "object_type": "user",
            "name": "grp-1", "object_id": "usr-1"},
           "post", "usermgmt/groups/grp-1/users/usr-1"),
    Action("group_add_remove_object",
           {"op_type": "add", "object_type": "client",
            "name": "grp-1", "object_id": "cli-1"},
           "post", "client-management/groups/grp-1/clients/cli-1"),
    Action("group_add_remove_object",
           {"op_type": "remove", "object_type": "user",
            "name": "grp-1", "object_id": "usr-1"},
           "delete", "usermgmt/groups/grp-1/users/usr-1"),
    Action("group_add_remove_object",
           {"op_type": "remove", "object_type": "client",
            "name": "grp-1", "object_id": "cli-1"},
           "delete", "client-management/groups/grp-1/clients/cli-1"),

    Action("interface_actions",
           {"op_type": "enable", "interface_id": "iface-1"},
           "post", IFACE + "/enable"),
    Action("interface_actions",
           {"op_type": "disable", "interface_id": "iface-1"},
           "post", IFACE + "/disable"),
    Action("interface_actions",
           {"op_type": "get_certificate", "interface_id": "iface-1"},
           "get", IFACE + "/certificate", writes=False),
    Action("interface_actions",
           {"op_type": "restore-default-tls-ciphers", "interface_id": "iface-1"},
           "post", IFACE + "/restore-default-tls-ciphers"),
    Action("interface_actions",
           {"op_type": "auto-gen-server-cert", "interface_id": "iface-1"},
           "post", IFACE + "/auto-gen-server-cert"),

    Action("license_create", {"license_string": "LICENSE-BLOB"},
           "post", "licensing/licenses"),
    Action("license_trial_action",
           {"action_type": "activate", "trialId": "trial-1"},
           "post", "licensing/trials/trial-1/activate",
           label="license_trial_action:activate"),
    Action("license_trial_action",
           {"action_type": "deactivate", "trialId": "trial-1"},
           "post", "licensing/trials/trial-1/deactivate",
           label="license_trial_action:deactivate"),

    Action("license_trial_get", {"name": "trial"},
           "get", "licensing/trials", writes=False,
           get_response={"resources": [{"id": "trial-1", "status": "active"}]}),
    Action("licensing_lockdata_get", {},
           "get", "licensing/lockdata", writes=False),

    Action("cm_regtoken", {"op_type": "create", "name_prefix": "node"},
           "post", "client-management/regtokens"),

    Action("cm_cluster", {"op_type": "new"}, "post", "cluster/new",
           label="cm_cluster:new"),

    # resource_type selects the endpoint; check one of each family
    Action("cm_resource_delete",
           {"resource_type": "keys", "key": "key-1"},
           "delete", "vault/keys2/key-1", label="cm_resource_delete:keys"),
    Action("cm_resource_delete",
           {"resource_type": "users", "key": "usr-1"},
           "delete", "usermgmt/users/usr-1", label="cm_resource_delete:users"),

    Action("cm_resource_delete",
           {"resource_type": "cluster"},
           "delete", "cluster", label="cm_resource_delete:cluster"),

    Action("cm_resource_get_id_from_name",
           {"resource_type": "keys", "query_param": "name",
            "query_param_value": "my-key"},
           "get", "vault/keys2/?skip=0&limit=1&name=my-key", writes=False,
           get_response={"resources": [{"id": "key-1", "name": "my-key"}]},
           label="cm_resource_get_id_from_name:keys"),
]

WRITE_ACTIONS = [a for a in ACTIONS if a.writes]

all_actions = pytest.mark.parametrize(
    "action", ACTIONS, ids=[a.label for a in ACTIONS]
)
write_actions = pytest.mark.parametrize(
    "action", WRITE_ACTIONS, ids=[a.label for a in WRITE_ACTIONS]
)


def _client_for(action):
    return make_client(get=action.get_response)


@all_actions
class TestActionReachesTheRightEndpoint:

    def test_calls_expected_verb_and_endpoint(self, action):
        client = _client_for(action)
        result = run_main(action.module, action.params, client=client)

        assert not result.failed, result.msg
        called = getattr(client, action.verb)
        assert called.called, (
            "expected a %s; saw %s" % (action.verb.upper(), result.write_calls())
        )
        urls = [call[0][0] for call in called.call_args_list if call[0]]
        assert action.endpoint in urls, (
            "expected %s %s, saw %s" % (action.verb.upper(), action.endpoint, urls)
        )

    def test_api_error_becomes_fail_json(self, action):
        client = make_client(
            get=CMApiException(message="Forbidden", api_error_code=403),
            post=CMApiException(message="Forbidden", api_error_code=403),
            delete=CMApiException(message="Forbidden", api_error_code=403),
        )
        result = run_main(action.module, action.params, client=client)

        assert result.failed, "a CM error must fail the module cleanly"
        assert "403" in result.msg


@write_actions
class TestCheckModeMakesNoChange:

    def test_check_mode_does_not_act(self, action):
        client = _client_for(action)
        result = run_main(action.module, action.params,
                          client=client, check_mode=True)

        assert not result.failed, result.msg
        assert result.changed is True, "an action module reports changed in check mode"
        assert not result.wrote(), (
            "check mode performed a write: %s" % (result.write_calls(),)
        )


class TestResourceDeleteTargetsTheResource:
    """cm_resource_delete is documented as "delete resource using ID".

    Every keyed resource type must delete <endpoint>/<key> and never the bare
    collection endpoint; a missing key must be reported rather than silently
    widening the request.
    """

    @pytest.mark.parametrize("resource_type,endpoint", [
        ("keys", "vault/keys2"),
        ("users", "usermgmt/users"),
        ("interfaces", "configs/interfaces"),
        ("dpg-policies", "data-protection/dpg-policies"),
        ("access-policies", "data-protection/access-policies"),
    ])
    def test_deletes_the_named_resource_only(self, resource_type, endpoint):
        client = make_client()
        result = run_main("cm_resource_delete",
                          {"resource_type": resource_type, "key": "res-1"},
                          client=client)

        assert not result.failed, result.msg
        urls = [call[0][0] for call in client.delete.call_args_list if call[0]]
        assert urls == [endpoint + "/res-1"], (
            "must delete one resource, not the %s collection" % endpoint
        )

    def test_cluster_deletes_the_singleton_without_a_key(self):
        """resource_type: cluster has no per-resource id -- DELETE /cluster."""
        client = make_client()
        result = run_main("cm_resource_delete", {"resource_type": "cluster"},
                          client=client)

        assert not result.failed, result.msg
        urls = [call[0][0] for call in client.delete.call_args_list if call[0]]
        assert urls == ["cluster"]

    def test_missing_key_fails_in_check_mode_too(self):
        """--check must predict the failure a real run would hit."""
        client = make_client()
        result = run_main("cm_resource_delete", {"resource_type": "keys"},
                          client=client, check_mode=True)

        assert result.failed, "check mode reported success for a task that cannot run"
        assert "key" in result.msg
        assert not client.delete.called

    def test_missing_key_is_reported(self):
        client = make_client()
        result = run_main("cm_resource_delete",
                          {"resource_type": "keys"}, client=client)

        assert result.failed
        assert "key" in result.msg
        assert not client.delete.called, "no request may be sent without a key"
