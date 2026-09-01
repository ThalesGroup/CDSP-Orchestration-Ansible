# -*- coding: utf-8 -*-
"""Every advertised ``op_type`` must actually be wired up.

The op_type choices in a module's argument_spec are a promise to users: the
value passes argument validation, so if the dispatch chain has no branch for
it the module accepts the task and then fails with "invalid op_type" -- or
worse, silently falls through to another branch.

This walks the choices out of each module's own argument_spec and drives
main() once per value, asserting only that the value is dispatched. Parameter
validation errors are an acceptable outcome (this test supplies a generic
parameter bag, not a valid one for every operation); "invalid op_type" is not.
"""

import importlib

import pytest

from module_harness import MODULES_ROOT, make_client, run_main

# Enough identifiers to get past the routing code of any operation. Modules
# read what they need and ignore the rest.
GENERIC_PARAMS = {
    # Identifiers and values named by the modules' own required_if rules, so
    # every branch can build its URL. AnsibleModule enforces these in
    # production; this harness bypasses it, so they are supplied here.
    "access_policy_name": "dispatch-test",
    "admins": ["admin"],
    "algorithm": "aes",
    "api_url": "/api/v1/thing",
    "api_url_id": "url-1",
    "app_connector_type": "DPG",
    "cert_id": "cert-1",
    "certificate": "CERT-BLOB",
    "char_set_id": "cs-1",
    "client_id": "cli-1",
    "client_id_list": ["cli-1"],
    "client_list": ["cli-1"],
    "cluster_type": "primary",
    "cm_key_id": "key-1",
    "cm_user_id": "local|12345678-1234-1234-1234-123456789abc",
    "cn": "dispatch.example.com",
    "copy_from": "src-1",
    "csr": "CSR-BLOB",
    "current_keys": [],
    "dataTxRuleId": "dtr-1",
    "destination_url": "http://localhost:8080",
    "domain_id": "dom-1",
    "early_access": True,
    "effect": "permit",
    "format": "pkcs8",
    "gp_id": "gp-1",
    "guard_paths": ["/data"],
    "guard_point_id": "gp-1",
    "guard_point_id_list": ["gp-1"],
    "guard_point_params": {},
    "id": "res-1",
    "idtRuleId": "idt-1",
    "inherit_attributes": True,
    "interface_id": "iface-1",
    "interface_type": "web",
    "k8s_namespace": "default",
    "k8s_storage_class": "standard",
    "key": "res-1",
    "keyRuleId": "kr-1",
    "key_id": "key-1",
    "ldtRuleId": "ldt-1",
    "masking_format_id": "mf-1",
    "name": "dispatch-test",
    "new_password": "NewPassw0rd!",
    "nodes": [],
    "object_id": "obj-1",
    "object_type": "user",
    "old_name": "dispatch-test",
    "password": "Passw0rd!",
    "paused": True,
    "policy_id": "pol-1",
    "policy_list": ["pol-1"],
    "policy_name": "dispatch-test",
    "policy_type": "standard",
    "policy_user_set_id": "pus-1",
    "port": 8443,
    "processIndex": 0,
    "profile_id": "prof-1",
    "purpose": "signing",
    "query_param": "name",
    "query_param_value": "dispatch-test",
    "range": ["0030-0039"],
    "reason": "Unspecified",
    "resourceIndex": 0,
    "resource_type": "keys",
    "securityRuleId": "sr-1",
    "services": ["nae"],
    "signature_id": "sig-1",
    "signatures": ["sig-1"],
    "trialId": "trial-1",
    "action_type": "activate",
    "userIndex": 0,
    "user_set_id": "us-1",
    "username": "dispatch-test",
}


def _op_types(module_name):
    mod = importlib.import_module(MODULES_ROOT + "." + module_name)
    spec = getattr(mod, "argument_spec", {})
    entry = spec.get("op_type") or {}
    return entry.get("choices") or []


MODULES = [
    "cm_certificate_authority", "cm_cluster", "cm_regtoken", "cm_services",
    "cte_client", "cte_client_group", "cte_csi_storage_group",
    "cte_policy_save", "cte_process_set", "cte_resource_set",
    "cte_signature_set", "cte_user_set", "domain_save",
    "dpg_access_policy_save", "dpg_character_set_save",
    "dpg_client_profile_save", "dpg_masking_format_save", "dpg_policy_save",
    "dpg_protection_policy_save", "dpg_user_set_save",
    "group_add_remove_object", "group_save", "interface_actions",
    "interface_save", "usermgmt_users_save", "vault_keys2_op",
    "vault_keys2_save",
]

CASES = [(m, op) for m in MODULES for op in _op_types(m)]


@pytest.mark.parametrize("module_name,op_type", CASES,
                         ids=["%s:%s" % (m, o) for m, o in CASES])
def test_op_type_is_dispatched(module_name, op_type):
    params = dict(GENERIC_PARAMS)
    params["op_type"] = op_type

    client = make_client(get={"resources": [{"id": "res-1",
                                             "user_id": "local|res-1",
                                             "name": "dispatch-test"}]})
    result = run_main(module_name, params, client=client)

    assert "invalid op_type" not in result.msg, (
        "%s advertises op_type '%s' but has no branch handling it"
        % (module_name, op_type)
    )


def test_every_module_under_test_declares_choices():
    """Guard against this suite silently covering nothing."""
    assert len(CASES) > 100, "expected op_type choices to be discovered"
