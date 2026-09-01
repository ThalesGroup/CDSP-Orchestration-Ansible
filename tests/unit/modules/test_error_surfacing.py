# -*- coding: utf-8 -*-
"""Bad input must reach the user as a message, never as a traceback.

The four modules with their own ``validate_parameters`` used to call it
before entering ``ciphertrust_operation``, so a rejected parameter
combination propagated out of ``main()`` and Ansible reported a Python
traceback instead of the carefully written guidance in the exception.
"""

import pytest

from module_harness import make_client, run_main

VALIDATION_CASES = [
    # module, params, fragment expected in the failure message
    ("vault_keys2_save",
     {"op_type": "create", "name": "k", "algorithm": "aes",
      "cm_key_id": "key-1"},
     "cm_key_id"),
    ("vault_keys2_save",
     {"op_type": "create"},
     "algorithm"),
    ("vault_keys2_save",
     {"op_type": "patch"},
     "cm_key_id"),
    ("interface_save",
     {"op_type": "create", "name": "iface"},
     "port"),
    ("interface_save",
     {"op_type": "patch", "port": 8443},
     "interface_id"),
    ("interface_save",
     {"op_type": "create", "interface_type": "web", "port": "not-a-number"},
     "port"),
    ("usermgmt_users_save",
     {"op_type": "create"},
     "username"),
    ("usermgmt_users_save",
     {"op_type": "patch", "username": "u"},
     "cm_user_id"),
    ("dpg_policy_save",
     {"op_type": "create"},
     "name"),
    ("dpg_policy_save",
     {"op_type": "patch"},
     "policy_id"),
]


@pytest.mark.parametrize(
    "module_name,params,fragment", VALIDATION_CASES,
    ids=["%s:%s:%s" % (m, p.get("op_type"), f)
         for m, p, f in VALIDATION_CASES],
)
def test_validation_failure_is_reported_not_raised(module_name, params, fragment):
    client = make_client()
    result = run_main(module_name, params, client=client)

    assert result.failed, "expected a clean failure, not a successful run"
    assert fragment in result.msg, (
        "message should name the offending parameter; got: %s" % result.msg
    )
    assert not result.wrote(), "nothing may be written when input is invalid"


class TestOptionalFiltersAreOptional:
    """``required_if`` decides what a task must supply; the URL builders must
    agree with it rather than assuming every filter is present."""

    def test_signature_lookup_without_file_name(self):
        client = make_client(get={"resources": []})
        result = run_main("cte_signature_set",
                          {"op_type": "get_signature", "id": "sigset-1"},
                          client=client)

        assert not result.failed, result.msg
        urls = [call[0][0] for call in client.get.call_args_list if call[0]]
        assert urls == [
            "transparent-encryption/signaturesets/sigset-1"
            "/signatures?skip=0&limit=1"
        ]

    def test_signature_lookup_with_file_name(self):
        client = make_client(get={"resources": []})
        result = run_main("cte_signature_set",
                          {"op_type": "get_signature", "id": "sigset-1",
                           "file_name": "app.exe"},
                          client=client)

        assert not result.failed, result.msg
        urls = [call[0][0] for call in client.get.call_args_list if call[0]]
        assert urls == [
            "transparent-encryption/signaturesets/sigset-1"
            "/signatures?skip=0&limit=1&file_name=app.exe"
        ]
