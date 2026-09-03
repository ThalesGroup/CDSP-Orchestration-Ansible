# -*- coding: utf-8 -*-
"""A failed connection test must not be reported as a successful task.

Covers both shapes: ``connection_test``, which tests a stored connection, and
``connection_<cloud>_test``, which tests credentials before they are stored.

CipherTrust Manager answers a failed connection test with HTTP 200 and a body
saying the connection did not work, rather than an error status. A module that
trusted the status code would pass for a connection whose credentials have
expired -- which is the one thing this module exists to detect. The same shape
of bug shipped once before, in ``getLockdata``.
"""

import json

import pytest

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)
from module_harness import make_client, run_main

CLOUDS = ["aws", "azure", "gcp", "oci"]

PARAMS = {"cloud": "aws", "connection_id": "conn-1"}


class TestFailedTestFailsTheTask:

    @pytest.mark.parametrize("cloud", CLOUDS)
    def test_connection_not_ok_fails(self, cloud):
        client = make_client(post={
            "connection_ok": False,
            "connection_error": "SignatureDoesNotMatch: Signature expired",
        })
        result = run_main("connection_test",
                          {"cloud": cloud, "connection_id": "conn-1"},
                          client=client)

        assert result.failed, (
            "a connection whose test failed must fail the task, not report success"
        )
        assert "SignatureDoesNotMatch" in result.msg, result.msg
        assert "conn-1" in result.msg

    def test_failure_names_the_cloud_and_connection(self):
        client = make_client(post={"connection_ok": False,
                                   "connection_error": "invalid_client"})
        result = run_main("connection_test",
                          {"cloud": "azure", "connection_id": "azure-prod"},
                          client=client)
        assert result.failed
        assert "azure" in result.msg
        assert "azure-prod" in result.msg

    def test_failure_without_a_reason_still_fails(self):
        """CM may omit connection_error; absence of a reason is not success."""
        client = make_client(post={"connection_ok": False})
        result = run_main("connection_test", PARAMS, client=client)
        assert result.failed
        assert "no reason given" in result.msg

    def test_failure_still_returns_the_response(self):
        client = make_client(post={"connection_ok": False,
                                   "connection_error": "expired"})
        result = run_main("connection_test", PARAMS, client=client)
        assert result.kwargs["response"]["connection_error"] == "expired"
        assert result.kwargs["connection_ok"] is False


class TestSuccessfulTest:

    @pytest.mark.parametrize("cloud", CLOUDS)
    def test_connection_ok_succeeds_without_reporting_change(self, cloud):
        client = make_client(post={"connection_ok": True})
        result = run_main("connection_test",
                          {"cloud": cloud, "connection_id": "conn-1"},
                          client=client)

        assert not result.failed, result.msg
        assert result.changed is False, (
            "testing a connection reads the provider's state; it changes nothing"
        )
        assert result.kwargs["connection_ok"] is True

    def test_runs_in_check_mode(self):
        """The test is a read, so --check should perform it rather than skip."""
        client = make_client(post={"connection_ok": True})
        result = run_main("connection_test", PARAMS,
                          client=client, check_mode=True)

        assert not result.failed, result.msg
        assert client.post.called, "a read-only operation should still run under --check"
        assert result.changed is False

    def test_missing_connection_ok_is_not_treated_as_failure(self):
        """Only an explicit false is a failed test.

        A response that omits the field entirely -- an older CM, or a shape
        change -- must not be reported as a broken connection.
        """
        client = make_client(post={})
        result = run_main("connection_test", PARAMS, client=client)
        assert not result.failed, result.msg


class TestErrorsFromCipherTrustManager:

    def test_unknown_connection_surfaces_the_api_error(self):
        client = make_client(post=CMApiException(
            message="Resource not found", api_error_code=404))
        result = run_main("connection_test", PARAMS, client=client)

        assert result.failed
        assert "404" in result.msg

    def test_targets_the_right_url(self):
        client = make_client(post={"connection_ok": True})
        run_main("connection_test", {"cloud": "gcp", "connection_id": "c 1"},
                 client=client)
        url = client.post.call_args[0][0]
        assert url == "connectionmgmt/services/gcp/connections/c%201/test"


# ---------------------------------------------------------------------------
# Pre-create credential tests
# ---------------------------------------------------------------------------

CREDENTIALS = {
    "aws": {"access_key_id": "AKIA", "secret_access_key": "shhh"},
    "azure": {"client_id": "app-1", "tenant_id": "tenant-1",
              "client_secret": "shhh"},
    "gcp": {"key_file": '{"type": "service_account"}'},
    "oci": {"credentials": {"key_file": "-----BEGIN-----"},
            "fingerprint": "aa:bb", "region": "us-ashburn-1",
            "tenancy_ocid": "ocid1.tenancy.oc1..a",
            "user_ocid": "ocid1.user.oc1..b"},
}


@pytest.mark.parametrize("cloud", CLOUDS)
class TestPreCreateCredentialTest:

    def test_posts_to_the_connection_test_endpoint(self, cloud):
        """Must not create anything: the URL is the service root, and the
        connections collection must never be touched."""
        client = make_client(post={"connection_ok": True})
        result = run_main("connection_%s_test" % cloud, CREDENTIALS[cloud],
                          client=client)

        assert not result.failed, result.msg
        url = client.post.call_args[0][0]
        assert url == "connectionmgmt/services/%s/connection-test" % cloud
        assert "/connections" not in url

    def test_reports_no_change(self, cloud):
        client = make_client(post={"connection_ok": True})
        result = run_main("connection_%s_test" % cloud, CREDENTIALS[cloud],
                          client=client)
        assert result.changed is False
        assert result.kwargs["connection_ok"] is True

    def test_rejected_credentials_fail_the_task(self, cloud):
        client = make_client(post={"connection_ok": False,
                                   "connection_error": "AccessDenied"})
        result = run_main("connection_%s_test" % cloud, CREDENTIALS[cloud],
                          client=client)

        assert result.failed, (
            "credentials the provider refused must fail the task"
        )
        assert "AccessDenied" in result.msg
        assert result.kwargs["connection_ok"] is False

    def test_sends_the_credentials_supplied(self, cloud):
        client = make_client(post={"connection_ok": True})
        run_main("connection_%s_test" % cloud, CREDENTIALS[cloud], client=client)
        body = json.loads(client.post.call_args[1]["data"])
        for key, value in CREDENTIALS[cloud].items():
            assert body[key] == value

    def test_missing_required_credentials_are_rejected(self, cloud):
        """required=True in the spec, so a real AnsibleModule would reject
        this; the harness bypasses that, so assert the spec instead."""
        import importlib
        mod = importlib.import_module(
            "ansible_collections.thalesgroup.ciphertrust.plugins.modules"
            ".connection_%s_test" % cloud)
        required = {k for k, v in mod.argument_spec.items() if v.get("required")}
        assert required, "the endpoint has required fields; the spec must say so"
        assert required <= set(CREDENTIALS[cloud])

    def test_runs_in_check_mode(self, cloud):
        """Storing nothing means --check can perform the test for real."""
        client = make_client(post={"connection_ok": True})
        result = run_main("connection_%s_test" % cloud, CREDENTIALS[cloud],
                          client=client, check_mode=True)
        assert not result.failed, result.msg
        assert client.post.called


def test_pre_create_test_never_writes_a_connection():
    """The whole point is that nothing is stored."""
    client = make_client(post={"connection_ok": True})
    run_main("connection_aws_test", CREDENTIALS["aws"], client=client)
    assert not client.patch.called
    assert not client.delete.called
    urls = [c[0][0] for c in client.post.call_args_list if c[0]]
    assert all(u.endswith("/connection-test") for u in urls), urls
