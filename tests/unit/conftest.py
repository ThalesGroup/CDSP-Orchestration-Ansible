#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Shared pytest fixtures for CipherTrust Ansible unit tests.

Provides pre-configured mocks for ThalesCipherTrustModule, CipherTrustClient,
and API responses so that every test can run without a live CipherTrust Manager.

Also patches Windows-incompatible modules (grp, pwd) that Ansible core imports.
"""

import json
import sys
import pytest
from unittest.mock import MagicMock, patch

import types

# ---------------------------------------------------------------------------
# Windows compatibility: Ansible's module_utils.basic imports 'grp', 'pwd', 
# 'fcntl', 'syslog', 'termios' which are Unix-only. We inject stubs before 
# any Ansible imports happen.
# ---------------------------------------------------------------------------
for _mod_name in ("grp", "pwd", "fcntl", "syslog", "termios"):
    if _mod_name not in sys.modules:
        sys.modules[_mod_name] = types.ModuleType(_mod_name)


# ---------------------------------------------------------------------------
# Dynamic Python Namespace Mapper for Ansible Collections
# This allows pytest to resolve `from ansible_collections.thalesgroup...` natively
# without needing complex nested symlinks in the root!
# ---------------------------------------------------------------------------
import os
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

sys.path.insert(0, repo_root)

import plugins
import plugins.module_utils
import plugins.modules

ansible_collections = types.ModuleType("ansible_collections")
thalesgroup = types.ModuleType("thalesgroup")
ciphertrust = types.ModuleType("ciphertrust")

ansible_collections.thalesgroup = thalesgroup
thalesgroup.ciphertrust = ciphertrust
ciphertrust.plugins = plugins

sys.modules["ansible_collections"] = ansible_collections
sys.modules["ansible_collections.thalesgroup"] = thalesgroup
sys.modules["ansible_collections.thalesgroup.ciphertrust"] = ciphertrust
sys.modules["ansible_collections.thalesgroup.ciphertrust.plugins"] = plugins
sys.modules["ansible_collections.thalesgroup.ciphertrust.plugins.module_utils"] = plugins.module_utils
sys.modules["ansible_collections.thalesgroup.ciphertrust.plugins.modules"] = plugins.modules





# ---------------------------------------------------------------------------
# Standard test node configuration — mirrors the ``localNode`` dict that
# every module receives from Ansible.
# ---------------------------------------------------------------------------

TEST_NODE = {
    "server_ip": "test.example.com",
    "server_private_ip": "10.10.10.10",
    "server_port": 5432,
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}


# ---------------------------------------------------------------------------
# Exception helpers — lightweight exceptions that ``mock_module.fail_json``
# and ``mock_module.exit_json`` raise so test code can catch and inspect them.
# ---------------------------------------------------------------------------

class MockBaseException(Exception):
    pass


class MockFailJsonException(MockBaseException):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        super().__init__(str(kwargs))


class MockExitJsonException(MockBaseException):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        super().__init__(str(kwargs))


# ---------------------------------------------------------------------------
# Module-level fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_module():
    """Create a mock ThalesCipherTrustModule that captures exit/fail calls.

    The mock behaves like a real module: ``exit_json`` and ``fail_json``
    raise lightweight exceptions so that test code can assert on the
    keyword arguments without the process actually exiting.
    """
    module = MagicMock()
    module.check_mode = False
    module._diff = False
    module._name = "test_module"
    module.params = {
        "localNode": TEST_NODE.copy(),
    }

    def fail_json(**kwargs):
        raise MockFailJsonException(**kwargs)

    def exit_json(**kwargs):
        raise MockExitJsonException(**kwargs)

    module.fail_json = fail_json
    module.exit_json = exit_json
    return module


@pytest.fixture
def mock_client():
    """Return a MagicMock that quacks like CipherTrustClient.

    Every HTTP verb (get, post, put, patch, delete) is a MagicMock
    that returns ``{}`` by default.  Tests can override per-method::

        mock_client.get.return_value = {"id": "abc123", "name": "foo"}
    """
    client = MagicMock()
    client.get.return_value = {}
    client.post.return_value = {}
    client.put.return_value = {}
    client.patch.return_value = {}
    client.delete.return_value = {}
    return client


@pytest.fixture
def mock_api_response():
    """Factory for creating mock HTTP response objects.

    Usage::

        resp = mock_api_response(200, {"id": "abc123"})
    """
    def _make_response(status_code=200, data=None):
        response = MagicMock()
        response.status_code = status_code
        response.getcode.return_value = status_code
        body = data or {}
        response.json.return_value = body
        response.text = str(body)
        response.read.return_value = json.dumps(body).encode("utf-8")
        return response
    return _make_response


@pytest.fixture
def patch_client():
    """Context-manager fixture that patches CipherTrustClient at a given module path.

    Usage::

        def test_something(patch_client):
            client = patch_client("module_utils.services")
            client.post.return_value = {"status": "ok"}
            ...

    Returns the *instance* mock (the object returned by ``CipherTrustClient(node)``).
    """
    _patchers = []

    def _patch(module_path):
        full_path = (
            "ansible_collections.thalesgroup.ciphertrust.plugins."
            + module_path
            + ".CipherTrustClient"
        )
        patcher = patch(full_path)
        mock_cls = patcher.start()
        mock_instance = MagicMock()
        mock_instance.get.return_value = {}
        mock_instance.post.return_value = {}
        mock_instance.put.return_value = {}
        mock_instance.patch.return_value = {}
        mock_instance.delete.return_value = {}
        mock_cls.return_value = mock_instance
        _patchers.append(patcher)
        return mock_instance

    yield _patch

    for p in _patchers:
        p.stop()
