"""Shared test constants and lightweight exceptions.

This module is importable in both plain `pytest` and `ansible-test units`
execution modes, unlike direct `from conftest import ...` imports.
"""

# server_private_ip and server_port are deprecated no-ops. They are kept here
# deliberately: existing playbooks still set them, and they must continue to be
# accepted without error until they are removed in 2.0.0.
TEST_NODE = {
    "server_ip": "test.example.com",
    "server_private_ip": "10.10.10.10",
    "server_port": 5432,
    "user": "admin",
    "password": "test123",
    "verify": False,
    "auth_domain_path": "",
}


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
