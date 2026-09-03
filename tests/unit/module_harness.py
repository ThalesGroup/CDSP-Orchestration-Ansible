# -*- coding: utf-8 -*-
"""Harness for exercising a module's ``main()`` for real.

Only the HTTP client is faked. ``ThalesCipherTrustModule`` is replaced so no
real ``AnsibleModule`` is constructed, but everything between that and the
wire -- parameter validation, the idempotency helpers, payload construction
in ``module_utils`` -- is the collection's own code.

The same fake client instance is installed both in the module (which uses it
for GET-before-write lookups) and in whichever ``module_utils`` the module
imports its write functions from, so a single object records the whole
conversation with CipherTrust Manager.
"""

import importlib
import types
from unittest.mock import MagicMock, patch

from test_helpers import (
    TEST_NODE,
    MockExitJsonException,
    MockFailJsonException,
)

MODULES_ROOT = "ansible_collections.thalesgroup.ciphertrust.plugins.modules"

# module_utils that never build a CipherTrustClient of their own.
# cm_api is deliberately NOT here: its backward-compatible wrappers
# (DELETEByNameOrId, GETIdByQueryParam, ...) construct a client from cm_api's
# own namespace, so that name has to be patched too.
_INFRA_UTILS = frozenset([
    "idempotent", "modules", "validation", "exceptions",
])


class Result(object):
    """Outcome of a module run."""

    def __init__(self, kind, kwargs, client, module):
        self.kind = kind
        self.kwargs = kwargs
        self.client = client
        self.module = module

    @property
    def changed(self):
        return self.kwargs.get("changed")

    @property
    def failed(self):
        return self.kind == "fail_json"

    @property
    def msg(self):
        return self.kwargs.get("msg", "")

    def wrote(self):
        """True if any write verb reached the client."""
        return bool(self.client.post.called
                    or self.client.patch.called
                    or self.client.put.called
                    or self.client.delete.called)

    def write_calls(self):
        calls = []
        for verb in ("post", "patch", "put", "delete"):
            for call in getattr(self.client, verb).call_args_list:
                calls.append((verb, call))
        return calls


def _client_targets(mod, module_path):
    """Every import site of CipherTrustClient this module's run can reach.

    A module reaches module_utils in one of two ways: by importing the
    functions it needs (``from ...connections import create``) or by importing
    the namespace (``from ...module_utils import cckm_aws``) and calling
    through it. Both put the helper's own ``CipherTrustClient`` on the path a
    run takes, so both have to be patched -- a namespace import left unpatched
    lets the module build a real client and try to reach the network.
    """
    targets = []
    if hasattr(mod, "CipherTrustClient"):
        targets.append(module_path + ".CipherTrustClient")
    seen = set()
    for attr_name in dir(mod):
        attr = getattr(mod, attr_name, None)
        if isinstance(attr, types.ModuleType):
            origin = getattr(attr, "__name__", "") or ""
        else:
            origin = getattr(attr, "__module__", None) or ""
        if "module_utils" not in origin:
            continue
        leaf = origin.rsplit(".", 1)[-1]
        if leaf in _INFRA_UTILS or origin in seen:
            continue
        seen.add(origin)
        util = importlib.import_module(origin)
        if hasattr(util, "CipherTrustClient"):
            targets.append(origin + ".CipherTrustClient")
    return targets


def make_client(get=None, post=None, patch_response=None, delete=None):
    """Build a fake CipherTrustClient.

    ``get`` may be a value, a callable taking the endpoint, or an exception
    instance to raise.
    """
    client = MagicMock(name="CipherTrustClient")

    def _responder(value, default):
        if isinstance(value, BaseException):
            return MagicMock(side_effect=value)
        if callable(value):
            return MagicMock(side_effect=value)
        return MagicMock(return_value=default if value is None else value)

    client.get = _responder(get, {})
    client.post = _responder(post, {"id": "new-id"})
    client.patch = _responder(patch_response, {"id": "patched-id"})
    client.put = _responder(None, {})
    client.delete = _responder(delete, {})
    return client


def run_main(module_name, params, client=None, check_mode=False, diff=False):
    """Run ``<module_name>.main()`` against a fake client.

    Returns a :class:`Result`. Raises AssertionError if main() returns
    without calling exit_json or fail_json.
    """
    module_path = MODULES_ROOT + "." + module_name
    mod = importlib.import_module(module_path)

    if client is None:
        client = make_client()

    module = MagicMock(name="ThalesCipherTrustModule")
    module.check_mode = check_mode
    module._diff = diff
    module._name = module_name
    # AnsibleModule fills in every default from the argument_spec before a
    # module body runs. Reproduce that here: a rule that only a defaulted
    # value trips is invisible otherwise, which is how two unusable
    # operations in vault_keys2_save went unnoticed.
    full_params = {"localNode": TEST_NODE.copy()}
    for name, spec in getattr(mod, "argument_spec", {}).items():
        if isinstance(spec, dict) and spec.get("default") is not None:
            full_params[name] = spec["default"]
    full_params.update(params)
    module.params = full_params
    # the idempotency helper reads defaults from here, as it does in production
    module.argument_spec = getattr(mod, "argument_spec", {})

    def fail_json(**kwargs):
        raise MockFailJsonException(**kwargs)

    def exit_json(**kwargs):
        raise MockExitJsonException(**kwargs)

    module.fail_json = fail_json
    module.exit_json = exit_json

    patchers = [patch(module_path + ".ThalesCipherTrustModule", return_value=module)]
    for target in _client_targets(mod, module_path):
        patchers.append(patch(target, return_value=client))

    started = [p.start() for p in patchers]
    try:
        mod.main()
    except MockExitJsonException as exc:
        return Result("exit_json", exc.kwargs, client, module)
    except MockFailJsonException as exc:
        return Result("fail_json", exc.kwargs, client, module)
    finally:
        for p in patchers:
            p.stop()
    raise AssertionError(
        "{0}.main() returned without calling exit_json/fail_json".format(module_name)
    )
