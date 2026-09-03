# -*- coding: utf-8 -*-
"""Every module's argument spec must survive real AnsibleModule validation.

The unit harness builds a fake module object, so it never constructs an
``AnsibleModule`` -- which means a spec that ``AnsibleModule`` would reject
outright passes every other test in this suite and then fails on the first
real task. A ``required_if`` naming a parameter that does not exist, a
``choices`` list on a ``dict``, or a malformed suboption block are all in
that category.

These tests build the real thing, with the real spec, and drive it the way
Ansible does: parameters arrive as JSON on stdin. Nothing reaches the network,
because validation fails or succeeds before any module body runs.
"""

import glob
import importlib
import json
import pathlib
import re

import pytest

from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1].parent
MODULES_ROOT = "ansible_collections.thalesgroup.ciphertrust.plugins.modules"
MODULE_FILES = sorted(glob.glob(str(REPO_ROOT / "plugins/modules/*.py")))
IDS = [pathlib.Path(p).stem for p in MODULE_FILES]

NODE = {
    "server_ip": "cm.example.com",
    "user": "admin",
    "password": "Passw0rd!",
    "verify": False,
}


def _module(name):
    return importlib.import_module(MODULES_ROOT + "." + name)


def _set_args(args):
    """Feed parameters in the way AnsibleModule reads them."""
    payload = {"ANSIBLE_MODULE_ARGS": dict(args, localNode=NODE)}
    basic._ANSIBLE_ARGS = to_bytes(json.dumps(payload))


class _Exit(Exception):
    pass


class _Fail(Exception):
    def __init__(self, msg):
        self.msg = msg


@pytest.fixture(autouse=True)
def _no_exit(monkeypatch):
    """Stop exit_json/fail_json from ending the test process.

    ``_log_invocation`` is silenced too. It is not part of what is under test,
    and on Windows the conftest stubs ``syslog`` with an empty module, so
    AnsibleModule's logging raises ``AttributeError`` for a spec that is
    perfectly valid -- a platform artefact that would otherwise read as a
    failure.
    """
    def exit_json(self, **kwargs):
        raise _Exit()

    def fail_json(self, **kwargs):
        raise _Fail(kwargs.get("msg", ""))

    monkeypatch.setattr(basic.AnsibleModule, "exit_json", exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", fail_json)
    monkeypatch.setattr(basic.AnsibleModule, "_log_invocation",
                        lambda self: None)


def _build(name):
    """Construct the module's real AnsibleModule, returning any failure msg."""
    mod = _module(name)
    try:
        mod.setup_module_object()
    except _Fail as exc:
        return exc.msg
    except _Exit:
        return None
    return None


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_spec_is_accepted_by_ansiblemodule(path):
    """A structurally invalid spec fails here rather than on a live run.

    The parameters supplied are deliberately minimal, so the expected outcome
    is usually a missing-parameter error. What must not happen is a complaint
    about the spec itself.
    """
    name = pathlib.Path(path).stem
    _set_args({})
    msg = _build(name)

    if msg is None:
        return

    # Errors about the *task* are fine -- nothing was supplied. Errors about
    # the *spec* are not.
    spec_complaints = (
        "internal error",
        "is not a valid",
        "unknown parameter",
        "must be a list",
        "must be a dict",
        "invalid argument spec",
        "does not exist in argument_spec",
    )
    for complaint in spec_complaints:
        assert complaint not in msg.lower(), (
            "%s: AnsibleModule rejected the argument spec: %s" % (name, msg))


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_required_if_names_real_parameters(path):
    """A required_if rule on a parameter that does not exist never fires.

    AnsibleModule does not always complain -- the rule is simply dead, so the
    operation it was meant to guard accepts a task it cannot carry out and
    fails deeper in, or builds a URL from None.
    """
    name = pathlib.Path(path).stem
    mod = _module(name)
    spec = getattr(mod, "argument_spec", {})

    # Read the constraint the module actually passes, by intercepting it.
    captured = {}

    class _Spy(ThalesCipherTrustModule):
        def __init__(self, **kwargs):
            captured.update(kwargs)
            raise _Exit()

    original = mod.ThalesCipherTrustModule
    mod.ThalesCipherTrustModule = _Spy
    try:
        try:
            mod.setup_module_object()
        except _Exit:
            pass
    finally:
        mod.ThalesCipherTrustModule = original

    known = set(spec) | {"localNode", "local_node"}
    # aliases count: a rule may name either spelling
    for entry in spec.values():
        if isinstance(entry, dict):
            known.update(entry.get("aliases") or [])

    unknown = []
    for rule in captured.get("required_if") or []:
        rule = list(rule)
        if rule and rule[0] not in known:
            unknown.append("required_if keys on unknown parameter %r" % rule[0])
        for param in (rule[2] if len(rule) > 2 else []) or []:
            if param not in known:
                unknown.append(
                    "required_if(%s=%s) requires unknown parameter %r"
                    % (rule[0], rule[1], param))

    for group in captured.get("mutually_exclusive") or []:
        for param in group:
            if param not in known:
                unknown.append(
                    "mutually_exclusive names unknown parameter %r" % param)

    assert not unknown, "%s:\n  %s" % (name, "\n  ".join(unknown))


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_required_if_conditions_are_valid_choices(path):
    """A rule keyed on a value the parameter cannot take is dead code.

    ``["op_type", "delete_key", [...]]`` where the choice is spelled
    ``delete`` silently guards nothing.
    """
    name = pathlib.Path(path).stem
    mod = _module(name)
    spec = getattr(mod, "argument_spec", {})

    captured = {}

    class _Spy(ThalesCipherTrustModule):
        def __init__(self, **kwargs):
            captured.update(kwargs)
            raise _Exit()

    original = mod.ThalesCipherTrustModule
    mod.ThalesCipherTrustModule = _Spy
    try:
        try:
            mod.setup_module_object()
        except _Exit:
            pass
    finally:
        mod.ThalesCipherTrustModule = original

    unreachable = []
    for rule in captured.get("required_if") or []:
        rule = list(rule)
        if len(rule) < 2:
            continue
        entry = spec.get(rule[0])
        choices = entry.get("choices") if isinstance(entry, dict) else None
        if choices and rule[1] not in choices:
            unreachable.append(
                "required_if(%s=%r) can never fire; %s accepts %s"
                % (rule[0], rule[1], rule[0], sorted(choices)))

    assert not unreachable, "%s:\n  %s" % (name, "\n  ".join(unreachable))


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_op_type_choices_are_unique(path):
    """A duplicated choice usually means two branches were meant to differ."""
    spec = getattr(_module(pathlib.Path(path).stem), "argument_spec", {})
    entry = spec.get("op_type") or {}
    choices = entry.get("choices") or []
    assert len(choices) == len(set(choices)), (
        "duplicate op_type choices: %s" % choices)


# ``ansible-test sanity`` fails a module (``no-log-needed``) whose parameter
# *name* looks like a secret unless ``no_log`` is set either way. The heuristic
# is a substring match, so ``key`` catches ``keystate`` and
# ``key_material_origin``. Set ``no_log=False`` on those: it states that the
# value is not sensitive, and without it a future reader cannot tell whether
# the omission was considered.
#
# This mirrors validate-modules' own rule, including its exemptions -- it
# skips ``bool`` (a flag about a secret, not a secret), ``path`` (a filename),
# and anything with ``choices`` (an enumerated value cannot be a secret). A
# check stricter than the tool it stands in for would demand changes CI does
# not want.
_SECRETISH = re.compile(r"(?:pass(?!ive)|secret|token|key)", re.I)

# Suffixes and substrings validate-modules already treats as non-secret.
_NOT_SECRET_SUFFIXES = (
    "_count", "_type", "_alg", "_algorithm", "_timeout", "_name", "_comment",
    "_bits", "_id", "_identifier", "_period", "_file", "_filename",
)
_NOT_SECRET_PARTS = (
    "publickey", "public_key", "keyusage", "key_usage", "keyserver",
    "key_server", "keysize", "key_size", "keyservice", "key_service",
    "pub_key", "pubkey", "keyboard", "secretary",
)


def _looks_like_a_secret(name):
    if not _SECRETISH.search(name):
        return False
    if name.endswith(_NOT_SECRET_SUFFIXES):
        return False
    return not any(part in name for part in _NOT_SECRET_PARTS)


def _walk_spec(spec, prefix=""):
    for name, entry in (spec or {}).items():
        if not isinstance(entry, dict):
            continue
        yield prefix + name, name, entry
        if isinstance(entry.get("options"), dict):
            for item in _walk_spec(entry["options"], prefix + name + "."):
                yield item


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_secret_looking_parameters_declare_no_log(path):
    """Reproduces the validate-modules check, in the suite that runs everywhere.

    Getting this wrong fails CI in one direction and leaks in the other: a
    genuine secret without ``no_log=True`` is printed in task output, and a
    harmless option the heuristic catches is redacted to ``VALUE_SPECIFIED_IN
    _NO_LOG_PARAMETER`` in every result that mentions it.
    """
    spec = getattr(_module(pathlib.Path(path).stem), "argument_spec", {})
    undeclared = [
        full for full, name, entry in _walk_spec(spec)
        if _looks_like_a_secret(name)
        and entry.get("no_log") is None
        and entry.get("type") not in ("path", "bool")
        and entry.get("choices") is None
    ]
    assert not undeclared, (
        "ansible-test sanity requires an explicit no_log on these; set "
        "no_log=True for a real secret, no_log=False for a name that only "
        "looks like one: %s" % undeclared)
