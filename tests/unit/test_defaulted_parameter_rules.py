# -*- coding: utf-8 -*-
"""A rule nobody can satisfy is worse than no rule.

``AnsibleModule`` fills in every ``default`` from the argument spec before a
module body runs, so a parameter carrying a default is *always* present. A rule
that forbids such a parameter for an operation therefore rejects every task
using that operation.

Two of ``vault_keys2_save``'s three operations were unusable for exactly this
reason -- ``algorithm`` carries ``default="aes"`` and both ``patch`` and
``create_version`` forbade it. No unit test could see it, because the test
harness supplied only the parameters a test passed. The harness now applies
spec defaults, and this check states the rule directly.
"""

import ast
import glob
import importlib
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULES_ROOT = "ansible_collections.thalesgroup.ciphertrust.plugins.modules"
MODULE_FILES = sorted(glob.glob(str(REPO_ROOT / "plugins/modules/*.py")))


def _validation_rules(path):
    source = pathlib.Path(path).read_text()
    match = re.search(r"validation_rules = (\{.*?\n    \})", source, re.S)
    if not match:
        return {}
    try:
        return ast.literal_eval(match.group(1))
    except (ValueError, SyntaxError):
        return {}


def _spec(path):
    name = pathlib.Path(path).stem
    return getattr(importlib.import_module(MODULES_ROOT + "." + name),
                   "argument_spec", {})


@pytest.mark.parametrize("path", MODULE_FILES,
                         ids=[pathlib.Path(p).stem for p in MODULE_FILES])
def test_no_operation_forbids_a_parameter_that_carries_a_default(path):
    spec = _spec(path)
    unsatisfiable = []
    for op_type, rules in _validation_rules(path).items():
        for param in (rules.get("conditional_not_allowed") or {}):
            entry = spec.get(param)
            if isinstance(entry, dict) and entry.get("default") is not None:
                unsatisfiable.append(
                    "op_type=%s forbids %s, which defaults to %r"
                    % (op_type, param, entry["default"])
                )
    assert not unsatisfiable, (
        "AnsibleModule always supplies these, so the operation can never run:\n  "
        + "\n  ".join(unsatisfiable)
    )


@pytest.mark.parametrize("path", MODULE_FILES,
                         ids=[pathlib.Path(p).stem for p in MODULE_FILES])
def test_required_parameters_are_not_also_forbidden(path):
    """A parameter cannot be both required and rejected for one operation."""
    conflicts = []
    for op_type, rules in _validation_rules(path).items():
        required = set(rules.get("required") or [])
        forbidden = {p for p, ops in (rules.get("conditional_not_allowed") or {}).items()
                     if op_type in ops}
        for param in required & forbidden:
            conflicts.append("op_type=%s both requires and forbids %s" % (op_type, param))
    assert not conflicts, "\n".join(conflicts)
