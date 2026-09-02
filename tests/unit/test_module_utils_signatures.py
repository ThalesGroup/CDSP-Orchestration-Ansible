# -*- coding: utf-8 -*-
"""``module_utils`` functions must declare the arguments they require.

These functions used to take ``**kwargs`` and nothing else, reading
``kwargs["node"]`` and friends at runtime. A caller that omitted or misspelled
one of those got a ``KeyError`` from deep inside the call, or -- worse -- a URL
built from ``None``. Two shipped bugs came from exactly that.

With real signatures, Python rejects the call. These tests keep it that way and
check every call site in the collection against the signature it targets, which
is the part no runtime test covers for the operations that need live
credentials.
"""

import ast
import glob
import importlib
import inspect
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL_ROOT = "ansible_collections.thalesgroup.ciphertrust.plugins.module_utils"
UTIL_FILES = sorted(glob.glob(str(REPO_ROOT / "plugins/module_utils/*.py")))
MODULE_FILES = sorted(glob.glob(str(REPO_ROOT / "plugins/modules/*.py")))


def _public_functions(path):
    name = pathlib.Path(path).stem
    module = importlib.import_module(UTIL_ROOT + "." + name)
    for attr, obj in vars(module).items():
        if (inspect.isfunction(obj) and obj.__module__ == module.__name__
                and not attr.startswith("_")):
            yield attr, obj


@pytest.mark.parametrize("path", UTIL_FILES,
                         ids=[pathlib.Path(p).stem for p in UTIL_FILES])
def test_no_function_takes_only_kwargs(path):
    offenders = []
    for name, fn in _public_functions(path):
        params = inspect.signature(fn).parameters
        named = [p for p in params.values() if p.kind is p.POSITIONAL_OR_KEYWORD]
        has_var_kw = any(p.kind is p.VAR_KEYWORD for p in params.values())
        if has_var_kw and not named:
            offenders.append(name)
    assert not offenders, (
        "these take **kwargs with no declared arguments: %s" % offenders
    )


@pytest.mark.parametrize("path", UTIL_FILES,
                         ids=[pathlib.Path(p).stem for p in UTIL_FILES])
def test_api_functions_declare_the_node_they_connect_with(path):
    """Every function that talks to CipherTrust Manager needs a node."""
    missing = []
    for name, fn in _public_functions(path):
        source = inspect.getsource(fn)
        if "CipherTrustClient(" not in source:
            continue
        if "node" not in inspect.signature(fn).parameters:
            missing.append(name)
    assert not missing, "these build a client without declaring node: %s" % missing


def _call_sites():
    """(module file, line, function, supplied keywords) for module_utils calls."""
    for path in MODULE_FILES:
        tree = ast.parse(pathlib.Path(path).read_text())
        origin = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "module_utils" in node.module:
                for alias in node.names:
                    origin[alias.asname or alias.name] = node.module
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in origin):
                yield (pathlib.Path(path).name, node.lineno, node.func.id,
                       origin[node.func.id],
                       {kw.arg for kw in node.keywords if kw.arg},
                       len(node.args))


@pytest.mark.parametrize("path", MODULE_FILES,
                         ids=[pathlib.Path(p).stem for p in MODULE_FILES])
def test_call_sites_supply_every_required_argument(path):
    wanted = pathlib.Path(path).name
    problems = []
    for name, line, fn_name, module_path, supplied, positional in _call_sites():
        if name != wanted:
            continue
        try:
            fn = getattr(importlib.import_module(module_path), fn_name)
            params = inspect.signature(fn).parameters
        except (ImportError, AttributeError, TypeError, ValueError):
            continue
        ordered = [n for n, p in params.items()
                   if p.kind is p.POSITIONAL_OR_KEYWORD]
        # arguments passed positionally satisfy the leading parameters
        supplied = set(supplied) | set(ordered[:positional])
        required = {n for n, p in params.items()
                    if p.default is p.empty and p.kind is p.POSITIONAL_OR_KEYWORD}
        missing = required - supplied
        if missing:
            problems.append("line %d: %s() missing %s" % (line, fn_name, sorted(missing)))
    assert not problems, "\n".join(problems)
