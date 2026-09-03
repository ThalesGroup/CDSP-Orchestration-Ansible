# -*- coding: utf-8 -*-
"""Integration targets must call the modules that actually exist.

Integration tests only run where a CipherTrust Manager is configured, so a
task that names a parameter no module has can sit unnoticed for a long time --
and did: every target was calling modules with an invented connection API
(``connection_string``, ``username``, ``api_key``), and the failures were
masked by ``ignore_errors``.

These checks are cheap and run in the normal unit suite, so the integration
suite cannot drift away from the collection again without something failing.
"""

import glob
import importlib
import re
import pathlib

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGETS = sorted(glob.glob(str(REPO_ROOT / "tests/integration/targets/*/tasks/main.yml")))
MODULES_ROOT = "ansible_collections.thalesgroup.ciphertrust.plugins.modules"


def _module_parameters(module_name):
    module = importlib.import_module(MODULES_ROOT + "." + module_name)
    spec = getattr(module, "argument_spec", {})
    # localNode is contributed by the shared argument spec, and the collection
    # accepts both spellings.
    return set(spec) | {"localNode", "local_node"}


def _collection_tasks(path):
    """Yield (module_name, params) for every collection task in a target."""
    stack = [yaml.safe_load(pathlib.Path(path).read_text()) or []]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                if key in ("block", "always", "rescue"):
                    stack.append(value)
                elif key.startswith("thalesgroup.ciphertrust."):
                    yield key.rsplit(".", 1)[-1], value


def _target_id(path):
    return pathlib.Path(path).parts[-3]


@pytest.mark.parametrize("path", TARGETS, ids=[_target_id(p) for p in TARGETS])
def test_target_is_valid_yaml(path):
    assert yaml.safe_load(pathlib.Path(path).read_text()) is not None


@pytest.mark.parametrize("path", TARGETS, ids=[_target_id(p) for p in TARGETS])
def test_target_calls_modules_that_exist(path):
    missing = []
    for module_name, _params in _collection_tasks(path):
        try:
            importlib.import_module(MODULES_ROOT + "." + module_name)
        except ImportError:
            missing.append(module_name)
    assert not missing, "target calls modules that do not exist: %s" % sorted(set(missing))


@pytest.mark.parametrize("path", TARGETS, ids=[_target_id(p) for p in TARGETS])
def test_target_uses_real_parameters(path):
    invalid = []
    for module_name, params in _collection_tasks(path):
        if not isinstance(params, dict):
            continue
        try:
            allowed = _module_parameters(module_name)
        except ImportError:
            continue
        invalid += [(module_name, p) for p in params if p not in allowed]
    assert not invalid, (
        "target passes parameters no module accepts: %s" % sorted(set(invalid))
    )


@pytest.mark.parametrize("path", TARGETS, ids=[_target_id(p) for p in TARGETS])
def test_target_uses_valid_op_types(path):
    invalid = []
    for module_name, params in _collection_tasks(path):
        if not isinstance(params, dict) or "op_type" not in params:
            continue
        op_type = params["op_type"]
        if not isinstance(op_type, str) or "{{" in op_type:
            continue
        module = importlib.import_module(MODULES_ROOT + "." + module_name)
        choices = (getattr(module, "argument_spec", {}).get("op_type") or {}).get("choices")
        if choices and op_type not in choices:
            invalid.append((module_name, op_type, choices))
    assert not invalid, "target uses op_type values the module rejects: %s" % invalid


def test_every_target_is_listed_in_the_suite():
    suite = yaml.safe_load((REPO_ROOT / "tests" / "integration.yml").read_text())
    listed = set(suite.get("targets") or [])
    on_disk = {pathlib.Path(p).parts[-3] for p in TARGETS}
    assert not (on_disk - listed), (
        "targets on disk missing from tests/integration.yml: %s"
        % sorted(on_disk - listed)
    )


def test_every_target_has_an_aliases_file():
    for path in TARGETS:
        target_dir = pathlib.Path(path).parents[1]
        assert (target_dir / "aliases").exists(), (
            "%s has no aliases file, so ansible-test will not run it" % target_dir.name
        )


def _defined_names(target_dir, tasks):
    """Every name a target can resolve: config, vars, defaults, set_fact, register."""
    import yaml as _yaml

    names = set()
    # The committed template is the contract: it names every variable a target
    # may rely on. A developer's own integration_config.yml is git-ignored and
    # may add more, so read it too when it is there -- but the template alone
    # must be enough, or the suite does not run on a clean checkout.
    integration = REPO_ROOT / "tests" / "integration"
    names |= set(_yaml.safe_load(
        (integration / "integration_config.yml.template").read_text()) or {})
    local = integration / "integration_config.yml"
    if local.exists():
        names |= set(_yaml.safe_load(local.read_text()) or {})
    for rel in ("vars/main.yml", "defaults/main.yml"):
        path = target_dir / rel
        if path.exists():
            names |= set(_yaml.safe_load(path.read_text()) or {})

    stack = [tasks]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                if key in ("block", "always", "rescue"):
                    stack.append(value)
                elif key == "register" and isinstance(value, str):
                    names.add(value)
                elif key == "vars" and isinstance(value, dict):
                    names |= set(value)
                elif key in ("set_fact", "ansible.builtin.set_fact") and isinstance(value, dict):
                    names |= {k for k in value if k != "cacheable"}
    return names


# Loop variables and facts that Ansible provides rather than the target.
_AMBIENT = {
    "item", "omit", "lookup", "ansible_check_mode", "ansible_date_time",
    "inventory_hostname", "playbook_dir", "ansible_facts",
}


@pytest.mark.parametrize("path", TARGETS, ids=[_target_id(p) for p in TARGETS])
def test_target_defines_every_variable_it_uses(path):
    """A target that references an undefined variable fails only on a live run.

    Eight targets referenced this_node_connection_string without defining it,
    which no structural check caught until this one existed.
    """
    target_dir = pathlib.Path(path).parents[1]
    tasks = yaml.safe_load(pathlib.Path(path).read_text()) or []
    defined = _defined_names(target_dir, tasks) | _AMBIENT

    # commented-out tasks are not executed, so they are not checked
    body = "\n".join(
        line for line in pathlib.Path(path).read_text().split("\n")
        if not line.lstrip().startswith("#")
    )
    used = set(re.findall(r"\{\{\s*([a-zA-Z_]\w*)", body))
    undefined = sorted(name for name in used - defined if not name.startswith("_"))

    assert not undefined, (
        "target uses variables nothing defines: %s" % undefined
    )
