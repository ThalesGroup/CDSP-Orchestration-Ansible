# -*- coding: utf-8 -*-
"""A module's DOCUMENTATION must describe the module it is attached to.

``ansible-doc`` and the published reference are generated from these strings,
so a drifted block is not a cosmetic problem -- it tells users an option
exists that does not, or hides one that does. ``ansible-test sanity`` checks
this, but only where ansible-test runs; these checks are cheap and run in the
ordinary unit suite, which is where a mismatch is introduced.

Two of these caught real breakage as this suite was written: an unquoted
``C({"environment": "production"})`` and a colon inside a plain scalar both
made a DOCUMENTATION block unparseable, which no other test noticed.
"""

import ast
import glob
import importlib
import pathlib

import pytest
import yaml

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    _normalize_argument_spec,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1].parent
MODULES_ROOT = "ansible_collections.thalesgroup.ciphertrust.plugins.modules"
MODULE_FILES = sorted(glob.glob(str(REPO_ROOT / "plugins/modules/*.py")))
IDS = [pathlib.Path(p).stem for p in MODULE_FILES]

# Contributed by the shared argument spec rather than by the module, and
# documented in the ciphertrust doc fragment.
_SHARED = {"localNode", "local_node"}


def _string_assignment(path, name):
    """The literal assigned to *name* at module level, without importing."""
    tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(getattr(t, "id", None) == name for t in node.targets):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return node.value.value
    return None


def _documentation(path):
    return yaml.safe_load(_string_assignment(path, "DOCUMENTATION"))


def _spec(path):
    """The spec as a *user* meets it, not as the module file spells it.

    ``ThalesCipherTrustModule`` normalises camelCase spec keys to snake_case
    and keeps the original as a deprecated alias, so the older modules declare
    ``trialId`` and correctly document ``trial_id``. Comparing against the raw
    module attribute would report every one of those as drift, which is the
    opposite of the truth.
    """
    name = pathlib.Path(path).stem
    raw = getattr(importlib.import_module(MODULES_ROOT + "." + name),
                  "argument_spec", {})
    normalized, _tree, _map = _normalize_argument_spec(raw)
    return normalized


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_documentation_is_parseable_yaml(path):
    """An unparseable block makes ansible-doc fail for the whole module."""
    raw = _string_assignment(path, "DOCUMENTATION")
    assert raw, "%s has no DOCUMENTATION" % pathlib.Path(path).stem
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        pytest.fail("DOCUMENTATION is not valid YAML: %s" % exc)
    assert isinstance(parsed, dict)


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_examples_and_return_are_parseable_yaml(path):
    for name in ("EXAMPLES", "RETURN"):
        raw = _string_assignment(path, name)
        assert raw, "%s has no %s" % (pathlib.Path(path).stem, name)
        try:
            yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            pytest.fail("%s is not valid YAML: %s" % (name, exc))


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_every_documented_option_exists(path):
    """A documented option the module does not accept is a promise it breaks."""
    documented = set(_documentation(path).get("options") or {})
    accepted = set(_spec(path)) | _SHARED
    phantom = sorted(documented - accepted)
    assert not phantom, "documents options the module does not accept: %s" % phantom


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_every_accepted_option_is_documented(path):
    documented = set(_documentation(path).get("options") or {}) | _SHARED
    undocumented = sorted(set(_spec(path)) - documented)
    assert not undocumented, "accepts undocumented options: %s" % undocumented


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_documented_choices_match_the_spec(path):
    """Choices in the docs are what a user reads before writing a task; the
    spec is what actually rejects the value."""
    options = _documentation(path).get("options") or {}
    spec = _spec(path)
    mismatched = []
    for name, entry in spec.items():
        if not isinstance(entry, dict):
            continue
        spec_choices = entry.get("choices")
        doc_choices = (options.get(name) or {}).get("choices")
        if spec_choices is None or doc_choices is None:
            continue
        if sorted(map(str, spec_choices)) != sorted(map(str, doc_choices)):
            mismatched.append(
                "%s: documented %s, spec accepts %s"
                % (name, sorted(doc_choices), sorted(spec_choices))
            )
    assert not mismatched, "\n".join(mismatched)


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_documented_types_match_the_spec(path):
    options = _documentation(path).get("options") or {}
    mismatched = []
    for name, entry in _spec(path).items():
        if not isinstance(entry, dict):
            continue
        documented = (options.get(name) or {}).get("type")
        actual = entry.get("type", "str")
        if documented is not None and documented != actual:
            mismatched.append("%s: documented %s, spec says %s"
                              % (name, documented, actual))
    assert not mismatched, "\n".join(mismatched)


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_documented_elements_match_the_spec(path):
    """``elements`` says what a list holds, and only a list has one.

    ``ansible-test sanity`` reports a mismatch as ``doc-elements-mismatch``.
    Getting it wrong means the published reference tells users to pass the
    wrong shape.
    """
    options = _documentation(path).get("options") or {}
    mismatched = []
    for name, entry in _spec(path).items():
        if not isinstance(entry, dict):
            continue
        documented = (options.get(name) or {}).get("elements")
        if entry.get("type") == "list":
            if documented != entry.get("elements"):
                mismatched.append("%s: documented elements=%r, spec says %r"
                                  % (name, documented, entry.get("elements")))
        elif documented is not None:
            mismatched.append(
                "%s documents elements=%r but is type %s, not a list"
                % (name, documented, entry.get("type", "str")))
    assert not mismatched, "\n".join(mismatched)


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_required_options_agree(path):
    """An option the spec requires but the docs call optional sends users
    into a validation error the documentation said would not happen."""
    options = _documentation(path).get("options") or {}
    disagreements = []
    for name, entry in _spec(path).items():
        if not isinstance(entry, dict):
            continue
        spec_required = bool(entry.get("required"))
        doc_required = bool((options.get(name) or {}).get("required"))
        if spec_required != doc_required:
            disagreements.append(
                "%s: spec required=%s, docs required=%s"
                % (name, spec_required, doc_required))
    assert not disagreements, "\n".join(disagreements)


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_documented_defaults_match_the_spec(path):
    options = _documentation(path).get("options") or {}
    mismatched = []
    for name, entry in _spec(path).items():
        if not isinstance(entry, dict):
            continue
        documented = (options.get(name) or {}).get("default")
        actual = entry.get("default")
        if documented != actual and not (documented is None and actual is None):
            mismatched.append("%s: documented %r, spec default %r"
                              % (name, documented, actual))
    assert not mismatched, "\n".join(mismatched)


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_suboptions_match_nested_specs(path):
    """A dict option's suboptions drift the same way top-level options do,
    and are read the same way."""
    options = _documentation(path).get("options") or {}
    problems = []
    for name, entry in _spec(path).items():
        if not isinstance(entry, dict) or not isinstance(entry.get("options"), dict):
            continue
        documented = set((options.get(name) or {}).get("suboptions") or {})
        accepted = set(entry["options"])
        for missing in sorted(accepted - documented):
            problems.append("%s.%s is accepted but not documented" % (name, missing))
        for phantom in sorted(documented - accepted):
            problems.append("%s.%s is documented but not accepted" % (name, phantom))
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("path", MODULE_FILES, ids=IDS)
def test_metadata_is_present(path):
    doc = _documentation(path)
    name = pathlib.Path(path).stem
    assert doc.get("module") == name, (
        "DOCUMENTATION names module %r, file is %s.py" % (doc.get("module"), name))
    assert doc.get("short_description"), "no short_description"
    assert doc.get("version_added"), "no version_added"
    assert doc.get("author"), "no author"
    assert doc.get("extends_documentation_fragment"), (
        "does not extend the shared ciphertrust doc fragment, so localNode "
        "goes undocumented")
