# -*- coding: utf-8 -*-
"""``meta/runtime.yml`` must stay in step with what the collection ships.

The ``all`` action group exists so a play can set ``localNode`` once via
``module_defaults``. A module missing from the group silently opts out of
those defaults, which is the kind of drift that is invisible until a playbook
misbehaves.
"""

import pathlib

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _runtime():
    return yaml.safe_load((REPO_ROOT / "meta" / "runtime.yml").read_text())


def _modules_on_disk():
    return {p.stem for p in (REPO_ROOT / "plugins" / "modules").glob("*.py")
            if p.stem != "__init__"}


def test_action_group_lists_every_module():
    group = set(_runtime()["action_groups"]["all"])
    missing = _modules_on_disk() - group
    assert not missing, "modules missing from the 'all' action group: %s" % sorted(missing)


def test_action_group_has_no_phantom_entries():
    group = set(_runtime()["action_groups"]["all"])
    phantom = group - _modules_on_disk()
    assert not phantom, "action group names modules that do not exist: %s" % sorted(phantom)


def test_requires_ansible_is_declared():
    assert _runtime()["requires_ansible"].startswith(">=")
