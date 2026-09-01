# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""This module adds shared support for generic Thales CipherTrust modules.

In order to use this module, include it as part of a custom
module as shown below.
  from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import ThalesCipherTrustModule
  module = ThalesCipherTrustModule(argument_spec=dictionary, supports_check_mode=boolean
                            mutually_exclusive=list1, required_together=list2)

The 'ThalesCipherTrustModule' module provides similar, but more restricted,
interfaces to the normal Ansible module.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


from contextlib import contextmanager
from copy import deepcopy
import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CipherTrustError,
    CMApiException,
)

COLLECTION_NAME = "thalesgroup.ciphertrust"
CAMELCASE_DEPRECATION_VERSION = "2.0.0"
_FIRST_CAP_RE = re.compile(r"(.)([A-Z][a-z]+)")
_ALL_CAP_RE = re.compile(r"([a-z0-9])([A-Z])")


def _camel_to_snake(name):
    """Convert camelCase/PascalCase to snake_case."""
    interim = _FIRST_CAP_RE.sub(r"\1_\2", name)
    return _ALL_CAP_RE.sub(r"\1_\2", interim).lower()


def _is_camel_case_name(name):
    if not isinstance(name, str):
        return False
    if "_" in name:
        return False
    return any(char.isupper() for char in name)


def _ensure_alias(entry, alias):
    aliases = list(entry.get("aliases", []))
    if alias not in aliases:
        aliases.append(alias)
    entry["aliases"] = aliases


def _ensure_deprecated_alias(entry, alias):
    deprecated_aliases = list(entry.get("deprecated_aliases", []))
    for existing in deprecated_aliases:
        if isinstance(existing, dict) and existing.get("name") == alias:
            return
    deprecated_aliases.append(
        {
            "name": alias,
            "version": CAMELCASE_DEPRECATION_VERSION,
            "collection_name": COLLECTION_NAME,
        }
    )
    entry["deprecated_aliases"] = deprecated_aliases


def _normalize_argument_spec(argument_spec):
    """Normalize argument_spec keys to snake_case with camelCase aliases."""
    normalized = {}
    legacy_tree = {}
    legacy_to_snake = {}

    for key, value in argument_spec.items():
        key_spec = deepcopy(value)
        snake_key = _camel_to_snake(key) if _is_camel_case_name(key) else key
        legacy_key = key if snake_key != key else None

        existing = normalized.get(snake_key)
        if existing is None:
            target_spec = key_spec
            normalized[snake_key] = target_spec
        else:
            # Rare collision case: preserve the first canonical definition.
            target_spec = existing

        child_tree = {}
        if isinstance(target_spec, dict):
            options = target_spec.get("options")
            if isinstance(options, dict):
                normalized_options, child_tree, _unused = _normalize_argument_spec(
                    options
                )
                target_spec["options"] = normalized_options

        if legacy_key:
            _ensure_alias(target_spec, legacy_key)
            _ensure_deprecated_alias(target_spec, legacy_key)
            legacy_to_snake[legacy_key] = snake_key

        if legacy_key or child_tree:
            legacy_tree[snake_key] = {
                "legacy": legacy_key,
                "children": child_tree,
            }

    return normalized, legacy_tree, legacy_to_snake


def _rewrite_param_name(param_name, legacy_to_snake):
    if isinstance(param_name, str):
        return legacy_to_snake.get(param_name, param_name)
    return param_name


def _rewrite_required_if(required_if, legacy_to_snake):
    if required_if is None:
        return None
    rewritten = []
    for rule in required_if:
        if not isinstance(rule, (list, tuple)):
            rewritten.append(rule)
            continue

        mutable = list(rule)
        if len(mutable) > 0:
            mutable[0] = _rewrite_param_name(mutable[0], legacy_to_snake)
        if len(mutable) > 2:
            required_params = mutable[2]
            if isinstance(required_params, (list, tuple)):
                mutable[2] = [
                    _rewrite_param_name(param_name, legacy_to_snake)
                    for param_name in required_params
                ]
            else:
                mutable[2] = _rewrite_param_name(required_params, legacy_to_snake)

        rewritten.append(type(rule)(mutable) if isinstance(rule, tuple) else mutable)
    return rewritten


def _rewrite_grouped_rules(grouped_rules, legacy_to_snake):
    if grouped_rules is None:
        return None
    rewritten = []
    for group in grouped_rules:
        if isinstance(group, (list, tuple)):
            mapped_group = [
                _rewrite_param_name(param_name, legacy_to_snake) for param_name in group
            ]
            rewritten.append(
                type(group)(mapped_group) if isinstance(group, tuple) else mapped_group
            )
        else:
            rewritten.append(_rewrite_param_name(group, legacy_to_snake))
    return rewritten


def _rewrite_required_by(required_by, legacy_to_snake):
    if required_by is None:
        return None
    rewritten = {}
    for key, values in required_by.items():
        mapped_key = _rewrite_param_name(key, legacy_to_snake)
        if isinstance(values, (list, tuple)):
            mapped_values = [
                _rewrite_param_name(param_name, legacy_to_snake) for param_name in values
            ]
        else:
            mapped_values = _rewrite_param_name(values, legacy_to_snake)
        rewritten[mapped_key] = mapped_values
    return rewritten


def _inject_legacy_params(params, legacy_tree):
    if not isinstance(params, dict):
        return

    for canonical_key, metadata in legacy_tree.items():
        if canonical_key not in params:
            continue

        value = params.get(canonical_key)
        legacy_key = metadata.get("legacy")
        children = metadata.get("children", {})

        if legacy_key and legacy_key not in params:
            params[legacy_key] = value

        if children:
            if isinstance(value, dict):
                _inject_legacy_params(value, children)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _inject_legacy_params(item, children)


class ThalesCipherTrustModule:
    """An ansible module class for CipherTrust modules
    ThalesCipherTrustModule provides an a class for building modules which
    connect to Thales CipherTrust Manager.  The interface is currently more
    restricted than the basic module class with the aim that later the
    basic module class can be reduced.  If you find that any key
    feature is missing please create an issue on the GitHub repo for this collection.
    """

    default_settings = {
        "default_args": True,
        "auto_retry": True,
        "module_class": AnsibleModule,
    }

    def __init__(self, **kwargs):
        local_settings = {}
        for key in ThalesCipherTrustModule.default_settings:
            try:
                local_settings[key] = kwargs.pop(key)
            except KeyError:
                local_settings[key] = ThalesCipherTrustModule.default_settings[key]

        self.settings = local_settings

        self._legacy_param_tree = {}
        if local_settings["default_args"]:
            argument_spec_full = ciphertrust_argument_spec()
            try:
                argument_spec_full.update(kwargs["argument_spec"])
            except (TypeError, NameError):
                pass
            normalized_spec, legacy_tree, legacy_to_snake = _normalize_argument_spec(
                argument_spec_full
            )
            kwargs["argument_spec"] = normalized_spec
            # Only forward a constraint when the caller actually supplied one.
            # Passing an explicit ``None`` makes AnsibleModule's schema
            # validation reject the module (``required_by`` expects a dict).
            rewritten = (
                ("required_if", _rewrite_required_if(
                    kwargs.get("required_if"), legacy_to_snake)),
                ("required_together", _rewrite_grouped_rules(
                    kwargs.get("required_together"), legacy_to_snake)),
                ("required_one_of", _rewrite_grouped_rules(
                    kwargs.get("required_one_of"), legacy_to_snake)),
                ("mutually_exclusive", _rewrite_grouped_rules(
                    kwargs.get("mutually_exclusive"), legacy_to_snake)),
                ("required_by", _rewrite_required_by(
                    kwargs.get("required_by"), legacy_to_snake)),
            )
            for constraint_name, value in rewritten:
                if value is None:
                    kwargs.pop(constraint_name, None)
                else:
                    kwargs[constraint_name] = value
            self._legacy_param_tree = legacy_tree

        self._module = ThalesCipherTrustModule.default_settings["module_class"](
            **kwargs
        )
        _inject_legacy_params(self._module.params, self._legacy_param_tree)
        self.check_mode = self._module.check_mode
        self._diff = self._module._diff
        self._name = self._module._name

    @property
    def params(self):
        return self._module.params

    def exit_json(self, *args, **kwargs):
        return self._module.exit_json(*args, **kwargs)

    def fail_json(self, *args, **kwargs):
        return self._module.fail_json(*args, **kwargs)

    def debug(self, *args, **kwargs):
        return self._module.debug(*args, **kwargs)

    def warn(self, *args, **kwargs):
        return self._module.warn(*args, **kwargs)

    def boolean(self, *args, **kwargs):
        return self._module.boolean(*args, **kwargs)


def _ciphertrust_common_argument_spec():
    """ """
    _node_params = dict(
        server_ip=dict(type="str", required=True),
        server_private_ip=dict(type="str", required=False, default='10.10.10.10'),
        server_port=dict(type="int", required=False, default=5432),
        user=dict(type="str", required=True),
        password=dict(type="str", required=True, no_log=True),
        verify=dict(type="bool", required=False, default=False),
        auth_domain_path=dict(type="str", required=False, default=''),
    )
    return dict(
        localNode=dict(
            type="dict",
            required=True,
            options=_node_params,
        )
    )


def ciphertrust_argument_spec():
    """
    Returns a dictionary containing the argument_spec common to all CipherTrust Manager modules.
    """
    spec = _ciphertrust_common_argument_spec()
    return spec


# ---------------------------------------------------------------------------
# Centralized error handling
# ---------------------------------------------------------------------------

def handle_module_error(module, exc):
    """Translate any collection-specific exception into a ``module.fail_json``.

    * ``CMApiException`` → includes the HTTP/application error code.
    * Any other ``CipherTrustError`` subclass → uses its composed ``message``.
    * ``HTTPError`` / ``URLError`` → raw urllib errors from any code path that
      bypasses ``CipherTrustClient``; translated rather than allowed to escape.
    * Anything else → bubbles up as "Unexpected error: <repr>".
    """
    if isinstance(exc, CMApiException):
        code = getattr(exc, "api_error_code", None)
        if code:
            msg = "API Error (code: {0}): {1}".format(code, exc.message or "")
        else:
            msg = "API Error: {0}".format(exc.message or "")
    elif isinstance(exc, CipherTrustError):
        msg = exc.message or str(exc)
    elif isinstance(exc, HTTPError):
        msg = "API Error (code: {0}): {1}".format(
            exc.code, getattr(exc, "reason", "") or exc
        )
    elif isinstance(exc, URLError):
        msg = "Could not connect to CipherTrust Manager: {0}".format(
            getattr(exc, "reason", exc)
        )
    else:
        msg = "Unexpected error: {0}".format(exc)
    module.fail_json(msg=msg)


@contextmanager
def ciphertrust_operation(module):
    """Context manager that catches every CipherTrust exception.

    Replaces the 70-line repeated ``try/except`` block that was present in
    every module.  Usage::

        with ciphertrust_operation(module):
            changed, response, diff = idempotent_create(...)
            result["changed"] = changed
            result["response"] = response

    Any raised :class:`CipherTrustError` (or subclass), as well as raw
    ``HTTPError``/``URLError`` from urllib, triggers a clean
    ``module.fail_json`` via :func:`handle_module_error`.
    """
    try:
        yield
    except (CipherTrustError, HTTPError, URLError) as exc:
        handle_module_error(module, exc)
