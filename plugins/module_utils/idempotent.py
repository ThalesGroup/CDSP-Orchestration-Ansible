# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""Idempotency helpers for CipherTrust Ansible modules.

These utilities implement the GET-before-write pattern so that modules
report ``changed`` accurately and honour ``--check`` / ``--diff`` mode.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.six.moves.urllib.error import HTTPError

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)


# Kwargs that route the request (build the URL, identify the resource) rather
# than describe desired state.  They are never present in a GET response, so
# comparing them would report a change on every run.
_ALWAYS_IGNORED = frozenset(["node"])


def _is_not_found(exc):
    """True when *exc* means 'the resource does not exist'.

    Any other failure (auth, permissions, server fault) must propagate: a
    500 silently treated as 'absent' leads to a duplicate create.
    """
    if isinstance(exc, CMApiException):
        return getattr(exc, "api_error_code", None) == 404
    return getattr(exc, "code", None) == 404


# ---------------------------------------------------------------------------
# Resource lookup
# ---------------------------------------------------------------------------

def find_resource_by_query(client, endpoint, param, value):
    """Look up a single resource by a query-string filter.

    Returns the first matching resource dict, or ``None`` if no match.
    """
    if value is None:
        return None
    try:
        response = client.get(
            endpoint + "?skip=0&limit=1&" + param + "=" + str(value)
        )
    except (CMApiException, HTTPError) as exc:
        if _is_not_found(exc):
            return None
        raise

    if (
        isinstance(response, dict)
        and response.get("resources")
        and len(response["resources"]) > 0
    ):
        return response["resources"][0]
    return None


# ---------------------------------------------------------------------------
# State comparison
# ---------------------------------------------------------------------------

def resource_needs_update(current, desired, compare_fields=None):
    """Return ``True`` if any *desired* field differs from *current* state.

    *compare_fields* limits comparison to an explicit list.  If omitted,
    every key in *desired* whose value is not ``None`` is compared.
    """
    if compare_fields is None:
        compare_fields = [k for k in desired if desired[k] is not None]
    for field in compare_fields:
        if field in desired and desired[field] is not None:
            if current.get(field) != desired[field]:
                return True
    return False


# ---------------------------------------------------------------------------
# High-level operation helpers
# ---------------------------------------------------------------------------

def idempotent_create(module, client, endpoint, lookup_param, lookup_value,
                      create_fn, create_kwargs):
    """Idempotent resource creation.

    1. GET by *lookup_param* / *lookup_value*.
    2. If resource exists → ``changed=False``, return it.
    3. In check mode → ``changed=True``, return empty.
    4. Otherwise POST via *create_fn* → ``changed=True``.

    Returns ``(changed, response, diff_or_None)``.
    """
    existing = find_resource_by_query(client, endpoint, lookup_param, lookup_value)

    if existing:
        return False, existing, None

    if module.check_mode:
        diff = {"before": {}, "after": {"state": "present"}} if module._diff else None
        return True, {}, diff

    response = create_fn(**create_kwargs)
    diff = {"before": {}, "after": response} if module._diff else None
    return True, response, diff


def idempotent_patch(module, client, endpoint, resource_id,
                     patch_fn, patch_kwargs, compare_fields=None,
                     ignore_fields=None):
    """Idempotent resource update.

    1. GET current state by *resource_id*.
    2. Compare with desired state.
    3. If no diff → ``changed=False``.
    4. In check mode → ``changed=True``, skip write.
    5. Otherwise PATCH → ``changed=True``.

    *ignore_fields* names kwargs that route the request rather than describe
    desired state — the resource identifier (``cm_key_id``, ``policy_id``,
    ``old_name`` …).  They are absent from the GET response, so including
    them in the comparison would make every patch report ``changed=True``
    and issue a redundant write.  Callers must pass their routing key.

    *compare_fields* optionally restricts the comparison to an explicit list.

    Returns ``(changed, response, diff_or_None)``.
    """
    try:
        current = client.get(endpoint + "/" + resource_id)
    except (CMApiException, HTTPError) as exc:
        if not _is_not_found(exc):
            raise
        current = {}

    ignored = set(_ALWAYS_IGNORED)
    if ignore_fields:
        ignored.update(ignore_fields)

    desired = {
        k: v for k, v in patch_kwargs.items()
        if k not in ignored and v is not None
    }

    if not resource_needs_update(current, desired, compare_fields):
        return False, current, None

    if module.check_mode:
        diff = {"before": current, "after": desired} if module._diff else None
        return True, current, diff

    response = patch_fn(**patch_kwargs)
    diff = {"before": current, "after": response} if module._diff else None
    return True, response, diff


def check_mode_action(module):
    """Guard for action-oriented (non-idempotent) modules.

    Call at the top of an action operation.  If check mode is active,
    exits immediately with ``changed=True``.  Otherwise returns so the
    caller can proceed.
    """
    if module.check_mode:
        module.exit_json(changed=True)
