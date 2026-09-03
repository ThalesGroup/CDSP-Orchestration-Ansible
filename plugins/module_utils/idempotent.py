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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    _build_query_string,
    quote_segment,
)
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
            endpoint + _build_query_string({"skip": 0, "limit": 1, param: value})
        )
    except (CMApiException, HTTPError) as exc:
        if _is_not_found(exc):
            return None
        raise

    if not (isinstance(response, dict) and response.get("resources")):
        return None

    resource = response["resources"][0]

    # CipherTrust Manager silently ignores a query parameter it does not
    # support and returns the first resource in the collection instead of an
    # empty result -- ca/local-cas?cn=... does exactly this, and the resource
    # it returns does not carry a cn field at all. Taking that at face value
    # makes a create decide the resource already exists and silently do
    # nothing, which is worse than attempting the write and being told it is a
    # duplicate. Only accept a match this function can actually confirm.
    if resource.get(param) != value:
        return None

    return resource


def find_resource_by_filters(client, endpoint, filters, confirm_fields=None):
    """Look up a single resource by several query-string filters.

    The single-field :func:`find_resource_by_query` is enough where a name is
    unique across the collection. It is not for CCKM's AWS keys: an alias is
    unique only within one region of one account, so a create has to ask "is
    there a key with this alias, in this region, under this KMS?" -- and
    getting that wrong means either creating a duplicate key or silently
    adopting a same-named key from another region.

    *filters* are sent as query parameters. *confirm_fields* names the subset
    the returned resource must actually echo back, for the same reason
    :func:`find_resource_by_query` re-checks its one parameter: CipherTrust
    Manager answers an unsupported filter by ignoring it, not by erroring.
    Filters that name a field the response does not carry under the same name
    -- ``alias``, which the response nests inside ``aws_param`` -- are simply
    left out of *confirm_fields* by the caller.

    Returns the first matching resource dict, or ``None``.
    """
    filters = {k: v for k, v in (filters or {}).items() if v is not None}
    if not filters:
        return None

    query = dict(filters)
    query.update({"skip": 0, "limit": 1})
    try:
        response = client.get(endpoint + _build_query_string(query))
    except (CMApiException, HTTPError) as exc:
        if _is_not_found(exc):
            return None
        raise

    if not (isinstance(response, dict) and response.get("resources")):
        return None

    resource = response["resources"][0]
    for field in (confirm_fields or ()):
        if resource.get(field) != filters.get(field):
            return None
    return resource


# ---------------------------------------------------------------------------
# State comparison
# ---------------------------------------------------------------------------

def _differs_as_subset(current_value, desired_value):
    """Compare a nested structure the way a PATCH applies it.

    A PATCH merges: sending ``{"aws_param": {"xks_proxy_uri_endpoint": U}}``
    changes that one field and leaves the rest of ``aws_param`` alone. A plain
    ``!=`` against the GET response therefore reports a change on every run,
    because CipherTrust Manager returns the whole sub-object -- read-only
    fields such as ``connection_state`` included -- and the desired dict holds
    only what the playbook set.

    So a desired dict differs only when one of *its own* keys differs, applied
    recursively. Lists and scalars compare whole: a list is replaced by a
    PATCH, not merged into.
    """
    if isinstance(desired_value, dict):
        if not isinstance(current_value, dict):
            return True
        for key, value in desired_value.items():
            if value is None:
                continue
            if key not in current_value:
                return True
            if _differs_as_subset(current_value[key], value):
                return True
        return False
    return current_value != desired_value


def resource_needs_update(current, desired, compare_fields=None, defaults=None,
                          response_aliases=None, subset_fields=None):
    """Return ``True`` if any *desired* field differs from *current* state.

    *compare_fields* limits comparison to an explicit list.  If omitted,
    every key in *desired* whose value is not ``None`` is compared.

    *defaults* maps parameter names to the value the argument spec supplies
    when a playbook does not. CipherTrust Manager omits many fields from a GET
    (``allVersions`` among them), and a defaulted value the user never asked
    for must not be read as a pending change -- otherwise every patch reports
    ``changed`` for ever and re-sends the same request. A field the user did
    ask for is still applied even when CM does not echo it back.

    *response_aliases* maps a desired field to the name CipherTrust Manager
    reports it under, for the handful of endpoints that accept a field under
    one spelling and return it under another -- CCKM's AWS policy templates
    take ``key_admins`` and answer with ``key-admins``. Without the mapping
    the field looks absent from every GET, so the patch reports ``changed``
    for ever.

    *subset_fields* names fields to compare with PATCH-merge semantics rather
    than for equality; see :func:`_differs_as_subset`.
    """
    if compare_fields is None:
        compare_fields = [k for k in desired if desired[k] is not None]
    defaults = defaults if isinstance(defaults, dict) else {}
    response_aliases = response_aliases if isinstance(response_aliases, dict) else {}
    subset_fields = frozenset(subset_fields or ())

    for field in compare_fields:
        if field not in desired or desired[field] is None:
            continue

        name = field if field in current else response_aliases.get(field, field)
        if name not in current:
            if field in defaults and desired[field] == defaults[field]:
                continue
            return True

        if field in subset_fields:
            if _differs_as_subset(current[name], desired[field]):
                return True
        elif current[name] != desired[field]:
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
    return create_if_absent(module, existing, create_fn, create_kwargs)


def create_if_absent(module, existing, create_fn, create_kwargs):
    """The create half of :func:`idempotent_create`, given a resolved lookup.

    Callers that cannot express "does it already exist?" as one query
    parameter -- CCKM's AWS keys need an alias, a region and a KMS -- do the
    lookup with :func:`find_resource_by_filters` and hand the result here, so
    the create, check-mode and diff behaviour stays in one place.

    Returns ``(changed, response, diff_or_None)``.
    """
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
                     ignore_fields=None, response_aliases=None,
                     subset_fields=None):
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

    *response_aliases* and *subset_fields* are passed to
    :func:`resource_needs_update`; see there for what they are for.

    Returns ``(changed, response, diff_or_None)``.
    """
    try:
        current = client.get(endpoint + "/" + quote_segment(resource_id))
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

    # The spec AnsibleModule holds is the normalised one, so its keys are
    # snake_case while module bodies still read the legacy camelCase names.
    # Record the default under every name the parameter answers to.
    spec = getattr(module, "argument_spec", None)
    defaults = {}
    for name, entry in (spec if isinstance(spec, dict) else {}).items():
        if not isinstance(entry, dict) or entry.get("default") is None:
            continue
        defaults[name] = entry["default"]
        for alias in entry.get("aliases") or []:
            defaults[alias] = entry["default"]

    if not resource_needs_update(current, desired, compare_fields, defaults,
                                 response_aliases, subset_fields):
        return False, current, None

    if module.check_mode:
        diff = {"before": current, "after": desired} if module._diff else None
        return True, current, diff

    response = patch_fn(**patch_kwargs)
    diff = {"before": current, "after": response} if module._diff else None
    return True, response, diff


# ---------------------------------------------------------------------------
# Action helpers
#
# Action-style operations (add a member, delete a resource) have no desired
# state to converge on, but they do have an observable one: whether the thing
# exists at the URL the write would target. Where that can be established the
# operation becomes idempotent; where it cannot, the action is performed, which
# is the behaviour these modules have always had.
# ---------------------------------------------------------------------------

def resource_exists(client, path):
    """Does a resource exist at *path*?

    Returns ``True``, ``False``, or ``None`` when CipherTrust Manager will not
    say -- for example when it rejects a GET on that path. ``None`` means the
    caller must not draw a conclusion and should perform the action.
    """
    try:
        client.get(path)
        return True
    except (CMApiException, HTTPError) as exc:
        if _is_not_found(exc):
            return False
        return None


def idempotent_add(module, client, path, add_fn, add_kwargs):
    """Perform an add unless the resource already exists at *path*.

    Returns ``(changed, response)``.
    """
    if resource_exists(client, path) is True:
        return False, {}

    if module.check_mode:
        return True, {}

    return True, add_fn(**add_kwargs)


def idempotent_remove(module, client, path, remove_fn, remove_kwargs):
    """Perform a removal unless the resource is already absent from *path*.

    Returns ``(changed, response)``.
    """
    if resource_exists(client, path) is False:
        return False, {}

    if module.check_mode:
        return True, {}

    return True, remove_fn(**remove_kwargs)


def check_mode_action(module):
    """Guard for action-oriented (non-idempotent) modules.

    Call at the top of an action operation.  If check mode is active,
    exits immediately with ``changed=True``.  Otherwise returns so the
    caller can proceed.
    """
    if module.check_mode:
        module.exit_json(changed=True)
