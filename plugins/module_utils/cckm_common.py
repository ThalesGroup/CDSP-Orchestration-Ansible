# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""Helpers shared by CCKM's per-cloud services.

CCKM presents the same request conventions whichever cloud is behind it --
recursively pruned payloads, multi-valued query filters, and action names
that form part of a URL and so must be validated. Those live here so
``cckm_aws`` and ``cckm_azure`` share one implementation rather than two that
can drift.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.six.moves.urllib.parse import urlencode

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    AnsibleCMParameterException,
)


def prune(value):
    """Drop ``None`` recursively from dicts and lists.

    ``AnsibleModule`` materialises every declared suboption, so a playbook
    that sets only ``aws_param.alias`` still produces a dict with a ``None``
    for each field it did not set. Sending those nulls is not the same as
    omitting them: AWS reads an explicit ``Description: null`` as a request to
    clear the description.

    A dict or list that is empty *after* pruning is dropped as well, so an
    untouched ``aws_param`` disappears instead of being sent as ``{}``.
    """
    if isinstance(value, dict):
        pruned = {}
        for key, item in value.items():
            if item is None:
                continue
            cleaned = prune(item)
            if cleaned is None:
                continue
            pruned[key] = cleaned
        return pruned or None
    if isinstance(value, list):
        cleaned = [prune(item) for item in value if item is not None]
        cleaned = [item for item in cleaned if item is not None]
        return cleaned or None
    return value


def remap_keys(source, mapping):
    """Rename the keys of *source* through *mapping*, dropping ``None`` values.

    Used where the API's field names are not the names the modules expose.
    AWS key parameters are PascalCase on the wire (``CustomerMasterKeySpec``);
    the modules spell them snake_case, as Ansible options are spelled
    everywhere else in this collection.
    """
    if not isinstance(source, dict):
        return None
    out = {}
    for name, value in source.items():
        if value is None:
            continue
        out[mapping.get(name, name)] = value
    return out or None


def build_query(params):
    """Build an encoded query string, repeating a key for each list element.

    CCKM's list endpoints declare their multi-valued filters as
    ``collectionFormat: multi`` -- ``?region=us-east-1&region=eu-west-1``, not
    a comma-joined value -- so a list has to become one pair per element.
    Booleans are lowercased, because ``?enabled=True`` is not what the API
    reads as true.
    """
    pairs = []
    for key, value in params.items():
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if item is None:
                continue
            if isinstance(item, bool):
                item = "true" if item else "false"
            pairs.append((key, item))
    if not pairs:
        return ""
    return "?" + urlencode(pairs)


def guard(value, allowed, parameter):
    """Reject a URL-forming value that is not in *allowed*.

    The modules constrain these with ``choices``, so a rejection here means a
    caller inside the collection passed something the API does not serve.
    """
    if value not in allowed:
        raise AnsibleCMParameterException(
            message="unsupported {0} for a CCKM request".format(parameter),
            parameter=parameter,
            valid_values=", ".join(sorted(allowed)),
        )
    return value
