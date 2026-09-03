# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    """Standard attribute blocks describing check mode and diff support.

    Every module in this collection supports check mode. Diff support depends
    on how the module works: modules that converge on a desired state through
    the idempotency helpers can report a before/after, whereas modules that
    perform an action have no state to compare.

    Use the variant that matches the module:
      * ``attributes``             -- converges on state, full diff
      * ``attributes.partial_diff`` -- some operations converge, others act
      * ``attributes.no_diff``      -- performs an action or reads only
    """

    # Modules whose every operation goes through idempotent_create/patch.
    DOCUMENTATION = r"""
attributes:
  check_mode:
    description:
      - Can run in C(--check) mode and predict C(changed) without modifying
        CipherTrust Manager.
    support: full
  diff_mode:
    description:
      - Returns the current and intended state of the resource when run with
        C(--diff).
    support: full
"""

    # Modules that mix converging operations with actions.
    PARTIAL_DIFF = r"""
attributes:
  check_mode:
    description:
      - Can run in C(--check) mode and predict C(changed) without modifying
        CipherTrust Manager.
    support: full
  diff_mode:
    description:
      - Returns a before/after for the C(create) and C(patch) operations.
      - Other operations perform an action rather than converging on a state,
        so they have nothing to compare and report no diff.
    support: partial
"""

    # Action-only and read-only modules.
    NO_DIFF = r"""
attributes:
  check_mode:
    description:
      - Can run in C(--check) mode. The operation is not performed and
        C(changed) is reported as it would be for a real run.
    support: full
  diff_mode:
    description:
      - This module performs an action or reads state rather than converging
        on a desired state, so there is no before/after to report.
    support: none
"""
