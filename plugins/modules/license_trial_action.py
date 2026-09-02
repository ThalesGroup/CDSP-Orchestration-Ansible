#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023-2026 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: license_trial_action
short_description: Activate or deactivate CipherTrust Manager trial license
description:
    - This is a Thales CipherTrust Manager module for working with the CipherTrust Manager APIs, more specifically with trials activation and deactivation API
version_added: "1.0.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes.no_diff
notes:
  - >-
    This module performs an operation rather than converging on a desired
    state. Except where noted, C(changed) reports that the operation was
    carried out, not that CipherTrust Manager was necessarily altered by it;
    a task that repeats the operation reports C(changed) again.
options:
    action_type:
        description: Operation to be performed on the trial license
        choices: [activate, deactivate]
        required: true
        type: str
    trial_id:
        aliases: [trialId]
        description: CM ID of the trial license
        required: true
        type: str

"""

EXAMPLES = """
- name: "Activate Trial License"
  thalesgroup.ciphertrust.license_trial_action:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    action_type: activate
    trialId: trial_id

- name: "De-activate Trial License"
  thalesgroup.ciphertrust.license_trial_action:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
    action_type: deactivate
    trialId: trial_id
"""

RETURN = r"""
changed:
    description: Always C(true) when the action is performed; C(false) in check mode.
    returned: always
    type: bool
    sample: true
response:
    description: Raw response payload from the CipherTrust Manager API.
    returned: on success
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.licensing import (
    activateTrial,
    deactivateTrial,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)

argument_spec = dict(
    action_type=dict(type="str", choices=["activate", "deactivate"], required=True),
    trialId=dict(type="str", required=True),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=[],
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    with ciphertrust_operation(module):
        if module.params.get("action_type") == "activate":
            check_mode_action(module)
            response = activateTrial(
                node=module.params.get("localNode"),
                trialId=module.params.get("trialId"),
            )
            result["response"] = response
            result["changed"] = True

        else:
            check_mode_action(module)
            response = deactivateTrial(
                node=module.params.get("localNode"),
                trialId=module.params.get("trialId"),
            )
            result["response"] = response
            result["changed"] = True

    module.exit_json(**result)


if __name__ == "__main__":
    main()
