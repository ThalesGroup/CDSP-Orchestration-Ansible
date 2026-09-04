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
module: cckm_azure_subscription
short_description: Remove an Azure subscription from CCKM
description:
    - Removes an Azure subscription record from CCKM.
    - Subscriptions are discovered rather than created -- read them with
      M(thalesgroup.ciphertrust.cckm_azure_subscription_info).
    - Nothing in Azure is deleted.
version_added: "1.1.0"
author:
  - Anurag Jain (@anugram)
extends_documentation_fragment:
  - thalesgroup.ciphertrust.ciphertrust
  - thalesgroup.ciphertrust.attributes
options:
    op_type:
      description:
        - Operation to perform.
        - C(delete) removes the subscription record from CCKM.
      choices:
        - delete
      required: true
      type: str
    subscription_id:
      description:
        - Identifier of the subscription in CCKM.
        - Required.
      type: str
"""

EXAMPLES = """
- name: "Remove a subscription record from CCKM"
  thalesgroup.ciphertrust.cckm_azure_subscription:
    localNode: "{{ cm_connection }}"
    op_type: delete
    subscription_id: "{{ _subscription.response.id }}"
"""

RETURN = r"""
changed:
    description:
      - C(true) when the removal was carried out.
      - The operation has no state to compare against, so it reports C(true) whenever it
        runs.
    returned: always
    type: bool
    sample: true
response:
    description:
      - The raw response dictionary from the CipherTrust Manager API, or the
        existing resource when one was found during a GET-before-write
        idempotency check.
    returned: when the operation returns a body
    type: dict
diff:
    description: Present only in C(--diff) mode when a change occurred.
    returned: when diff mode is enabled and the module made a change
    type: dict
"""

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import (
    ThalesCipherTrustModule,
    ciphertrust_operation,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils import (
    cckm_azure,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.idempotent import (
    check_mode_action,
)
argument_spec = dict(
    op_type=dict(
        type="str",
        choices=[
            "delete",
        ],
        required=True,
    ),
    subscription_id=dict(type="str"),
)


def setup_module_object():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=(
            ["op_type", "delete", ["subscription_id"]],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module


def main():

    module = setup_module_object()

    result = dict(
        changed=False,
    )

    node = module.params.get("localNode")
    params = module.params
    op_type = params.get("op_type")

    with ciphertrust_operation(module):
        if op_type == "delete":
            check_mode_action(module)
            result["response"] = cckm_azure.subscription_delete(
                node=node,
                subscription_id=params.get("subscription_id"),
            )
            result["changed"] = True
        else:
            module.fail_json(msg="invalid op_type")

    module.exit_json(**result)


if __name__ == "__main__":
    main()
