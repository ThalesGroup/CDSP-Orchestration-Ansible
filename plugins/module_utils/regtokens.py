#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import ast

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    POSTData,
    PATCHData,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)


def create(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="client-management/regtokens",
            id="token",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def patch(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="client-management/regtokens/" + kwargs["id"],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise
