# -*- coding: utf-8 -*-

# This is a utility file for interacting with the Thales CipherTrust Manager APIs for managing CipherTrust Manager Services

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import ast

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    POSTData,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)


def restartCMServices(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        __resp = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="system/services/restart",
        )

        return ast.literal_eval(str(__resp))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise
