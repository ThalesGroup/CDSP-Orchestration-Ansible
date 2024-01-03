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

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import POSTData, PATCHData, POSTWithoutData, DELETEByNameOrId
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException


def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError as e:
        return False
    return True


def createAccessPolicy(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="data-protection/access-policies",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateAccessPolicy(**kwargs):
    # Using policy_id to update the Access Policy
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "policy_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/access-policies/" +
            kwargs['policy_id'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def accessPolicyAddUserSet(**kwargs):
    # Add UserSet to DPG Access Policy
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "policy_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/access-policies/" +
            kwargs['policy_id'] + "/user-set",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def accessPolicyUpdateUserSet(**kwargs):
    # Update userSet in access policy
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "policy_id", "policy_user_set_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/access-policies/" +
            kwargs['policy_id'] + "/user-set/" + kwargs['policy_user_set_id'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def accessPolicyDeleteUserSet(**kwargs):
    result = dict(
        changed=False,
    )
    endpoint = "data-protection/access-policies/" + \
        kwargs['policy_id'] + "/user-set"
    try:
        response = DELETEByNameOrId(
            key=kwargs['policy_user_set_id'],
            cm_node=kwargs['node'],
            cm_api_endpoint=endpoint
        )
        result['response'] = response
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise

# Save or Update Protection Policy


def createProtectionPolicy(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="data-protection/protection-policies",
            id="name",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateProtectionPolicy(**kwargs):
    # Using policy_name to update the Protection Policy
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "policy_name"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/protection-policies/" +
            kwargs['policy_name'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise

# Save or Update UserSet


def createUserSet(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="data-protection/user-sets",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateUserSet(**kwargs):
    # Using user_set_id to update the UserSet
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "user_set_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/user-sets/" +
            kwargs['user_set_id'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise

# Save or Update CharSet


def createCharacterSet(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="data-protection/character-sets",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateCharacterSet(**kwargs):
    # Using char_set_id to update the Character Set
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "char_set_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/character-sets/" +
            kwargs['char_set_id'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise

# Save or Update Masking Format


def createMaskingFormat(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="data-protection/masking-formats",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateMaskingFormat(**kwargs):
    # Using masking_format_id to update the Masking Format
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "masking_format_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/masking-formats/" +
            kwargs['masking_format_id'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise

# Save or Update Client Profile


def createClientProfile(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="data-protection/client-profiles",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateClientProfile(**kwargs):
    # Using profile_id to update the Client Profile
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "profile_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/client-profiles/" +
            kwargs['profile_id'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise

# Save or Update DPG Policy


def createDPGPolicy(**kwargs):
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="data-protection/dpg-policies",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def updateDPGPolicy(**kwargs):
    # Using policy_id to update the DPG Policy
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "policy_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/dpg-policies/" +
            kwargs['policy_id'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def dpgPolicyAddAPIUrl(**kwargs):
    # Add UserSet to DPG Access Policy
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "policy_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/dpg-policies/" +
            kwargs['policy_id'] + "/api-urls",
            id="id",
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def dpgPolicyUpdateAPIUrl(**kwargs):
    # Update userSet in access policy
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "policy_id", "api_url_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="data-protection/dpg-policies/" +
            kwargs['policy_id'] + "/api-urls/" + kwargs['api_url_id'],
        )
        return ast.literal_eval(str(response))
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def dpgPolicyDeleteAPIUrl(**kwargs):
    result = dict(
        changed=False,
    )
    endpoint = "data-protection/dpg-policies/" + \
        kwargs['policy_id'] + "/api-urls"
    try:
        response = DELETEByNameOrId(
            key=kwargs['api_url_id'],
            cm_node=kwargs['node'],
            cm_api_endpoint=endpoint
        )
        result['response'] = response
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise
