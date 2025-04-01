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
import re
from ansible.module_utils.urls import Request
# from ansible.module_utils.basic import missing_required_lib
# from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
)


def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError as e:
        return False
    return True


def getJwt(host, username, password, auth_domain_path):
    headers = {
        "Content-Type": "application/json",
        "Connection": "keep-alive",
    }
    auth_url = "https://" + host + "/api/v1/auth/tokens"

    if auth_domain_path is not None:
        auth_payload = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "auth_domain_path": auth_domain_path,
        }
    else:
        auth_payload = {
            "grant_type": "password",
            "username": username,
            "password": password,
        }

    r = Request(headers=headers, timeout=120, validate_certs=False)
    _res = r.open(method="POST", url=auth_url, data=json.dumps(auth_payload))
    response = json.loads(_res.read())
    return response["jwt"]


def POSTData(payload=None, cm_node=None, cm_api_endpoint=None, id=None):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    pattern_2xx = re.compile(r"20[0-9]")
    pattern_4xx = re.compile(r"40[0-9]")
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )
    # execute the post API call to create the resource on CM
    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="POST",
            url=cmSessionObject["url"],
            data=payload,
        )

        response = json.loads(_res.read())
        status_code = _res.getcode()

        if id is not None and id in response:
            __ret = {
                "id": response[id],
                "data": response,
                "message": "Resource created successfully",
            }
        else:
            if "codeDesc" in json.dumps(response):
                raise CMApiException(
                    message="Error creating resource < " + response["codeDesc"] + " >",
                    api_error_code=status_code,
                )
            else:
                if id is None:
                    if pattern_2xx.search(str(status_code)):
                        __ret = {
                            "message": "Resource created successfully",
                            "description": str(response),
                        }
                    elif pattern_4xx.search(str(status_code)):
                        raise CMApiException(
                            message="Error creating resource " + str(response),
                            api_error_code=status_code,
                        )
                    else:
                        raise CMApiException(
                            message="Error creating resource " + str(response),
                            api_error_code=status_code,
                        )
                elif id is not None and (pattern_2xx.search(str(status_code))):
                    __ret = {
                        "message": "Resource created successfully",
                        "description": str(response),
                    }
                else:
                    raise CMApiException(
                        message="Error creating resource " + str(response),
                        api_error_code=status_code,
                    )

        return __ret
    except HTTPError as err:
        raise err


# Added to support PUT operation
def PUTData(payload=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    pattern_2xx = re.compile(r"20[0-9]")
    pattern_4xx = re.compile(r"40[0-9]")
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )
    # execute the put API call to update resource on CM
    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="PUT",
            url=cmSessionObject["url"],
            data=payload,
        )

        response = json.loads(_res.read())
        status_code = _res.getcode()

        if is_json(str(response)):
            if "codeDesc" in response.json:
                raise CMApiException(
                    message="Error updating resource < " + response["codeDesc"] + " >",
                    api_error_code=status_code,
                )
            else:
                __ret = {
                    "message": "Resource updated successfully",
                }
        else:
            if pattern_2xx.search(str(status_code)):
                __ret = {
                    "message": "Resource updated successfully",
                    "description": str(response),
                }
            elif pattern_4xx.search(str(status_code)):
                raise CMApiException(
                    message="Error updating resource " + str(response),
                    api_error_code=status_code,
                )
            else:
                raise CMApiException(
                    message="Error updating resource " + str(response),
                    api_error_code=status_code,
                )

        return __ret
    except HTTPError as err:
        raise err


def POSTWithoutData(cm_node=None, cm_api_endpoint=None):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    pattern_2xx = re.compile(r"20[0-9]")
    pattern_4xx = re.compile(r"40[0-9]")
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )
    # execute the post API call to create the resource on CM
    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="POST",
            url=cmSessionObject["url"],
        )

        response = json.loads(_res.read())
        status_code = _res.getcode()

        if is_json(str(response)):
            if "codeDesc" in response.json:
                raise CMApiException(
                    message="Error creating resource < " + response["codeDesc"] + " >",
                    api_error_code=status_code,
                )
            else:
                __ret = {
                    "message": "Resource created successfully",
                }
        else:
            if pattern_2xx.search(str(status_code)):
                __ret = {
                    "message": "Resource created successfully",
                    "description": str(response),
                }
            elif pattern_4xx.search(str(status_code)):
                raise CMApiException(
                    message="Error creating resource " + str(response),
                    api_error_code=status_code,
                )
            else:
                raise CMApiException(
                    message="Error creating resource " + str(response),
                    api_error_code=status_code,
                )

        return __ret
    except HTTPError as err:
        raise err


def PATCHData(payload=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    pattern_2xx = re.compile(r"20[0-9]")
    pattern_4xx = re.compile(r"40[0-9]")
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )
    # execute the patch API call to update the resource on CM
    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="PATCH",
            url=cmSessionObject["url"],
            data=payload,
        )

        response = json.loads(_res.read())
        status_code = _res.getcode()

        if is_json(str(response)):
            if "codeDesc" in response.json:
                raise CMApiException(
                    message="Error creating resource < " + response["codeDesc"] + " >",
                    api_error_code=status_code,
                )
            else:
                __ret = {
                    "message": "Resource updated successfully",
                }
        else:
            if pattern_2xx.search(str(status_code)):
                __ret = {
                    "message": "Resource updated successfully",
                    "status_code": str(response),
                }
            elif pattern_4xx.search(str(status_code)):
                raise CMApiException(
                    message="Error creating resource " + str(response),
                    api_error_code=status_code,
                )
            else:
                raise CMApiException(
                    message="Error creating resource " + str(response),
                    api_error_code=status_code,
                )

        return __ret
    except HTTPError as err:
        raise err


def DELETEByNameOrId(key=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    pattern_2xx = re.compile(r"20[0-9]")
    pattern_4xx = re.compile(r"40[0-9]")
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )
    # execute the delete API call to delete the resource on CM
    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="DELETE",
            url=cmSessionObject["url"] + "/" + key,
        )

        response = _res.read()
        status_code = _res.getcode()

        if is_json(str(response)):
            if "codeDesc" in response.json:
                raise CMApiException(
                    message="Error deleting resource < " + response["codeDesc"] + " >",
                    api_error_code=status_code,
                )
            else:
                __ret = {
                    "message": "Resource deleted successfully",
                }
        else:
            if pattern_2xx.search(str(status_code)):
                __ret = {
                    "message": "Resource deleted successfully",
                    "status_code": str(response),
                }
            elif pattern_4xx.search(str(status_code)):
                raise CMApiException(
                    message="Error deleting resource " + str(response),
                    api_error_code=status_code,
                )
            else:
                raise CMApiException(
                    message="Error deleting resource " + str(response),
                    api_error_code=status_code,
                )

        return __ret
    except HTTPError as err:
        raise err


def DeleteWithoutData(cm_node=None, cm_api_endpoint=None):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    pattern_2xx = re.compile(r"20[0-9]")
    pattern_4xx = re.compile(r"40[0-9]")
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )
    # execute the delete API call to delete the resource on CM
    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="DELETE",
            url=cmSessionObject["url"],
        )

        response = _res.read()
        status_code = _res.getcode()

        if is_json(str(response)):
            if "codeDesc" in response.json():
                raise CMApiException(
                    message="Error creating resource < " + response["codeDesc"] + " >",
                    api_error_code=status_code,
                )
            else:
                return "Resource deleted successfully"
        else:
            if pattern_2xx.search(str(status_code)):
                return "Resource deleted successfully"
            elif pattern_4xx.search(str(status_code)):
                raise CMApiException(
                    message="Error deleting resource " + str(response),
                    api_error_code=status_code,
                )
            else:
                raise CMApiException(
                    message="Error deleting resource " + str(response),
                    api_error_code=status_code,
                )

    except HTTPError as err:
        raise err
    except json.decoder.JSONDecodeError as jsonErr:
        return jsonErr


def GETData(cm_node=None, cm_api_endpoint=None):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )

    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="GET",
            url=cmSessionObject["url"],
        )
        response = json.loads(_res.read())
        status_code = _res.getcode()

        if response["resources"] is None:
            raise CMApiException(
                message="Error fetching data " + str(response),
                api_error_code=status_code,
            )

        if len(response["resources"]) > 0:
            __ret = {"id": response["resources"][0][id]}
        else:
            raise CMApiException(message="No records found", api_error_code=status_code)

        return __ret
    except HTTPError as err:
        raise err


# GETData just returns ID for a particular filter
# This method will simply return the GET API data
def GETAPIData(cm_node=None, cm_api_endpoint=None):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    pattern_2xx = re.compile(r"20[0-9]")
    pattern_4xx = re.compile(r"40[0-9]")
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )

    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="GET",
            url=cmSessionObject["url"],
        )
        response = json.loads(_res.read())
        status_code = _res.getcode()

        if is_json(str(response)):
            if "codeDesc" in response.json():
                raise CMApiException(
                    message="Error in API Call < " + response["codeDesc"] + " >",
                    api_error_code=status_code,
                )
            else:
                __ret = {
                    "message": "Resource fetched successfully",
                    "data": response,
                }
        else:
            if pattern_2xx.search(str(status_code)):
                __ret = {
                    "message": "Resource fetched successfully",
                    "data": response,
                }
            elif pattern_4xx.search(str(status_code)):
                raise CMApiException(
                    message="Error fetching data " + str(response),
                    api_error_code=status_code,
                )
            else:
                raise CMApiException(
                    message="Error fetching data " + str(response),
                    api_error_code=status_code,
                )
        return __ret
    except HTTPError as err:
        raise err
    except json.decoder.JSONDecodeError as jsonErr:
        return jsonErr


# Below method is outdated...need to be cleaned up later


def GETIdByName(name=None, cm_node=None, cm_api_endpoint=None):
    # Create the session object
    cmSessionObject = CMAPIObject(
        cm_api_user=cm_node["user"],
        cm_api_pwd=cm_node["password"],
        cm_url=cm_node["server_ip"],
        auth_domain_path=cm_node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )
    # execute the delete API call to delete the resource on CM
    ret = dict()
    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(
            method="GET",
            url=cmSessionObject["url"] + "/?skip=0&limit=1&name=" + name,
        )
        response = json.loads(_res.read())
        status_code = _res.getcode()

        if len(response.json()["resources"]) > 0:
            ret["id"] = response.json()["resources"][0]["id"]
            ret["status"] = status_code
            return ret
        else:
            ret["status"] = status_code
            ret["id"] = ""
            return ret
    except HTTPError as err:
        raise err


def GETIdByQueryParam(
    param=None, value=None, cm_node=None, cm_api_endpoint=None, id=None
):
    # Create the session object
    # node = ast.literal_eval(cm_node)
    node = cm_node
    cmSessionObject = CMAPIObject(
        cm_api_user=node["user"],
        cm_api_pwd=node["password"],
        cm_url=node["server_ip"],
        auth_domain_path=node["auth_domain_path"],
        cm_api_endpoint=cm_api_endpoint,
        verify=False,
    )

    url = ""
    if param is None:
        url = cmSessionObject["url"]
    else:
        url = cmSessionObject["url"] + "/?skip=0&limit=1&" + param + "=" + value

    try:
        r = Request(
            headers=cmSessionObject["headers"], timeout=120, validate_certs=False
        )
        _res = r.open(method="GET", url=url)

        response = json.loads(_res.read())
        status_code = _res.getcode()

        if response["resources"] is None:
            raise CMApiException(
                message="Error fetching data " + str(response),
                api_error_code=status_code,
            )

        if len(response["resources"]) > 0:
            if id is None:
                return response
            else:
                __ret = {"id": response["resources"][0][id]}
        else:
            raise CMApiException(
                message="No matching records found", api_error_code=status_code
            )

        return __ret
    except HTTPError as err:
        raise err  # AnsibleCMException(message="Exception: cm_api >> " + err)
    # except requests.exceptions.HTTPError as errh:
    #    raise AnsibleCMException(message="HTTPError: cm_api >> " + errh)
    # except requests.exceptions.ConnectionError as errc:
    #    raise AnsibleCMException(message="ConnectionError: cm_api >> " + errc)
    # except requests.exceptions.Timeout as errt:
    #    raise AnsibleCMException(message="TimeoutError: cm_api >> " + errt)
    # except requests.exceptions.RequestException as err:
    #    raise AnsibleCMException(message="ErrorPath: cm_api >> " + err)


def CMAPIObject(
    cm_api_user=None,
    cm_api_pwd=None,
    cm_url=None,
    cm_api_endpoint=None,
    auth_domain_path=None,
    verify=None,
):
    """Create a Ciphertrust Manager (CM) client"""
    session = dict()
    session["url"] = "https://" + cm_url + "/api/v1/" + cm_api_endpoint
    token = getJwt(
        host=cm_url,
        username=cm_api_user,
        password=cm_api_pwd,
        auth_domain_path=auth_domain_path,
    )
    session["headers"] = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": "Bearer " + token,
    }
    return session
