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
import time

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cm_api import (
    POSTData,
    PATCHData,
    POSTWithoutData,
    DeleteWithoutData,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import (
    CMApiException,
    AnsibleCMException,
)
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cache import (
    cache_resource_id,
    get_cached_resource_id,
    invalidate_resource_id_cache,
    get_global_metrics,
    BatchOperation,
)


def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError as e:
        return False
    return True


def create(**kwargs):
    """
    Create a group with performance metrics.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - name: Group name
            - description: Group description
            - domain: Domain name
            - local_user_list: List of local users
            - client_list: List of clients
            - user_list: List of users
            - group_list: List of groups
            - client_group_list: List of client groups

    Returns:
        dict: API response with group details
    """
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value is not None:
            request[key] = value

    payload = json.dumps(request)
    url = "usermgmt/groups"

    start_time = time.time()
    try:
        response = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
            id="name",
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=True,
            response_code=200,
        )
        # Cache the group ID
        if response and "id" in response:
            cache_resource_id(None, "group", response["id"], response["name"])
        return response
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise


def patch(**kwargs):
    """
    Patch a group with performance metrics.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - old_name: Original group name
            - name: New group name (optional)
            - description: New description (optional)
            - domain: New domain (optional)
            - local_user_list: New local users list (optional)
            - client_list: New clients list (optional)
            - user_list: New users list (optional)
            - group_list: New groups list (optional)
            - client_group_list: New client groups list (optional)

    Returns:
        dict: API response with updated group details
    """
    result = dict()
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "old_name"] and value is not None:
            request[key] = value

    payload = json.dumps(request)
    url = "usermgmt/groups/" + kwargs["old_name"]

    start_time = time.time()
    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="PATCH",
            duration=duration,
            success=True,
            response_code=200,
        )
        # Invalidate cache for the old group name
        if kwargs.get("old_name") and kwargs.get("old_name") != kwargs.get("name"):
            invalidate_resource_id_cache(None, "group", kwargs["old_name"])
        return response
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="PATCH",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="PATCH",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise


def addUserToGroup(**kwargs):
    """
    Add a user to a group with caching and performance metrics.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - name: Group name
            - object_id: User ID to add

    Returns:
        dict: API response
    """
    # Check cache first
    cache_key = f"user_group:{kwargs['name']}:{kwargs['object_id']}"
    cached = get_cached_resource_id(None, "user_group", cache_key)
    if cached:
        get_global_metrics().record_cache_hit()
        return {"cached": True, "message": "User already in group (cached)"}

    get_global_metrics().record_cache_miss()
    url = "usermgmt/groups/" + kwargs["name"] + "/users/" + kwargs["object_id"]

    start_time = time.time()
    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=True,
            response_code=200,
        )
        return response
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise


def addClientToGroup(**kwargs):
    """
    Add a client to a group with caching and performance metrics.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - name: Group name
            - object_id: Client ID to add

    Returns:
        dict: API response
    """
    # Check cache first
    cache_key = f"client_group:{kwargs['name']}:{kwargs['object_id']}"
    cached = get_cached_resource_id(None, "client_group", cache_key)
    if cached:
        get_global_metrics().record_cache_hit()
        return {"cached": True, "message": "Client already in group (cached)"}

    get_global_metrics().record_cache_miss()
    url = (
        "client-management/groups/" + kwargs["name"] + "/clients/" + kwargs["object_id"]
    )

    start_time = time.time()
    try:
        response = POSTWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=True,
            response_code=200,
        )
        return response
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="POST",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise


def deleteUserFromGroup(**kwargs):
    """
    Delete a user from a group with performance metrics.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - name: Group name
            - object_id: User ID to delete

    Returns:
        str: Response message
    """
    invalidate_resource_id_cache(
        None, "user_group", f"user_group:{kwargs['name']}:{kwargs['object_id']}"
    )
    url = "usermgmt/groups/" + kwargs["name"] + "/users/" + kwargs["object_id"]

    start_time = time.time()
    try:
        response = DeleteWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="DELETE",
            duration=duration,
            success=True,
            response_code=200,
        )
        return str(response)
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="DELETE",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="DELETE",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise


def batchAddUsersToGroup(**kwargs):
    """
    Batch add users to a group using batch operations.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - name: Group name
            - user_ids: List of user IDs to add
            - batch_size: Size of each batch (default 10)

    Returns:
        dict: Batch operation results
    """
    batch = BatchOperation(
        operation_type="add_users_to_group",
        batch_size=kwargs.get("batch_size", 10),
        group_name=kwargs["name"],
    )

    for user_id in kwargs["user_ids"]:
        cache_key = f"user_group:{kwargs['name']}:{user_id}"
        cached = get_cached_resource_id(None, "user_group", cache_key)
        if cached:
            get_global_metrics().record_cache_hit()
            batch.add_cached_result({"user_id": user_id, "cached": True, "message": "User already in group (cached)"})
        else:
            get_global_metrics().record_cache_miss()
            batch.add_operation(
                operation_id=user_id,
                endpoint=f"usermgmt/groups/{kwargs['name']}/users/{user_id}",
                method="POST",
                payload=None,
            )

    if batch.has_operations():
        try:
            results = batch.execute(kwargs["node"])
            return {
                "batch_operation": True,
                "total_operations": len(kwargs["user_ids"]),
                "cached_operations": batch.get_cached_count(),
                "api_operations": batch.get_api_count(),
                "success_count": sum(1 for r in results if r.get("success")),
                "failed_count": sum(1 for r in results if not r.get("success")),
                "results": results,
            }
        except Exception as e:
            return {
                "batch_operation": True,
                "error": str(e),
                "total_operations": len(kwargs["user_ids"]),
                "success_count": 0,
                "failed_count": len(kwargs["user_ids"]),
            }
    else:
        return {
            "batch_operation": True,
            "total_operations": len(kwargs["user_ids"]),
            "cached_operations": batch.get_cached_count(),
            "api_operations": 0,
            "all_cached": True,
            "message": "All users already in group (from cache)",
        }


def batchAddClientsToGroup(**kwargs):
    """
    Batch add clients to a group using batch operations.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - name: Group name
            - client_ids: List of client IDs to add
            - batch_size: Size of each batch (default 10)

    Returns:
        dict: Batch operation results
    """
    batch = BatchOperation(
        operation_type="add_clients_to_group",
        batch_size=kwargs.get("batch_size", 10),
        group_name=kwargs["name"],
    )

    for client_id in kwargs["client_ids"]:
        cache_key = f"client_group:{kwargs['name']}:{client_id}"
        cached = get_cached_resource_id(None, "client_group", cache_key)
        if cached:
            get_global_metrics().record_cache_hit()
            batch.add_cached_result({"client_id": client_id, "cached": True, "message": "Client already in group (cached)"})
        else:
            get_global_metrics().record_cache_miss()
            batch.add_operation(
                operation_id=client_id,
                endpoint=f"client-management/groups/{kwargs['name']}/clients/{client_id}",
                method="POST",
                payload=None,
            )

    if batch.has_operations():
        try:
            results = batch.execute(kwargs["node"])
            return {
                "batch_operation": True,
                "total_operations": len(kwargs["client_ids"]),
                "cached_operations": batch.get_cached_count(),
                "api_operations": batch.get_api_count(),
                "success_count": sum(1 for r in results if r.get("success")),
                "failed_count": sum(1 for r in results if not r.get("success")),
                "results": results,
            }
        except Exception as e:
            return {
                "batch_operation": True,
                "error": str(e),
                "total_operations": len(kwargs["client_ids"]),
                "success_count": 0,
                "failed_count": len(kwargs["client_ids"]),
            }
    else:
        return {
            "batch_operation": True,
            "total_operations": len(kwargs["client_ids"]),
            "cached_operations": batch.get_cached_count(),
            "api_operations": 0,
            "all_cached": True,
            "message": "All clients already in group (from cache)",
        }


def deleteClientFromGroup(**kwargs):
    """
    Delete a client from a group with performance metrics.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - name: Group name
            - object_id: Client ID to delete

    Returns:
        str: Response message
    """
    invalidate_resource_id_cache(
        None, "client_group", f"client_group:{kwargs['name']}:{kwargs['object_id']}"
    )
    url = (
        "client-management/groups/" + kwargs["name"] + "/clients/" + kwargs["object_id"]
    )

    start_time = time.time()
    try:
        response = DeleteWithoutData(
            cm_node=kwargs["node"],
            cm_api_endpoint=url,
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="DELETE",
            duration=duration,
            success=True,
            response_code=200,
        )
        return str(response)
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="DELETE",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint=url,
            method="DELETE",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise
