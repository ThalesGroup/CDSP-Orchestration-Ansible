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
    Create a user with performance metrics.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - user_id: User ID
            - username: Username
            - first_name: First name
            - last_name: Last name
            - email: Email address
            - phone: Phone number
            - country: Country
            - state: State
            - city: City
            - zip: ZIP code
            - locale: Locale
            - company: Company
            - role: Role
            - password: Password

    Returns:
        dict: API response with user details
    """
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value is not None:
            request[key] = value

    payload = json.dumps(request)

    start_time = time.time()
    try:
        __resp = POSTData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="usermgmt/users",
            id="user_id",
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="usermgmt/users",
            method="POST",
            duration=duration,
            success=True,
            response_code=200,
        )
        # Cache the user ID
        if __resp and "user_id" in __resp:
            cache_resource_id(None, "user", __resp["user_id"], kwargs.get("username", __resp["user_id"]))
        return __resp
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="usermgmt/users",
            method="POST",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="usermgmt/users",
            method="POST",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise


def patch(**kwargs):
    """
    Patch a user with performance metrics.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - cm_user_id: User ID to patch
            - username: New username (optional)
            - first_name: New first name (optional)
            - last_name: New last name (optional)
            - email: New email (optional)
            - phone: New phone (optional)
            - country: New country (optional)
            - state: New state (optional)
            - city: New city (optional)
            - zip: New ZIP code (optional)
            - locale: New locale (optional)
            - company: New company (optional)
            - role: New role (optional)

    Returns:
        dict: API response with updated user details
    """
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "cm_user_id"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    start_time = time.time()
    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="usermgmt/users/" + kwargs["cm_user_id"],
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="usermgmt/users/" + kwargs["cm_user_id"],
            method="PATCH",
            duration=duration,
            success=True,
            response_code=200,
        )
        # Invalidate cache for the user ID
        invalidate_resource_id_cache(None, "user", kwargs["cm_user_id"])
        return response
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="usermgmt/users/" + kwargs["cm_user_id"],
            method="PATCH",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="usermgmt/users/" + kwargs["cm_user_id"],
            method="PATCH",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise


def changepw(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="auth/changepw",
        )
        return response
    except CMApiException as api_e:
        raise
    except AnsibleCMException as custom_e:
        raise


def patch_self(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node"] and value is not None:
            request[key] = value

    payload = json.dumps(request)

    start_time = time.time()
    try:
        response = PATCHData(
            payload=payload,
            cm_node=kwargs["node"],
            cm_api_endpoint="auth/self/user",
        )
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="auth/self/user",
            method="PATCH",
            duration=duration,
            success=True,
            response_code=200,
        )
        return response
    except CMApiException as api_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="auth/self/user",
            method="PATCH",
            duration=duration,
            success=False,
            response_code=api_e.api_error_code,
        )
        raise
    except AnsibleCMException as custom_e:
        duration = time.time() - start_time
        get_global_metrics().record_api_call(
            endpoint="auth/self/user",
            method="PATCH",
            duration=duration,
            success=False,
            response_code=None,
        )
        raise


def batchCreateUsers(**kwargs):
    """
    Batch create users using batch operations.

    Args:
        **kwargs: Keyword arguments including:
            - node: CipherTrust node configuration
            - users: List of user dictionaries with user details
            - batch_size: Size of each batch (default 10)

    Returns:
        dict: Batch operation results
    """
    batch = BatchOperation(
        operation_type="create_users",
        batch_size=kwargs.get("batch_size", 10),
    )

    for user_data in kwargs["users"]:
        username = user_data.get("username", user_data.get("user_id", "unknown"))
        cache_key = f"user:{username}"
        cached = get_cached_resource_id(None, "user", cache_key)
        if cached:
            get_global_metrics().record_cache_hit()
            batch.add_cached_result({"username": username, "cached": True, "message": "User already exists (cached)"})
        else:
            get_global_metrics().record_cache_miss()
            payload = {}
            for key, value in user_data.items():
                if key != "node":
                    payload[key] = value
            batch.add_operation(
                operation_id=username,
                endpoint="usermgmt/users",
                method="POST",
                payload=json.dumps(payload),
            )

    if batch.has_operations():
        try:
            results = batch.execute(kwargs["node"])
            return {
                "batch_operation": True,
                "total_operations": len(kwargs["users"]),
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
                "total_operations": len(kwargs["users"]),
                "success_count": 0,
                "failed_count": len(kwargs["users"]),
            }
    else:
        return {
            "batch_operation": True,
            "total_operations": len(kwargs["users"]),
            "cached_operations": batch.get_cached_count(),
            "api_operations": 0,
            "all_cached": True,
            "message": "All users already exist (from cache)",
        }
