# -*- coding: utf-8 -*-
#
# (c) 2024 Thales Group. All rights reserved.
# Author: Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""
Cache utility module for performance optimization.
Provides caching functionality to reduce redundant API calls.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import time
import json
import os
from collections import OrderedDict


class CacheManager:
    """
    Cache manager for storing and retrieving API responses and resource IDs.
    Implements LRU (Least Recently Used) cache eviction policy.
    """

    def __init__(self, max_size=1000, default_ttl=300):
        """
        Initialize the cache manager.

        Args:
            max_size (int): Maximum number of cache entries
            default_ttl (int): Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache = OrderedDict()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "insertions": 0,
        }

    def get(self, key):
        """
        Get a value from the cache.

        Args:
            key (str): Cache key

        Returns:
            dict or None: Cached value or None if not found or expired
        """
        if key not in self._cache:
            self._stats["misses"] += 1
            return None

        entry = self._cache[key]

        # Check if entry has expired
        if entry["expires_at"] < time.time():
            del self._cache[key]
            self._stats["misses"] += 1
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        self._stats["hits"] += 1
        return entry["value"]

    def set(self, key, value, ttl=None):
        """
        Set a value in the cache.

        Args:
            key (str): Cache key
            value (dict): Value to cache
            ttl (int): Time-to-live in seconds (uses default if not specified)
        """
        if ttl is None:
            ttl = self.default_ttl

        # Remove oldest entry if cache is full
        while len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
            self._stats["evictions"] += 1

        self._cache[key] = {
            "value": value,
            "created_at": time.time(),
            "expires_at": time.time() + ttl,
        }
        self._stats["insertions"] += 1

    def delete(self, key):
        """
        Delete a value from the cache.

        Args:
            key (str): Cache key
        """
        if key in self._cache:
            del self._cache[key]

    def clear(self):
        """Clear all cache entries."""
        self._cache.clear()

    def get_stats(self):
        """
        Get cache statistics.

        Returns:
            dict: Cache statistics
        """
        total = self._stats["hits"] + self._stats["misses"]
        hit_rate = (
            round(self._stats["hits"] / total * 100, 2) if total > 0 else 0
        )
        return {
            **self._stats,
            "total_requests": total,
            "hit_rate_percent": hit_rate,
            "current_size": len(self._cache),
        }

    def cleanup_expired(self):
        """Remove all expired entries."""
        current_time = time.time()
        expired_keys = [
            key
            for key, entry in self._cache.items()
            if entry["expires_at"] < current_time
        ]
        for key in expired_keys:
            del self._cache[key]


# Global cache instance
_global_cache = None


def get_global_cache():
    """
    Get the global cache instance.

    Returns:
        CacheManager: Global cache instance
    """
    global _global_cache
    if _global_cache is None:
        _global_cache = CacheManager()
    return _global_cache


def clear_global_cache():
    """Clear the global cache instance."""
    global _global_cache
    if _global_cache is not None:
        _global_cache.clear()


# Cache key generation functions


def generate_resource_id_cache_key(resource_type, name, domain_path=None):
    """
    Generate a cache key for resource ID lookup.

    Args:
        resource_type (str): Type of resource (e.g., 'user', 'group', 'policy')
        name (str): Resource name
        domain_path (str): Authentication domain path (optional)

    Returns:
        str: Cache key
    """
    key = f"resource_id:{resource_type}:{name}"
    if domain_path:
        key += f":{domain_path}"
    return key


def generate_api_response_cache_key(endpoint, method, params=None):
    """
    Generate a cache key for API response.

    Args:
        endpoint (str): API endpoint
        method (str): HTTP method
        params (dict): Request parameters (optional)

    Returns:
        str: Cache key
    """
    key = f"api_response:{method}:{endpoint}"
    if params:
        key += f":{json.dumps(params, sort_keys=True)}"
    return key


def generate_list_cache_key(resource_type, domain_path=None):
    """
    Generate a cache key for listing resources.

    Args:
        resource_type (str): Type of resource
        domain_path (str): Authentication domain path (optional)

    Returns:
        str: Cache key
    """
    key = f"list:{resource_type}"
    if domain_path:
        key += f":{domain_path}"
    return key


# Resource ID caching functions


def cache_resource_id(module, resource_type, name, resource_id, domain_path=None):
    """
    Cache a resource ID.

    Args:
        module: Ansible module instance
        resource_type (str): Type of resource
        name (str): Resource name
        resource_id (str): Resource ID
        domain_path (str): Authentication domain path (optional)
    """
    cache = get_global_cache()
    key = generate_resource_id_cache_key(resource_type, name, domain_path)
    cache.set(key, {"id": resource_id})


def get_cached_resource_id(module, resource_type, name, domain_path=None):
    """
    Get a cached resource ID.

    Args:
        module: Ansible module instance
        resource_type (str): Type of resource
        name (str): Resource name
        domain_path (str): Authentication domain path (optional)

    Returns:
        str or None: Cached resource ID or None
    """
    cache = get_global_cache()
    key = generate_resource_id_cache_key(resource_type, name, domain_path)
    result = cache.get(key)
    return result["id"] if result else None


def invalidate_resource_id_cache(module, resource_type, name, domain_path=None):
    """
    Invalidate a cached resource ID.

    Args:
        module: Ansible module instance
        resource_type (str): Type of resource
        name (str): Resource name
        domain_path (str): Authentication domain path (optional)
    """
    cache = get_global_cache()
    key = generate_resource_id_cache_key(resource_type, name, domain_path)
    cache.delete(key)


# Batch operation support


class BatchOperation:
    """
    Batch operation manager for grouping multiple API calls.
    """

    def __init__(self, max_batch_size=50):
        """
        Initialize the batch operation manager.

        Args:
            max_batch_size (int): Maximum number of operations per batch
        """
        self.max_batch_size = max_batch_size
        self._operations = []
        self._results = []

    def add_operation(self, operation_type, endpoint, data=None):
        """
        Add an operation to the batch.

        Args:
            operation_type (str): Type of operation ('create', 'update', 'delete')
            endpoint (str): API endpoint
            data (dict): Operation data (optional)
        """
        self._operations.append({
            "type": operation_type,
            "endpoint": endpoint,
            "data": data,
        })

    def execute(self, cm_node):
        """
        Execute the batch operations.

        Args:
            cm_node (dict): CipherTrust node configuration

        Returns:
            list: Results of each operation
        """
        # TODO: Implement actual batch execution
        # For now, execute operations individually
        results = []
        for op in self._operations:
            # This would be replaced with actual batch API call
            results.append({
                "success": True,
                "endpoint": op["endpoint"],
                "data": op["data"],
            })
        self._results.extend(results)
        self._operations.clear()
        return results

    def get_results(self):
        """
        Get results of executed operations.

        Returns:
            list: Results of operations
        """
        return self._results

    def clear(self):
        """Clear all operations and results."""
        self._operations.clear()
        self._results.clear()


# Performance metrics collection


class PerformanceMetrics:
    """
    Performance metrics collector for API calls.
    """

    def __init__(self):
        """
        Initialize the performance metrics collector.
        """
        self._metrics = {
            "api_calls": [],
            "cache_hits": 0,
            "cache_misses": 0,
            "batch_operations": 0,
            "parallel_executions": 0,
        }
        self._start_time = None

    def start(self):
        """Start timing."""
        self._start_time = time.time()

    def stop(self):
        """Stop timing and calculate duration."""
        if self._start_time:
            return time.time() - self._start_time
        return 0

    def record_api_call(self, endpoint, method, duration, success, response_code=None):
        """
        Record an API call.

        Args:
            endpoint (str): API endpoint
            method (str): HTTP method
            duration (float): Duration in seconds
            success (bool): Whether the call was successful
            response_code (int): HTTP response code (optional)
        """
        self._metrics["api_calls"].append({
            "endpoint": endpoint,
            "method": method,
            "duration": duration,
            "success": success,
            "response_code": response_code,
            "timestamp": time.time(),
        })

    def record_cache_hit(self):
        """Record a cache hit."""
        self._metrics["cache_hits"] += 1

    def record_cache_miss(self):
        """Record a cache miss."""
        self._metrics["cache_misses"] += 1

    def record_batch_operation(self):
        """Record a batch operation."""
        self._metrics["batch_operations"] += 1

    def record_parallel_execution(self, num_parallel):
        """Record parallel executions."""
        self._metrics["parallel_executions"] += num_parallel

    def get_metrics(self):
        """
        Get performance metrics.

        Returns:
            dict: Performance metrics
        """
        total_api_calls = len(self._metrics["api_calls"])
        total_duration = sum(call["duration"] for call in self._metrics["api_calls"])
        avg_duration = (
            total_duration / total_api_calls if total_api_calls > 0 else 0
        )

        return {
            **self._metrics,
            "total_api_calls": total_api_calls,
            "total_duration": round(total_duration, 3),
            "avg_duration_per_call": round(avg_duration, 3),
            "cache_stats": get_global_cache().get_stats() if get_global_cache() else {},
        }

    def reset(self):
        """Reset all metrics."""
        self._metrics = {
            "api_calls": [],
            "cache_hits": 0,
            "cache_misses": 0,
            "batch_operations": 0,
            "parallel_executions": 0,
        }
        self._start_time = None


# Global metrics instance
_global_metrics = None


def get_global_metrics():
    """
    Get the global metrics instance.

    Returns:
        PerformanceMetrics: Global metrics instance
    """
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = PerformanceMetrics()
    return _global_metrics


def reset_global_metrics():
    """Reset the global metrics instance."""
    global _global_metrics
    if _global_metrics is not None:
        _global_metrics.reset()


# Utility functions for module integration


def add_performance_metadata(module, result, metrics=None, cache_stats=None):
    """
    Add performance metadata to module result.

    Args:
        module: Ansible module instance
        result (dict): Module result dictionary
        metrics (dict): Performance metrics (optional)
        cache_stats (dict): Cache statistics (optional)
    """
    if metrics is None:
        metrics = get_global_metrics().get_metrics()
    if cache_stats is None and get_global_cache():
        cache_stats = get_global_cache().get_stats()

    performance_metadata = {
        "performance": {
            "api_calls_made": metrics.get("total_api_calls", 0),
            "cache_hits": metrics.get("cache_hits", 0),
            "cache_misses": metrics.get("cache_misses", 0),
            "cache_hit_rate_percent": cache_stats.get("hit_rate_percent", 0) if cache_stats else 0,
            "total_execution_time_seconds": round(metrics.get("total_duration", 0), 3),
            "avg_time_per_api_call_seconds": round(metrics.get("avg_duration_per_call", 0), 3),
        }
    }

    if "meta" not in result:
        result["meta"] = {}
    result["meta"].update(performance_metadata)
