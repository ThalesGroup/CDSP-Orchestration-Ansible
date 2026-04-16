#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""Unit tests for cache/performance helpers in plugins/module_utils/cache.py."""

import time

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cache import (
    CacheManager,
    PerformanceMetrics,
    BatchOperation,
    get_global_cache,
    clear_global_cache,
    get_global_metrics,
    reset_global_metrics,
    cache_resource_id,
    get_cached_resource_id,
    invalidate_resource_id_cache,
)


class TestCacheManager:
    """Tests for CacheManager class."""

    def test_cache_set_and_get(self):
        cache = CacheManager(max_size=100, default_ttl=300)
        cache.set("test_key", {"value": 1})
        assert cache.get("test_key") == {"value": 1}

    def test_cache_ttl_expiration(self):
        cache = CacheManager(max_size=100, default_ttl=300)
        cache.set("test_key", {"value": 1}, ttl=0.01)
        time.sleep(0.02)
        assert cache.get("test_key") is None

    def test_cache_lru_eviction(self):
        cache = CacheManager(max_size=3, default_ttl=300)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        # Make key1 recently used so key2 becomes LRU.
        assert cache.get("key1") == "value1"

        cache.set("key4", "value4")

        assert cache.get("key1") == "value1"
        assert cache.get("key2") is None
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"

    def test_cache_clear(self):
        cache = CacheManager(max_size=100, default_ttl=300)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None


class TestPerformanceMetrics:
    """Tests for PerformanceMetrics class."""

    def test_metrics_initialization(self):
        metrics = PerformanceMetrics()
        summary = metrics.get_metrics()
        assert summary["total_api_calls"] == 0
        assert summary["cache_hits"] == 0
        assert summary["cache_misses"] == 0
        assert summary["batch_operations"] == 0
        assert summary["parallel_executions"] == 0

    def test_record_api_call(self):
        metrics = PerformanceMetrics()
        metrics.record_api_call(
            endpoint="vault/keys2",
            method="GET",
            duration=0.125,
            success=True,
            response_code=200,
        )
        summary = metrics.get_metrics()
        assert summary["total_api_calls"] == 1
        assert summary["total_duration"] == 0.125
        assert summary["avg_duration_per_call"] == 0.125

    def test_cache_hit_miss(self):
        metrics = PerformanceMetrics()
        metrics.record_cache_hit()
        metrics.record_cache_hit()
        metrics.record_cache_miss()
        summary = metrics.get_metrics()
        assert summary["cache_hits"] == 2
        assert summary["cache_misses"] == 1

    def test_batch_and_parallel_metrics(self):
        metrics = PerformanceMetrics()
        metrics.record_batch_operation()
        metrics.record_batch_operation()
        metrics.record_parallel_execution(3)
        summary = metrics.get_metrics()
        assert summary["batch_operations"] == 2
        assert summary["parallel_executions"] == 3

    def test_start_stop(self):
        metrics = PerformanceMetrics()
        metrics.start()
        time.sleep(0.01)
        duration = metrics.stop()
        assert duration > 0

    def test_reset_metrics(self):
        metrics = PerformanceMetrics()
        metrics.record_api_call("vault/keys2", "GET", 0.1, True, 200)
        metrics.record_cache_hit()
        metrics.record_cache_miss()
        metrics.reset()
        summary = metrics.get_metrics()
        assert summary["total_api_calls"] == 0
        assert summary["cache_hits"] == 0
        assert summary["cache_misses"] == 0


class TestBatchOperation:
    """Tests for BatchOperation class."""

    def test_batch_add_operation(self):
        batch = BatchOperation()
        batch.add_operation("create", "usermgmt/users", {"name": "test"})
        assert len(batch._operations) == 1
        assert batch._operations[0]["type"] == "create"
        assert batch._operations[0]["endpoint"] == "usermgmt/users"

    def test_batch_execute(self):
        batch = BatchOperation()
        batch.add_operation("create", "usermgmt/users", {"name": "user1"})
        batch.add_operation("create", "usermgmt/users", {"name": "user2"})

        results = batch.execute(cm_node={"server_ip": "test.example.com"})
        assert len(results) == 2
        assert results[0]["success"] is True
        assert results[0]["endpoint"] == "usermgmt/users"
        assert results[1]["data"]["name"] == "user2"


class TestGlobalCacheAndMetrics:
    """Tests for global cache and metrics singletons."""

    def test_global_cache_instance(self):
        clear_global_cache()
        cache = get_global_cache()
        assert isinstance(cache, CacheManager)

    def test_global_metrics_instance(self):
        reset_global_metrics()
        metrics = get_global_metrics()
        assert isinstance(metrics, PerformanceMetrics)

    def test_reset_global_metrics(self):
        metrics = get_global_metrics()
        metrics.record_api_call("x", "GET", 0.01, True, 200)
        reset_global_metrics()
        summary = get_global_metrics().get_metrics()
        assert summary["total_api_calls"] == 0


class TestResourceIDCaching:
    """Tests for resource ID caching helpers."""

    def test_cache_and_retrieve_resource_id(self):
        clear_global_cache()
        cache_resource_id(None, "dpg_policy", "test_policy", "policy-123")
        cached_id = get_cached_resource_id(None, "dpg_policy", "test_policy")
        assert cached_id == "policy-123"

    def test_invalidate_resource_id_cache(self):
        clear_global_cache()
        cache_resource_id(None, "dpg_policy", "test_policy", "policy-123")
        invalidate_resource_id_cache(None, "dpg_policy", "test_policy")
        cached_id = get_cached_resource_id(None, "dpg_policy", "test_policy")
        assert cached_id is None
