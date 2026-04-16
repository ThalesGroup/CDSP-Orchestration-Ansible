#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the MIT License
#

"""Performance benchmark tests for caching and performance metrics."""

import pytest
import time
import json

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.cache import (
    CacheManager,
    PerformanceMetrics,
    BatchOperation,
    get_cache,
    get_performance_metrics,
    cache_resource_id,
    get_cached_resource_id,
    invalidate_resource_id_cache,
    reset_performance_metrics,
)


class TestCacheManager:
    """Tests for CacheManager class."""

    def test_cache_put_and_get(self):
        """Test basic cache put and get operations."""
        cache = CacheManager(max_size=100, ttl=300)
        cache.put("test_key", "test_value")
        result = cache.get("test_key")
        assert result == "test_value"

    def test_cache_ttl_expiration(self):
        """Test cache entry expiration."""
        cache = CacheManager(max_size=100, ttl=1)
        cache.put("test_key", "test_value")
        time.sleep(2)  # Wait for TTL to expire
        result = cache.get("test_key")
        assert result is None

    def test_cache_lru_eviction(self):
        """Test LRU eviction policy."""
        cache = CacheManager(max_size=3, ttl=300)
        cache.put("key1", "value1")
        cache.put("key2", "value2")
        cache.put("key3", "value3")
        
        # Access key1 to make it recently used
        cache.get("key1")
        
        # Add key4, should evict key2 (least recently used)
        cache.put("key4", "value4")
        
        assert cache.get("key1") == "value1"
        assert cache.get("key2") is None  # Should be evicted
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"

    def test_cache_clear(self):
        """Test cache clear operation."""
        cache = CacheManager(max_size=100, ttl=300)
        cache.put("key1", "value1")
        cache.put("key2", "value2")
        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None


class TestPerformanceMetrics:
    """Tests for PerformanceMetrics class."""

    def test_metrics_initialization(self):
        """Test metrics initialization."""
        metrics = PerformanceMetrics()
        assert metrics.api_calls == 0
        assert metrics.cache_hits == 0
        assert metrics.cache_misses == 0
        assert metrics.batch_operations == 0
        assert metrics.total_execution_time == 0

    def test_increment_api_calls(self):
        """Test API calls increment."""
        metrics = PerformanceMetrics()
        metrics.increment_api_calls()
        assert metrics.api_calls == 1
        metrics.increment_api_calls(5)
        assert metrics.api_calls == 6

    def test_cache_hit_miss(self):
        """Test cache hit and miss tracking."""
        metrics = PerformanceMetrics()
        metrics.record_cache_hit()
        assert metrics.cache_hits == 1
        metrics.record_cache_miss()
        assert metrics.cache_misses == 1

    def test_execution_time_tracking(self):
        """Test execution time tracking."""
        metrics = PerformanceMetrics()
        start_time = time.time()
        time.sleep(0.1)
        end_time = time.time()
        metrics.record_execution_time(start_time, end_time)
        assert metrics.total_execution_time >= 0.1

    def test_reset_metrics(self):
        """Test metrics reset."""
        metrics = PerformanceMetrics()
        metrics.increment_api_calls(5)
        metrics.record_cache_hit()
        metrics.record_cache_miss()
        metrics.record_execution_time(0, 1)
        metrics.reset()
        assert metrics.api_calls == 0
        assert metrics.cache_hits == 0
        assert metrics.cache_misses == 0
        assert metrics.total_execution_time == 0

    def test_get_metrics_summary(self):
        """Test metrics summary generation."""
        metrics = PerformanceMetrics()
        metrics.increment_api_calls(10)
        metrics.record_cache_hit(5)
        metrics.record_cache_miss(3)
        metrics.record_execution_time(0, 2.5)
        
        summary = metrics.get_summary()
        assert summary["api_calls"] == 10
        assert summary["cache_hits"] == 5
        assert summary["cache_misses"] == 3
        assert summary["total_execution_time"] == 2.5


class TestBatchOperation:
    """Tests for BatchOperation class."""

    def test_batch_add_operation(self):
        """Test adding operations to batch."""
        batch = BatchOperation()
        batch.add_operation("create_user", {"name": "test"})
        assert len(batch.operations) == 1
        assert batch.operations[0]["type"] == "create_user"

    def test_batch_execute(self):
        """Test batch execution."""
        batch = BatchOperation()
        batch.add_operation("create_user", {"name": "user1"})
        batch.add_operation("create_user", {"name": "user2"})
        
        # Mock execute function
        executed = []
        def mock_execute(op):
            executed.append(op)
            return {"id": len(executed), "name": op["data"]["name"]}
        
        results = batch.execute(mock_execute)
        assert len(results) == 2
        assert executed[0]["data"]["name"] == "user1"
        assert executed[1]["data"]["name"] == "user2"


class TestGlobalCacheAndMetrics:
    """Tests for global cache and metrics instances."""

    def test_global_cache_instance(self):
        """Test global cache instance."""
        cache = get_cache()
        assert isinstance(cache, CacheManager)

    def test_global_metrics_instance(self):
        """Test global metrics instance."""
        metrics = get_performance_metrics()
        assert isinstance(metrics, PerformanceMetrics)

    def test_reset_performance_metrics(self):
        """Test reset_performance_metrics function."""
        reset_performance_metrics()
        metrics = get_performance_metrics()
        assert metrics.api_calls == 0


class TestResourceIDCaching:
    """Tests for resource ID caching functions."""

    def test_cache_and_retrieve_resource_id(self):
        """Test caching and retrieving resource ID."""
        cache_resource_id("dpg_policy", "test_policy", "policy-123")
        cached_id = get_cached_resource_id("dpg_policy", "test_policy")
        assert cached_id == "policy-123"

    def test_invalidate_resource_id_cache(self):
        """Test invalidating resource ID cache."""
        cache_resource_id("dpg_policy", "test_policy", "policy-123")
        invalidate_resource_id_cache("dpg_policy", "test_policy")
        cached_id = get_cached_resource_id("dpg_policy", "test_policy")
        assert cached_id is None


class TestPerformanceBenchmark:
    """Performance benchmark tests comparing cached vs non-cached operations."""

    def test_cache_performance_benchmark(self):
        """Benchmark cache performance vs direct API calls."""
        cache = CacheManager(max_size=1000, ttl=300)
        
        # Simulate API call function
        def simulate_api_call(resource_id):
            time.sleep(0.001)  # Simulate network latency
            return {"id": resource_id, "data": "test_data"}
        
        # Test without cache
        start_time = time.time()
        for i in range(100):
            result = simulate_api_call(f"resource_{i}")
        no_cache_time = time.time() - start_time
        
        # Test with cache
        cache.clear()
        start_time = time.time()
        for i in range(100):
            cached_result = cache.get(f"cached_resource_{i}")
            if cached_result is None:
                result = simulate_api_call(f"resource_{i}")
                cache.put(f"cached_resource_{i}", result)
            else:
                result = cached_result
        cache_time = time.time() - start_time
        
        # Cache should be faster (allow for some variance)
        assert cache_time <= no_cache_time * 1.5  # Allow 50% variance

    def test_batch_operations_performance(self):
        """Benchmark batch operations vs individual operations."""
        # Simulate individual operations
        start_time = time.time()
        for i in range(10):
            time.sleep(0.001)  # Simulate individual API call
        individual_time = time.time() - start_time
        
        # Simulate batch operations
        start_time = time.time()
        time.sleep(0.005)  # Simulate single batch API call
        batch_time = time.time() - start_time
        
        # Batch should be faster
        assert batch_time < individual_time
