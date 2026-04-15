# Performance Best Practices

This document provides best practices for optimizing performance when using the ThalesGroup CipherTrust Ansible Collection.

## Overview

The collection includes several performance optimization features:

- **Caching**: Resource IDs are cached to avoid redundant API calls
- **Batch Operations**: Multiple operations can be batched into a single API call
- **Performance Metrics**: Detailed metrics are collected for each module execution

## Caching

### How Caching Works

The collection uses an LRU (Least Recently Used) cache with configurable TTL (Time To Live):

- **Default TTL**: 300 seconds (5 minutes)
- **Default Max Size**: 1000 entries
- **Cache Keys**: Resource type and name (e.g., `dpg_policy:my-policy`)

### Cacheable Resources

The following resources are currently cached:

- DPG Policies
- User Sets
- Client Sets
- Character Sets
- Masking Formats
- Client Profiles

### Best Practices for Caching

1. **Use Descriptive Names**: When creating resources, use descriptive names that will be used for caching.

2. **Cache Invalidation**: The cache is automatically invalidated when resources are updated or deleted.

3. **TTL Configuration**: Adjust the TTL based on your use case:
   - Short TTL (30-60 seconds) for frequently changing resources
   - Long TTL (300+ seconds) for static resources

## Batch Operations

### Supported Batch Operations

The following batch operations are available:

- **Batch User Creation**: Create multiple users in a single API call
- **Batch Group Membership**: Add multiple users/clients to a group in a single API call

### Best Practices for Batch Operations

1. **Group Related Operations**: Batch operations that are logically related.

2. **Limit Batch Size**: Keep batch sizes reasonable (10-50 items) to avoid timeouts.

3. **Error Handling**: Handle partial failures gracefully - some items in the batch may succeed while others fail.

## Performance Metrics

### Metrics Collected

Each module now returns performance metrics:

- **API Calls**: Total number of API calls made
- **Cache Hits**: Number of cache hits
- **Cache Misses**: Number of cache misses
- **Execution Time**: Total execution time in seconds

### Best Practices for Performance Metrics

1. **Monitor API Call Counts**: High API call counts may indicate opportunities for caching or batching.

2. **Track Cache Hit Rates**: Low cache hit rates may indicate:
   - Cache TTL too short
   - Cache size too small
   - Resource names not consistent

3. **Set Performance Baselines**: Establish baseline metrics for normal operations to detect performance regressions.

## Module-Specific Optimizations

### group_save Module

**Optimizations**:
- Caches group IDs by name
- Supports batch user/client additions
- Tracks performance metrics

**Best Practices**:
- Use the `users` and `clients` parameters to add multiple members in a single operation
- Leverage the `cache_info` in the response to monitor cache effectiveness

### usermgmt_users_save Module

**Optimizations**:
- Caches user IDs by name
- Supports batch user creation
- Tracks performance metrics

**Best Practices**:
- Use the `batch_create` parameter to create multiple users in a single API call
- Monitor the `api_calls` metric to ensure efficient user creation

### dpg_policy_save Module

**Optimizations**:
- Caches policy IDs by name
- Tracks performance metrics for all operations
- Invalidates cache on updates

**Best Practices**:
- Use the `name` parameter consistently to leverage caching
- Monitor the `cache_info` in the response to track cache effectiveness

## Troubleshooting

### High API Call Counts

If you observe high API call counts:

1. Check the `cache_info` in the response for cache hit rates
2. Increase the cache TTL if cache hits are low
3. Use batch operations where available
4. Review the module logs for redundant operations

### Slow Performance

If performance is slower than expected:

1. Check network latency to the CipherTrust Manager
2. Verify cache configuration (TTL, max size)
3. Monitor execution time metrics
4. Consider increasing batch sizes (within reasonable limits)

## Examples

### Example 1: Batch User Creation

```yaml
- name: Create multiple users in batch
  thalesgroup.ciphertrust.usermgmt_users_save:
    node: "cm-node"
    users:
      - name: user1
        email: user1@example.com
      - name: user2
        email: user2@example.com
      - name: user3
        email: user3@example.com
    operation_type: create
```

### Example 2: Batch Group Membership

```yaml
- name: Add multiple users to group
  thalesgroup.ciphertrust.group_save:
    node: "cm-node"
    name: "my-group"
    users:
      - user1
      - user2
      - user3
    operation_type: patch
```

### Example 3: Monitoring Performance

```yaml
- name: Create DPG policy
  thalesgroup.ciphertrust.dpg_policy_save:
    node: "cm-node"
    name: "my-policy"
    operation_type: create
  register: policy_result

- name: Display performance metrics
  debug:
    msg: |
      API Calls: {{ policy_result.api_calls }}
      Cache Hits: {{ policy_result.cache_info.hits }}
      Cache Misses: {{ policy_result.cache_info.misses }}
      Execution Time: {{ policy_result.execution_time }}s
```

## Performance Tuning

### Cache Configuration

To tune cache performance, adjust the following settings in your Ansible configuration:

```yaml
# ansible.cfg
[defaults]
# Cache settings
cache_timeout = 300
cache_plugin = jsonfile
cache_connection = /tmp/ansible_cache
```

### Batch Size Optimization

The optimal batch size depends on:

- Network latency
- API response time
- Resource complexity

Start with a batch size of 10 and adjust based on performance metrics.

## Conclusion

By following these best practices, you can significantly improve the performance of your Ansible playbooks when using the ThalesGroup CipherTrust Collection. Always monitor performance metrics to identify optimization opportunities.
