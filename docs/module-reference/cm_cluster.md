# cm_cluster Module

## Description

Manages CipherTrust Manager cluster configuration.

This module manages cluster configuration for CipherTrust Manager, including cluster creation, node management, and cluster status.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `action` | string | No | Action to perform (create, delete, status, join) | - |
| `cluster_name` | string | No | Name of the cluster | - |
| `cluster_ip` | string | No | IP address of the cluster | - |
| `node_ip` | string | No | IP address of the node | - |
| `node_username` | string | No | Username for the node | - |
| `node_password` | string | No | Password for the node | - |

## Examples

### Create Cluster

```yaml
- name: Create cluster
  thalesgroup.ciphertrust.cm_cluster:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "create"
    cluster_name: "my-cluster"
    cluster_ip: "10.0.0.1"
  register: result

- name: Display cluster info
  debug:
    var: result
```

### Get Cluster Status

```yaml
- name: Get cluster status
  thalesgroup.ciphertrust.cm_cluster:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "status"
  register: result

- name: Display cluster status
  debug:
    var: result
```

### Join Node to Cluster

```yaml
- name: Join node to cluster
  thalesgroup.ciphertrust.cm_cluster:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "join"
    cluster_ip: "10.0.0.1"
    node_ip: "10.0.0.2"
    node_username: "admin"
    node_password: "password"
  register: result

- name: Display join result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `cluster_id` | string | ID of the cluster | `"cluster-123"` |
| `cluster_name` | string | Name of the cluster | `"my-cluster"` |
| `status` | string | Status of the cluster | `"active"` |
| `nodes` | list | List of cluster nodes | `[{"id": "node-1", "ip": "10.0.0.1"}]` |

## Notes

- Ensure CipherTrust Manager is running before performing cluster operations
- Use SSL verification in production environments
- Store credentials securely using Ansible Vault

## See Also

- [Cluster Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
