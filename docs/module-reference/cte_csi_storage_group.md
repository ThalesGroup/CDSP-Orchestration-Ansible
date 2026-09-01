# cte_csi_storage_group Module

## Description

Manages CTE CSI (Container Storage Interface) storage groups.

This module manages CTE CSI storage groups, including creation, modification, deletion, and storage group membership.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `localNode` | dict | Yes | Connection parameters for CipherTrust Manager | - |
| `localNode.server_ip` | string | Yes | CM Server IP or FQDN | - |
| `localNode.server_private_ip` | string | No | Not used; accepted for backwards compatibility, deprecated for removal in 2.0.0 | `10.10.10.10` |
| `localNode.server_port` | int | No | Not used; the API port is not configurable, deprecated for removal in 2.0.0 | `5432` |
| `localNode.user` | string | Yes | Admin username of CM | - |
| `localNode.password` | string | Yes | Admin password of CM | - |
| `localNode.verify` | bool | No | If SSL verification is required | `false` |
| `localNode.auth_domain_path` | string | No | User's domain path | `''` |
| `op_type` | string | Yes | Operation to be performed (create, patch, add_client, remove_client, add_guard_point, patch_guard_point, remove_guard_point) | - |
| `id` | string | No | Identifier of the CTE CSI Storage Group to be patched | - |
| `client_id` | string | No | Identifier of the client added to the CSI Group | - |
| `gp_id` | string | No | Identifier of the guard point added to the CSI Group | - |
| `k8s_namespace` | string | No | Name of the K8s namespace | - |
| `k8s_storage_class` | string | No | Name of the K8s StorageClass | - |
| `name` | string | No | Name to uniquely identify the CSI storage group | - |
| `client_profile` | string | No | Optional Client Profile for the storage group | - |
| `description` | string | No | Optional description for the storage group | - |
| `client_list` | list | No | List of identifiers of clients to be associated with the client group | - |
| `policy_list` | list | No | List of CSI policy identifiers to be associated with the storage group | - |
| `guard_enabled` | bool | No | Enable or disable the GuardPolicy | - |

## Examples

### Create CSI Storage Group

```yaml
- name: "Create CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: AnsibleCSI_SG_1
    k8s_namespace: AnsibleK8s_NS_1
    k8s_storage_class: AnsibleK8s_SC_1
    description: "Test CSIStorageGroup"
    client_profile: DefaultClientProfile
  register: csi_sg
```

### Edit CSI Storage Group

```yaml
- name: "Edit CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: patch
    id: "sg_id"
    description: "Test CSIStorageGroup Updated"
    client_profile: DefaultClientProfile
```

### Add Clients to the CSI Storage Group

```yaml
- name: "Add clients to the CSI Storage Group"
  thalesgroup.ciphertrust.cte_csi_storage_group:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_client
    id: "csi_storage_group_id"
    client_list:
      - client1
      - client2
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the CSI storage group | `"group-456"` |
| `name` | string | Name of the CSI storage group | `"AnsibleCSI_SG_1"` |
| `k8s_namespace` | string | Name of the K8s namespace | `"AnsibleK8s_NS_1"` |
| `k8s_storage_class` | string | Name of the K8s StorageClass | `"AnsibleK8s_SC_1"` |
| `description` | string | Description | `"Test CSIStorageGroup"` |
| `client_profile` | string | Client Profile | `"DefaultClientProfile"` |

## Notes

- CSI storage groups are used for Kubernetes container storage encryption
- Storage groups can be associated with CTE client groups and guard points
- The `op_type` parameter specifies the operation to perform

## See Also

- [CTE Role Documentation](../roles/cte4k8s.md)
- [Example Playbooks](../examples/index.md)
