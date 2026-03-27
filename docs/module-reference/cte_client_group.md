# cte_client_group Module

## Description

Manages CTE (CipherTrust Transparent Encryption) client groups.

This module manages CTE client groups, including creation, patching, deletion, and client group management operations. It works with CipherTrust Manager APIs to manage client groups so that group level policies can be applied to multiple clients.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `localNode` | dict | Yes | Connection parameters for CipherTrust Manager | - |
| `localNode.server_ip` | string | Yes | CM Server IP or FQDN | - |
| `localNode.server_private_ip` | string | No | Internal or private IP of the CM Server | `10.10.10.10` |
| `localNode.server_port` | int | No | Port on which CM server is listening | `5432` |
| `localNode.user` | string | Yes | Admin username of CM | - |
| `localNode.password` | string | Yes | Admin password of CM | - |
| `localNode.verify` | bool | No | If SSL verification is required | `false` |
| `localNode.auth_domain_path` | string | No | User's domain path | `''` |
| `op_type` | string | Yes | Operation to be performed | - |
| `id` | string | No | Identifier of the Client Group to be acted upon | - |
| `client_id` | string | No | Identifier of the client within the group that needs to be acted upon | - |
| `cluster_type` | string | No | Cluster type of the ClientGroup | - |
| `name` | string | No | Name of the ClientGroup | - |
| `description` | string | No | Description of the ClientGroup | - |
| `communication_enabled` | bool | No | Whether the File System communication is enabled | - |
| `password` | string | No | User supplied password if password_creation_method is MANUAL | - |
| `password_creation_method` | string | No | Password creation method, GENERATE or MANUAL | `GENERATE` |
| `profile_id` | string | No | ID of the client group profile that is used to schedule custom configuration for logger, logging, and Quality of Service (QoS) | - |
| `client_locked` | bool | No | Is FS Agent locked? | `false` |
| `enable_domain_sharing` | bool | No | Whether to enable domain sharing for ClientGroup | - |
| `enabled_capabilities` | string | No | Comma separated agent capabilities which are enabled | - |
| `shared_domain_list` | list | No | List of domains with which ClientGroup needs to be shared | - |
| `system_locked` | bool | No | Whether the system is locked | `false` |
| `client_list` | list | No | List of Client identifier which are to be associated with clientgroup | - |
| `inherit_attributes` | bool | No | Whether the client should inherit attributes from the ClientGroup | - |
| `guard_paths` | list | No | List of GuardPaths to be created | - |
| `guard_point_params` | dict | No | Parameters for creating a GuardPoint | - |

### op_type Choices

- `create` - Create a new client group
- `patch` - Patch an existing client group
- `add_client` - Add client to group
- `add_guard_point` - Add guard point to group
- `update_guardpoint` - Update guardpoint
- `unguard_guardpoints` - Unguard guardpoints
- `auth-binaries` - Authenticate binaries
- `remove_client` - Remove client from group
- `ldt_pause` - Pause LDT

## Examples

### Create Client Group

```yaml
- name: Create CTE client group
  thalesgroup.ciphertrust.cte_client_group:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    name: "CTE-ClientGroup"
    description: "CTE Client Group for data protection"
    cluster_type: "NON-CLUSTER"
    communication_enabled: true
  register: result

- name: Display client group info
  debug:
    var: result
```

### Patch Client Group

```yaml
- name: Patch CTE client group
  thalesgroup.ciphertrust.cte_client_group:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "patch"
    id: "group-123"
    description: "Updated group description"
    client_locked: true
  register: result

- name: Display patch result
  debug:
    var: result
```

### Add Client to Group

```yaml
- name: Add client to group
  thalesgroup.ciphertrust.cte_client_group:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "add_client"
    id: "group-123"
    client_id: "client-456"
  register: result

- name: Display add result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the client group | `"group-123"` |
| `name` | string | Name of the client group | `"CTE-ClientGroup"` |
| `description` | string | Description | `"CTE Client Group for data protection"` |
| `cluster_type` | string | Cluster type | `"NON-CLUSTER"` |
| `communication_enabled` | bool | Whether communication is enabled | `true` |

## Notes

- Client groups help organize and manage multiple CTE clients
- Policies can be applied at the client group level
- Clients can be members of multiple groups

## See Also

- [CTE Role Documentation](../roles/cte4u.md)
- [Example Playbooks](../examples/index.md)
