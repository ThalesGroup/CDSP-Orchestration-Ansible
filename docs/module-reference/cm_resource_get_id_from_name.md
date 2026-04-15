# cm_resource_get_id_from_name Module

## Description

Retrieves resource IDs from names in CipherTrust Manager.

This module provides a convenient way to look up resource IDs by name, which is useful when you know the name but need the ID for other operations.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `resource_type` | string | Yes | Type of resource to look up | - |
| `resource_name` | string | Yes | Name of the resource to look up | - |

## Examples

### Get User ID by Name

```yaml
- name: Get user ID by name
  thalesgroup.ciphertrust.cm_resource_get_id_from_name:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    resource_type: "user"
    resource_name: "john.doe"
  register: result

- name: Display user ID
  debug:
    var: result
```

### Get Group ID by Name

```yaml
- name: Get group ID by name
  thalesgroup.ciphertrust.cm_resource_get_id_from_name:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    resource_type: "group"
    resource_name: "security-admins"
  register: result

- name: Display group ID
  debug:
    var: result
```

### Get Interface ID by Name

```yaml
- name: Get interface ID by name
  thalesgroup.ciphertrust.cm_resource_get_id_from_name:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    resource_type: "interface"
    resource_name: "eth0"
  register: result

- name: Display interface ID
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `resource_id` | string | ID of the resource | `"user-123"` |
| `resource_name` | string | Name of the resource | `"john.doe"` |
| `resource_type` | string | Type of the resource | `"user"` |

## Notes

- Resource type must match the actual resource type
- Returns error if resource name is not found
- Useful for dynamic resource lookups in playbooks

## See Also

- [User Management Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
