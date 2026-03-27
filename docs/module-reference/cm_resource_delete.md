# cm_resource_delete Module

## Description

Deletes resources from CipherTrust Manager.

This module provides a generic interface for deleting various CipherTrust Manager resources including users, groups, interfaces, and other objects.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `resource_type` | string | Yes | Type of resource to delete | - |
| `resource_id` | string | Yes | ID of the resource to delete | - |

## Examples

### Delete User

```yaml
- name: Delete user
  thalesgroup.ciphertrust.cm_resource_delete:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    resource_type: "user"
    resource_id: "user-123"
  register: result

- name: Display deletion result
  debug:
    var: result
```

### Delete Group

```yaml
- name: Delete group
  thalesgroup.ciphertrust.cm_resource_delete:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    resource_type: "group"
    resource_id: "group-123"
  register: result

- name: Display deletion result
  debug:
    var: result
```

### Delete Interface

```yaml
- name: Delete interface
  thalesgroup.ciphertrust.cm_resource_delete:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    resource_type: "interface"
    resource_id: "interface-123"
  register: result

- name: Display deletion result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `deleted` | bool | Whether resource was deleted | `true` |
| `resource_id` | string | ID of deleted resource | `"user-123"` |
| `resource_type` | string | Type of deleted resource | `"user"` |
| `message` | string | Deletion message | `"Resource deleted successfully"` |

## Notes

- Use resource_id from get_id_from_name module or API responses
- Confirm resource type matches the actual resource
- Deletion is irreversible - use with caution

## See Also

- [User Management Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
