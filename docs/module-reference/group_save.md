# group_save Module

## Description

Creates or updates groups on CipherTrust Manager.

This module manages groups, including creation and modification with metadata.

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
| `op_type` | string | Yes | Operation to be performed (create, patch) | - |
| `old_name` | string | No | Group's original name that needs to be patched (required for patch) | `null` |
| `name` | string | Yes | Name of the group | `null` |
| `app_metadata` | dict | No | Schema-less object for application-specific information | `null` |
| `client_metadata` | dict | No | Schema-less object for client-specific information | `null` |
| `user_metadata` | dict | No | Schema-less object for user-specific information | `null` |

## Examples

### Create Group

```yaml
- name: Create group
  thalesgroup.ciphertrust.group_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
    op_type: "create"
    name: "security-admins"
    app_metadata:
      description: "Security administrators group"
  register: result

- name: Display group info
  debug:
    var: result
```

### Update Group

```yaml
- name: Update group
  thalesgroup.ciphertrust.group_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
    op_type: "patch"
    old_name: "security-admins"
    name: "security-admins-updated"
    app_metadata:
      description: "Updated security administrators group"
  register: result

- name: Display result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `response` | dict | The response from the server | - |
| `id` | string | ID of the group | `"group-123"` |
| `name` | string | Name of the group | `"security-admins"` |
| `app_metadata` | dict | Application metadata | `{"description": "Security administrators group"}` |

## Notes

- Group names must be unique within the domain
- Use `op_type: create` to create new groups
- Use `op_type: patch` to update existing groups (requires `old_name`)
- Metadata fields are schema-less and can contain any valid JSON

## See Also

- [Example Playbooks](../examples/index.md)
- Member types can be "user" or "group" for nested groups

## See Also

- [User and Group Management](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
