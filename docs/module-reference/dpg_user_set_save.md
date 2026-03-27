# dpg_user_set_save Module

## Description

Manages DPG (Data Protection Gateway) user sets.

This module manages DPG user sets, including creation, modification, deletion, and user set settings.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `action` | string | No | Action to perform (create, update, delete, enable, disable) | - |
| `user_set_name` | string | No | Name of the user set | - |
| `user_set_id` | string | No | ID of the user set | - |
| `description` | string | No | Description of the user set | - |
| `users` | list | No | List of users in the set | - |
| `user_ids` | list | No | List of user IDs | - |

## Examples

### Create User Set

```yaml
- name: Create DPG user set
  thalesgroup.ciphertrust.dpg_user_set_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "create"
    user_set_name: "dba-team"
    description: "Database administrators"
    users:
      - name: "john.doe"
        email: "john.doe@example.com"
      - name: "jane.smith"
        email: "jane.smith@example.com"
  register: result

- name: Display user set info
  debug:
    var: result
```

### Add User to Set

```yaml
- name: Add user to DPG user set
  thalesgroup.ciphertrust.dpg_user_set_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "update"
    user_set_id: "user-set-456"
    users:
      - name: "bob.wilson"
        email: "bob.wilson@example.com"
  register: result

- name: Display update result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `user_set_id` | string | ID of the user set | `"user-set-456"` |
| `user_set_name` | string | Name of the user set | `"dba-team"` |
| `description` | string | Description | `"Database administrators"` |
| `users` | list | List of users | `[{"name": "john.doe", "email": "john.doe@example.com"}]` |
| `user_ids` | list | List of user IDs | `["user-123", "user-456"]` |
| `is_enabled` | bool | Whether user set is enabled | `true` |

## Notes

- User sets group users for access control
- Useful for managing permissions and access to protected resources
- Can be used with protection policies and access policies

## See Also

- [DPG Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
