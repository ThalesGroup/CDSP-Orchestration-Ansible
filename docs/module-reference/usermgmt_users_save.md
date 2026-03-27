# usermgmt_users_save Module

## Description

Creates and manages users in CipherTrust Manager.

This module manages users, including creation, modification, password management, and user status.

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
| `op_type` | string | Yes | Operation to be performed (create, patch, changepw, patch_self) | - |
| `cm_user_id` | string | No | CM user ID of the user that needs to be patched (required for patch) | - |
| `allowed_auth_methods` | list | No | List of login authentication methods allowed to the user | `["password"]` |
| `app_metadata` | dict | No | Schema-less object for application-specific information | `null` |
| `certificate_subject_dn` | string | No | The Distinguished Name of the user in certificate | - |
| `connection` | string | No | Connection name (e.g., 'local_account') | `local_account` |
| `email` | string | No | Email address of the user | - |
| `enable_cert_auth` | bool | No | Deprecated - use allowed_auth_methods instead | - |
| `is_domain_user` | bool | No | Create user in non-root domain | - |
| `login_flags` | dict | No | Flags for controlling user's login behavior | - |
| `name` | string | No | Full name of the user | - |
| `password` | string | No | Password for the user (required for most operations) | - |
| `password_change_required` | bool | No | Require password change on next login | - |
| `user_id` | string | No | ID of an existing root domain user | - |
| `user_metadata` | dict | No | Schema-less object for user-specific information | - |

## Examples

### Create User

```yaml
- name: Create user
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.0.0.2"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
    op_type: "create"
    name: "John Doe"
    email: "john.doe@example.com"
    password: "secure-password"
    connection: "local_account"
    allowed_auth_methods: ["password"]
  register: result

- name: Display user info
  debug:
    var: result
```

### Update User

```yaml
- name: Update user
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.0.0.2"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
    op_type: "patch"
    cm_user_id: "user-123"
    name: "John Doe Updated"
    email: "john.updated@example.com"
  register: result

- name: Display update result
  debug:
    var: result
```

### Change Password

```yaml
- name: Change password
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.0.0.2"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
    op_type: "changepw"
    cm_user_id: "user-123"
    password: "new-secure-password"
  register: result

- name: Display password change result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `response` | dict | The response from the server | - |
| `id` | string | ID of the user | `"user-123"` |
| `name` | string | Full name of the user | `"John Doe"` |
| `email` | string | Email address | `"john.doe@example.com"` |
| `status` | string | User status | `"active"` |

## Notes

- Use `op_type: create` to create new users
- Use `op_type: patch` to update existing users (requires `cm_user_id`)
- Use `op_type: changepw` to change user passwords
- The `password` field is required for most operations unless certificate authentication is used
- Metadata fields are schema-less and can contain any valid JSON

## See Also

- [Example Playbooks](../examples/index.md)

- Passwords must meet complexity requirements
- Users can be disabled without deletion
- Roles define user permissions and access levels

## See Also

- [User Management](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
