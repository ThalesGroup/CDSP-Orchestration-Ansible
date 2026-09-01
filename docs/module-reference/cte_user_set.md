# cte_user_set Module

## Description

Manages CTE (CipherTrust Transparent Encryption) user sets.

This module manages CTE user sets, including creation, modification, deletion, and user set membership.

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
| `op_type` | string | Yes | Operation to be performed (create, patch, add_user, patch_user, delete_user) | - |
| `id` | string | No | Identifier of the CTE CSI Storage Group to be patched | - |
| `userIndex` | int | No | Identifier of the CTE User within UserSet to be patched or deleted | - |
| `name` | string | No | Name of the user set | - |
| `description` | string | No | Description of the user set | - |
| `users` | list | No | List of users to be added to the user set | - |
| `users.gid` | int | No | Group id of the user which shall be added in user-set | - |
| `users.gname` | string | No | Group name of the user which shall be added in user-set | - |
| `users.os_domain` | string | No | OS domain name in case of windows environment | - |
| `users.uid` | int | No | User id of the user which shall be added in user-set | - |
| `users.uname` | string | No | Name of the user which shall be added in user-set | - |

## Examples

### Create User Set

```yaml
- name: "Create CTE UserSet"
  thalesgroup.ciphertrust.cte_user_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: TestUserSet
    description: "via Ansible"
  register: user_set
```

### Add User to UserSet

```yaml
- name: "Add user to UserSet"
  thalesgroup.ciphertrust.cte_user_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_user
    id: "userSetID"
    users:
      - uname: "testUser"
        gid: 1001
        gname: "testGroup"
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the user set | `"set-303"` |
| `name` | string | Name of the user set | `"TestUserSet"` |
| `description` | string | Description | `"via Ansible"` |
| `users` | list | List of users in the set | `[{"uname": "testUser", "gid": 1001, "gname": "testGroup"}]` |

## Notes

- User sets help organize and manage encrypted user resources
- Users can be added, edited, or removed from user sets
- The `op_type` parameter specifies the operation to perform

## See Also

- [CTE Role Documentation](../roles/cte4u.md)
- [Example Playbooks](../examples/index.md)
