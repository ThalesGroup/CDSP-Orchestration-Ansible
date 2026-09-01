# group_add_remove_object Module

## Description

Adds or removes users or clients from groups in CipherTrust Manager.

This module manages group membership by adding or removing objects (users or clients) from groups.

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
| `op_type` | string | Yes | Operation to be performed (add, remove) | - |
| `object_type` | string | Yes | Type of object to be added to or removed from a group (user, client) | - |
| `name` | string | Yes | Name of the group to be updated | - |
| `object_id` | string | Yes | CM ID of the object (user or client) to be added to the group | - |

## Examples

### Add User to Group

```yaml
- name: Add user to group
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "add"
    object_type: "user"
    object_id: "user-123"
    name: "group-1"
  register: result

- name: Display result
  debug:
    var: result
```

### Add Client to Group

```yaml
- name: Add client to group
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "add"
    object_type: "client"
    object_id: "client-456"
    name: "group-1"
  register: result

- name: Display result
  debug:
    var: result
```

### Remove User from Group

```yaml
- name: Remove user from group
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "remove"
    object_type: "user"
    object_id: "user-123"
    name: "group-1"
  register: result

- name: Display result
  debug:
    var: result
```

### Remove Client from Group

```yaml
- name: Remove client from group
  thalesgroup.ciphertrust.group_add_remove_object:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "remove"
    object_type: "client"
    object_id: "client-456"
    name: "group-1"
  register: result

- name: Display result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the group | `"group-123"` |
| `name` | string | Name of the group | `"group-1"` |
| `status` | string | Status of the operation | `"success"` |

## See Also

- [Group Management Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
