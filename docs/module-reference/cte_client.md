# cte_client Module

## Description

Manages CTE (CipherTrust Transparent Encryption) clients.

This module manages CTE clients, including creation, patching, deletion, and client management operations. It works with CipherTrust Manager APIs to manage CTE clients where data needs to be protected.

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
| `id` | string | No | CTE Client ID to be patched or updated | - |
| `name` | string | No | Name to uniquely identify the client | - |
| `client_type` | string | No | Type of CTE Client | `FS` |
| `client_locked` | bool | No | Whether the CTE client is locked | `false` |
| `communication_enabled` | bool | No | Whether communication with the client is enabled | `false` |
| `description` | string | No | Description to identify the client | - |
| `password` | string | No | Password for the client | - |
| `password_creation_method` | string | No | Password creation method for the client | `GENERATE` |
| `profile_identifier` | string | No | Identifier of the Client Profile to be associated with the client | - |
| `registration_allowed` | bool | No | Whether client's registration with the CipherTrust Manager is allowed | `false` |
| `system_locked` | bool | No | Whether the system is locked | `false` |
| `user_space_client` | bool | No | User space client | - |
| `client_mfa_enabled` | bool | No | Whether MFA is enabled on the client | - |

### op_type Choices

- `create` - Create a new CTE client
- `patch` - Patch an existing CTE client
- `add_guard_point` - Add guard point to client
- `unenroll` - Unenroll a CTE client
- `delete` - Delete a CTE client
- `delete_id` - Delete a CTE client by ID
- `auth_binaries` - Authenticate binaries
- `ldt_pause` - Pause LDT
- `patch_guard_point` - Patch guard point
- `gp_unguard` - Unguard a guard point
- `gp_enable_early_access` - Enable early access for guard point

## Examples

### Create CTE Client

```yaml
- name: Create CTE client
  thalesgroup.ciphertrust.cte_client:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    name: "CTE-Client"
    client_type: "FS"
    description: "CTE Client for data protection"
    registration_allowed: true
    communication_enabled: true
  register: result

- name: Display client info
  debug:
    var: result
```

### Patch CTE Client

```yaml
- name: Patch CTE client
  thalesgroup.ciphertrust.cte_client:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "patch"
    id: "client-123"
    description: "Updated client description"
    client_locked: true
  register: result

- name: Display patch result
  debug:
    var: result
```

### Add Guard Point to Client

```yaml
- name: Add guard point to CTE client
  thalesgroup.ciphertrust.cte_client:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "add_guard_point"
    id: "client-123"
    guard_point_id: "gp-456"
  register: result

- name: Display add guard point result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the CTE client | `"client-123"` |
| `name` | string | Name of the CTE client | `"CTE-Client"` |
| `client_type` | string | Type of CTE client | `"FS"` |
| `description` | string | Description | `"CTE Client for data protection"` |
| `registration_allowed` | bool | Whether registration is allowed | `true` |
| `communication_enabled` | bool | Whether communication is enabled | `true` |

## Notes

- CTE clients require proper installation packages for the target OS
- Policies must be created before applying to clients
- Client groups help organize and manage multiple clients

## See Also

- [CTE Role Documentation](../roles/cte4u.md)
- [Example Playbooks](../examples/index.md)
