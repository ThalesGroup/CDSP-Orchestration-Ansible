# dpg_protection_policy_save Module

## Description

Manages DPG (Data Protection Gateway) protection policies.

This module manages DPG protection policies, including creation, modification, and protection policy settings. It works with CipherTrust Manager APIs to create and manage protection policies for data masking.

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
| `op_type` | string | Yes | Operation to be performed | - |
| `policy_name` | string | No | Identifier of the protection policy to be patched | - |
| `access_policy_name` | string | No | Name of access policy to be associated with the protection policy | - |
| `masking_format_id` | string | No | ID of the Static Masking Format | - |
| `algorithm` | string | No | Algorithm to be used during crypto operations | - |
| `key` | string | No | Name of the key | - |
| `name` | string | No | Unique name for the protection policy | - |
| `allow_single_char_input` | bool | No | If true, null or single-character inputs are passed untransformed | - |
| `character_set_id` | string | No | ID of the Character Set | - |
| `iv` | string | No | IV to be used during crypto operations | - |
| `key_version` | int | No | Version of the key | - |
| `salt` | bool | No | Whether to use salt | - |
| `salt_character_set_id` | string | No | ID of the Character Set for salt | - |
| `salt_length` | int | No | Length of the salt | - |
| `transform_if_null` | string | No | Transform if null | - |
| `work_factor` | int | No | Work factor for crypto operations | - |

### op_type Choices

- `create` - Create a new protection policy
- `patch` - Patch an existing protection policy

## Examples

### Create Protection Policy

```yaml
- name: Create DPG protection policy
  thalesgroup.ciphertrust.dpg_protection_policy_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    name: "DPGProtectionPolicy"
    algorithm: "AES-256"
    key: "my-key"
    access_policy_name: "DPGAccessPolicy"
    masking_format_id: "format-123"
    character_set_id: "charset-123"
    work_factor: 16
  register: result

- name: Display policy info
  debug:
    var: result
```

### Patch Protection Policy

```yaml
- name: Patch DPG protection policy
  thalesgroup.ciphertrust.dpg_protection_policy_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "patch"
    policy_name: "policy-123"
    work_factor: 32
  register: result

- name: Display patch result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the protection policy | `"policy-123"` |
| `name` | string | Name of the protection policy | `"DPGProtectionPolicy"` |
| `algorithm` | string | Algorithm used | `"AES-256"` |
| `key` | string | Key name | `"my-key"` |
| `access_policy_name` | string | Access policy name | `"DPGAccessPolicy"` |
| `masking_format_id` | string | Masking format ID | `"format-123"` |

## Notes

- Protection policies define how data should be protected using crypto operations
- Policies can be associated with access policies and masking formats
- Useful for data masking and encryption scenarios

## See Also

- [DPG Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
