# dpg_access_policy_save Module

## Description

Manages DPG (Data Protection Gateway) access policies.

This module manages DPG access policies, including creation, modification, deletion, and policy settings. It works with CipherTrust Manager APIs to configure data access governance.

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
| `policy_id` | string | No | Identifier of the access policy to be patched | - |
| `default_error_replacement_value` | string | No | Value to be revealed if the type is 'Error Replacement Value' | - |
| `default_masking_format_id` | string | No | Masking format used to reveal if the type is 'Masked Value' | - |
| `default_reveal_type` | string | No | Value using which data should be revealed | - |
| `description` | string | No | Description of the Access Policy | - |
| `name` | string | No | Access Policy Name | - |
| `user_set_policy` | list | No | List of policies to be added to the access policy | - |
| `error_replacement_value` | string | No | Value to be revealed if the type is 'Error Replacement Value' | - |
| `masking_format_id` | string | No | Masking format used to reveal if the type is 'Masked Value' | - |
| `reveal_type` | string | No | Value using which data should be revealed | - |
| `user_set_id` | string | No | User set to which the policy is applied | - |
| `policy_user_set_id` | string | No | Update or delete the user set in an Access Policy | - |

### op_type Choices

- `create` - Create a new access policy
- `patch` - Patch an existing access policy
- `add-user-set` - Add user set to the access policy
- `update-user-set` - Update user set in the access policy
- `delete-user-set` - Delete user set from the access policy

### default_reveal_type Choices

- `Error Replacement Value`
- `Masked Value`
- `Ciphertext`
- `Plaintext`

### user_set_policy Suboptions

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `error_replacement_value` | string | No | Value to be revealed if the type is 'Error Replacement Value' |
| `masking_format_id` | string | No | Masking format used to reveal if the type is 'Masked Value' |
| `reveal_type` | string | No | Value using which data should be revealed |
| `user_set_id` | string | No | User set to which the policy is applied |

## Examples

### Create Access Policy

```yaml
- name: Create DPG access policy
  thalesgroup.ciphertrust.dpg_access_policy_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    name: "restricted-access"
    description: "Restricted access policy for sensitive data"
    default_reveal_type: "Ciphertext"
    user_set_policy:
      - reveal_type: "Plaintext"
        user_set_id: "user-set-123"
      - reveal_type: "Ciphertext"
        user_set_id: "user-set-456"
  register: result

- name: Display policy info
  debug:
    var: result
```

### Patch Access Policy

```yaml
- name: Patch DPG access policy
  thalesgroup.ciphertrust.dpg_access_policy_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "patch"
    policy_id: "policy-456"
    name: "updated-access-policy"
    description: "Updated access policy"
  register: result

- name: Display patch result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the access policy | `"policy-456"` |
| `name` | string | Name of the access policy | `"restricted-access"` |
| `description` | string | Description | `"Restricted access policy for sensitive data"` |
| `default_reveal_type` | string | Default reveal type | `"Ciphertext"` |
| `user_set_policy` | list | List of user set policies | `[{"reveal_type": "Plaintext", "user_set_id": "user-set-123"}]` |

## Notes

- Access policies control who can access protected data
- User set policies define reveal types for different user sets
- Policies can be modified using different op_type operations

## See Also

- [DPG Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
