# cte_policy_save Module

## Description

Manages CTE (CipherTrust Transparent Encryption) policies.

This module manages CTE policies, including creation, modification, deletion, and policy settings.

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
| `op_type` | string | Yes | Operation to be performed (create, patch, add_data_transfer_rule, add_ldt_rule, add_key_rule, add_security_rule, patch_data_transfer_rule, patch_ldt_rule, patch_key_rule, patch_security_rule, patch_idt_rule, remove_data_transfer_rule, remove_ldt_rule, remove_key_rule, remove_security_rule) | - |
| `policy_id` | string | No | Identifier of the CTE Policy to be patched or rules to be patched or removed | - |
| `name` | string | No | Name of the CTE policy | - |
| `description` | string | No | Description of the CTE policy | - |
| `policy_type` | string | No | Type of the policy (Standard, LDT, IDT, CSI, Cloud_Object_Storage) | - |
| `data_transform_rules` | list | No | Data transformation rules to link with the policy | - |
| `idt_key_rules` | list | No | IDT rules to link with the policy | - |
| `key_rules` | list | No | Key rules to link with the policy | - |
| `security_rules` | list | No | Security rules to link with the policy | - |
| `ldt_rules` | list | No | LDT rules to link with the policy | - |
| `data_transfer_rules` | list | No | Data transfer rules to link with the policy | - |

## Examples

### Create Policy

```yaml
- name: "Create CTE Policy"
  thalesgroup.ciphertrust.cte_policy_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: "MyPolicy"
    description: "My CTE Policy"
    policy_type: "Standard"
  register: policy_result
```

### Patch Policy

```yaml
- name: "Patch CTE Policy"
  thalesgroup.ciphertrust.cte_policy_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: patch
    policy_id: "policy_id"
    description: "Updated description"
  register: policy_result
```

### Add Data Transfer Rule

```yaml
- name: "Add Data Transfer Rule"
  thalesgroup.ciphertrust.cte_policy_save:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_data_transfer_rule
    policy_id: "policy_id"
    data_transfer_rules:
      - key_id: "key_id"
        key_type: "id"
        resource_set_id: "resource_set_id"
  register: policy_result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the policy | `"policy-123"` |
| `name` | string | Name of the policy | `"MyPolicy"` |
| `description` | string | Description | `"My CTE Policy"` |
| `policy_type` | string | Policy type | `"Standard"` |

## Notes

- Policies define encryption behavior for CTE clients and storage
- The `op_type` parameter specifies the operation to perform
- Rules can be added/patched/removed from policies using the appropriate op_type values

## See Also

- [CTE Role Documentation](../roles/cte4u.md)
- [Example Playbooks](../examples/index.md)
