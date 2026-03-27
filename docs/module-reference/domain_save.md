# domain_save Module

## Description

Manages domains in CipherTrust Manager.

This module manages domains, including creation, modification, deletion, and domain settings.

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
| `domain_name` | string | No | Name of the domain | - |
| `domain_id` | string | No | ID of the domain | - |
| `description` | string | No | Description of the domain | - |
| `parent_domain` | string | No | Parent domain name or ID | - |
| `parent_domain_id` | string | No | Parent domain ID | - |
| `domain_type` | string | No | Type of domain (local, remote, cloud) | - |

## Examples

### Create Domain

```yaml
- name: Create domain
  thalesgroup.ciphertrust.domain_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "create"
    domain_name: "production"
    description: "Production domain"
    domain_type: "local"
  register: result

- name: Display domain info
  debug:
    var: result
```

### Enable Domain

```yaml
- name: Enable domain
  thalesgroup.ciphertrust.domain_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "enable"
    domain_id: "domain-123"
  register: result

- name: Display enable result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `domain_id` | string | ID of the domain | `"domain-123"` |
| `domain_name` | string | Name of the domain | `"production"` |
| `description` | string | Description | `"Production domain"` |
| `domain_type` | string | Domain type | `"local"` |
| `parent_domain_id` | string | Parent domain ID | `"root-domain"` |
| `is_enabled` | bool | Whether domain is enabled | `true` |

## Notes

- Domains help organize resources in CipherTrust Manager
- Hierarchical domain structure supports complex environments
- Domains can be enabled or disabled for access control

## See Also

- [CTE Role Documentation](../roles/cte4u.md)
- [Example Playbooks](../examples/index.md)
