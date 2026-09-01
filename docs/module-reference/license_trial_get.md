# license_trial_get Module

## Description

Retrieves information about CipherTrust Manager trial licenses.

This module retrieves trial license information including status, expiration, and feature details.

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

## Examples

### Get Trial License Info

```yaml
- name: Get trial license info
  thalesgroup.ciphertrust.license_trial_get:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
  register: result

- name: Display trial license info
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `response` | dict | The response from the server | - |
| `id` | string | ID of the trial license | `"trial-license-123"` |
| `trial_days` | int | Number of trial days | `30` |
| `feature` | string | Licensed feature | `"dpg"` |
| `start_date` | string | Start date | `"2024-01-01"` |
| `expiration_date` | string | Expiration date | `"2024-01-31"` |
| `is_active` | bool | Whether trial is active | `true` |

## Notes

- Useful for monitoring trial license status
- Can list all trial licenses or get specific license info
- Useful for license management and compliance scenarios

## See Also

- [License Management Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
