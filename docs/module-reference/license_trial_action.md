# license_trial_action Module

## Description

Manages CipherTrust Manager trial licenses including creation, extension, and trial management.

This module manages trial licenses, including creation, extension, and trial settings.

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
| `action_type` | string | Yes | Action to perform (create, extend) | - |
| `trialId` | string | No | ID of the trial license | - |
| `trial_days` | int | No | Number of days for trial license | `30` |
| `feature` | string | No | Feature to license | - |

## Examples

### Create Trial License

```yaml
- name: Create trial license
  thalesgroup.ciphertrust.license_trial_action:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
    action_type: "create"
    trial_days: 30
    feature: "dpg"
  register: result

- name: Display trial license info
  debug:
    var: result
```

### Extend Trial License

```yaml
- name: Extend trial license
  thalesgroup.ciphertrust.license_trial_action:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
    action_type: "extend"
    trialId: "trial-license-123"
    trial_days: 30
  register: result

- name: Display extend result
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

- Trial licenses are for evaluation purposes
- Can be extended for additional evaluation time
- Useful for testing and evaluation scenarios

## See Also

- [License Management Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
