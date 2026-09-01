# licensing_lockdata_get Module

## Description

Retrieves licensing lock data from CipherTrust Manager.

This module retrieves lock data information used for licensing purposes, including hardware identifiers and lock data details.

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

### Get Lock Data

```yaml
- name: Get lock data
  thalesgroup.ciphertrust.licensing_lockdata_get:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
  register: result

- name: Display lock data
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `response` | dict | The response from the server | - |
| `id` | string | The ID of the lockdata | `"lockdata-123"` |
| `lockdata` | string | The lockdata string | `"ABC123XYZ789"` |
| `hardware_id` | string | Hardware identifier | `"HW-123456"` |
| `node_id` | string | Node identifier | `"node-123"` |
| `status` | string | Status of the lockdata | `"active"` |

## Notes

- Lock data is used for offline licensing scenarios
- Hardware ID is unique to each CipherTrust Manager instance
- Useful for license activation and transfer scenarios

## See Also

- [License Management Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
