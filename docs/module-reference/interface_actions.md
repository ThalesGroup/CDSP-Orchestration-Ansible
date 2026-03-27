# interface_actions Module

## Description

Manages interface actions such as enabling, disabling, and restarting network interfaces.

This module manages interface actions, including enabling, disabling, and restarting network interfaces.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `action` | string | Yes | Action to perform (enable, disable, restart) | - |
| `interface_id` | string | Yes | ID of the interface | - |
| `interface_name` | string | No | Name of the interface | - |

## Examples

### Enable Interface

```yaml
- name: Enable network interface
  thalesgroup.ciphertrust.interface_actions:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "enable"
    interface_id: "interface-123"
  register: result

- name: Display result
  debug:
    var: result
```

### Disable Interface

```yaml
- name: Disable network interface
  thalesgroup.ciphertrust.interface_actions:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "disable"
    interface_id: "interface-123"
  register: result

- name: Display result
  debug:
    var: result
```

### Restart Interface

```yaml
- name: Restart network interface
  thalesgroup.ciphertrust.interface_actions:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "restart"
    interface_id: "interface-123"
  register: result

- name: Display result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `success` | bool | Whether the operation succeeded | `true` |
| `message` | string | Status message | `"Interface enabled successfully"` |
| `interface_id` | string | Interface ID | `"interface-123"` |
| `interface_name` | string | Interface name | `"eth0"` |

## Notes

- Useful for network configuration management
- Can enable/disable interfaces for maintenance
- Useful for network troubleshooting scenarios

## See Also

- [Interface Management Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
