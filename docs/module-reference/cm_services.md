# cm_services Module

## Description

Manages services in CipherTrust Manager.

This module manages services, including starting, stopping, restarting, and service status.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `action` | string | No | Action to perform (start, stop, restart, status, enable, disable) | - |
| `service_name` | string | No | Name of the service | - |
| `service_id` | string | No | ID of the service | - |
| `all_services` | bool | No | Apply action to all services | `false` |

## Examples

### Restart Services

```yaml
- name: Restart all services
  thalesgroup.ciphertrust.cm_services:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "restart"
    all_services: true
  register: result

- name: Display restart result
  debug:
    var: result
```

### Get Service Status

```yaml
- name: Get service status
  thalesgroup.ciphertrust.cm_services:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "status"
    service_name: "cteservice"
  register: result

- name: Display service status
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `service_id` | string | ID of the service | `"service-123"` |
| `service_name` | string | Name of the service | `"cteservice"` |
| `status` | string | Service status | `"running"` |
| `enabled` | bool | Whether the service is enabled | `true` |

## Notes

- Some services require restart to apply configuration changes
- All services can be managed collectively or individually
- Service status includes running, stopped, and error states

## See Also

- [Cluster Management](../roles/crdp.md)
- [Example Playbooks](../examples/index.md)
