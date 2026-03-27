# cm_regtoken Module

## Description

Manages registration tokens in CipherTrust Manager.

This module creates, retrieves, and manages registration tokens used for registering new nodes or clients with CipherTrust Manager.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `action` | string | Yes | Action to perform (create, get, delete) | - |
| `token_id` | string | No | ID of the registration token | - |
| `expiry_days` | int | No | Number of days until token expires | `7` |
| `max_uses` | int | No | Maximum number of uses | `1` |

## Examples

### Create Registration Token

```yaml
- name: Create registration token
  thalesgroup.ciphertrust.cm_regtoken:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "create"
    expiry_days: 7
    max_uses: 1
  register: result

- name: Display registration token
  debug:
    var: result
```

### Get Registration Token

```yaml
- name: Get registration token
  thalesgroup.ciphertrust.cm_regtoken:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "get"
    token_id: "token-123"
  register: result

- name: Display registration token
  debug:
    var: result
```

### Delete Registration Token

```yaml
- name: Delete registration token
  thalesgroup.ciphertrust.cm_regtoken:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "delete"
    token_id: "token-123"
  register: result

- name: Display deletion result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `token_id` | string | ID of the registration token | `"token-123"` |
| `token_value` | string | Token value for registration | `"ABC123XYZ789"` |
| `expiry_days` | int | Number of days until expiration | `7` |
| `max_uses` | int | Maximum number of uses | `1` |
| `current_uses` | int | Current number of uses | `0` |
| `is_active` | bool | Whether token is active | `true` |

## Notes

- Registration tokens are used for node registration
- Tokens can have expiry dates and use limits
- Securely store token values - they provide registration access

## See Also

- [Cluster Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
