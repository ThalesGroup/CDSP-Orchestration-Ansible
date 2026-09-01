# dpg_client_profile_save Module

## Description

Manages DPG (Data Protection Gateway) client profiles.

This module manages DPG client profiles, including creation, modification, and client profile settings. It works with CipherTrust Manager APIs to create and manage client profiles for data masking.

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
| `profile_id` | string | No | Identifier of the client profile to be patched | - |
| `name` | string | No | Unique name for the client profile | - |
| `app_connector_type` | string | No | App connector type for which the client profile is created | - |
| `ca_id` | string | No | Local CA mapped with client profile | - |
| `cert_duration` | int | No | Duration for which client credentials are valid | - |
| `configurations` | dict | No | Parameters required to initialize connector | - |

### op_type Choices

- `create` - Create a new client profile
- `patch` - Patch an existing client profile

### app_connector_type Choices

- `DPG` - Data Protection Gateway
- `CADP For Java` - CADP For Java
- `CRDP` - CRDP

## Examples

### Create Client Profile

```yaml
- name: Create DPG client profile
  thalesgroup.ciphertrust.dpg_client_profile_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    name: "DPGClientProfile"
    app_connector_type: "DPG"
    cert_duration: 365
    configurations:
      symmetric_key_cache_enabled: true
      symmetric_key_cache_expiry: 43200
      size_of_connection_pool: 10
  register: result

- name: Display profile info
  debug:
    var: result
```

### Patch Client Profile

```yaml
- name: Patch DPG client profile
  thalesgroup.ciphertrust.dpg_client_profile_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "patch"
    profile_id: "profile-123"
    cert_duration: 730
  register: result

- name: Display patch result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the client profile | `"profile-123"` |
| `name` | string | Name of the client profile | `"DPGClientProfile"` |
| `app_connector_type` | string | App connector type | `"DPG"` |
| `cert_duration` | int | Certificate duration | `365` |
| `configurations` | dict | Configuration parameters | `{"symmetric_key_cache_enabled": true}` |

## Notes

- Client profiles define connection settings for protected resources
- Profiles can be created for different app connector types (DPG, CADP For Java, CRDP)
- Useful for database and application protection scenarios

## See Also

- [DPG Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
