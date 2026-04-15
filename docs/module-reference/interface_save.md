# interface_save Module

## Description

Creates or updates an interface or service that CipherTrust Manager is hosting.

This module manages interfaces, including creation and patching of web, KMIP, NAE, and SNMP interfaces.

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
| `allow_unregistered` | bool | No | Flag to allow unregistered clients | - |
| `interface_id` | string | No | Identifier of the interface to be patched | - |
| `port` | int | Yes | The new interface will listen on the specified port | - |
| `auto_gen_ca_id` | string | No | Auto-generate a new server certificate using the identifier of a Local CA resource | - |
| `auto_registration` | bool | No | Set auto registration to allow auto registration of KMIP clients | `null` |
| `cert_user_field` | string | No | Specifies how the user name is extracted from the client certificate | - |
| `custom_uid_size` | int | No | This flag is used to define the custom uid size of managed object over the KMIP interface | `null` |
| `custom_uid_v2` | bool | No | Specifies which version of custom uid feature is to be used for KMIP interface | `null` |
| `default_connection` | string | No | The default connection may be "local_account" for local authentication or the LDAP domain for LDAP authentication | - |
| `interface_type` | string | No | This parameter is used to identify the type of interface, what service to run on the interface | `nae` |
| `kmip_enable_hard_delete` | int | No | Enables hard delete of keys on KMIP Destroy operation | `0` |

## Examples

### Create Interface

```yaml
- name: Create interface
  thalesgroup.ciphertrust.interface_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.0.0.1"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    port: 8443
    interface_type: "web"
  register: result

- name: Display interface info
  debug:
    var: result
```

### Patch Interface

```yaml
- name: Patch interface
  thalesgroup.ciphertrust.interface_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.0.0.1"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "patch"
    interface_id: "interface-123"
    port: 9443
  register: result

- name: Display patch result
  debug:
    var: result
```

### Create KMIP Interface

```yaml
- name: Create KMIP interface
  thalesgroup.ciphertrust.interface_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.0.0.1"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    port: 5696
    interface_type: "kmip"
    auto_registration: true
    kmip_enable_hard_delete: 1
  register: result

- name: Display KMIP interface info
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the interface | `"interface-123"` |
| `name` | string | Name of the interface | `"web-interface"` |
| `port` | int | Port number | `8443` |
| `interface_type` | string | Type of interface | `"web"` |
| `status` | string | Status of the operation | `"success"` |

## Notes

- Interface names must be unique on the CipherTrust Manager
- VLAN interfaces require a parent interface and VLAN ID
- Bonding requires multiple interfaces and appropriate mode selection

## See Also

- [Interface Management](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
