# dpg_masking_format_save Module

## Description

Manages DPG (Data Protection Gateway) masking formats.

This module manages DPG masking formats, including creation, modification, and masking format settings. It works with CipherTrust Manager APIs to create and manage masking formats for data masking.

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
| `masking_format_id` | string | No | Identifier of the Masking Format to be patched | - |
| `name` | string | No | Unique name for the masking format | - |
| `ending_characters` | int | No | Number of ending characters to be masked | - |
| `mask_char` | string | No | Character used for masking | - |
| `show` | bool | No | Flag to show/hide the starting/ending characters while revealing the data | - |
| `starting_characters` | int | No | Number of starting characters to be masked | - |

### op_type Choices

- `create` - Create a new masking format
- `patch` - Patch an existing masking format

## Examples

### Create Masking Format

```yaml
- name: Create DPG masking format
  thalesgroup.ciphertrust.dpg_masking_format_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    name: "SSN-Mask"
    starting_characters: 4
    ending_characters: 5
    mask_char: "X"
    show: true
  register: result

- name: Display format info
  debug:
    var: result
```

### Patch Masking Format

```yaml
- name: Patch DPG masking format
  thalesgroup.ciphertrust.dpg_masking_format_save:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.10.10.10"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "patch"
    masking_format_id: "format-123"
    ending_characters: 4
  register: result

- name: Display patch result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the masking format | `"format-123"` |
| `name` | string | Name of the masking format | `"SSN-Mask"` |
| `starting_characters` | int | Number of starting characters | `4` |
| `ending_characters` | int | Number of ending characters | `5` |
| `mask_char` | string | Mask character | `"X"` |
| `show` | bool | Show flag | `true` |

## Notes

- Masking formats define how data should be masked
- Common use cases include SSN, credit card, email, and custom formats
- Useful for data masking and anonymization scenarios

## See Also

- [DPG Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
