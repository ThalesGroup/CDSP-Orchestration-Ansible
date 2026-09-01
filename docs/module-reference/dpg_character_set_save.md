# dpg_character_set_save Module

## Description

Manages DPG (Data Protection Gateway) character sets.

This module manages DPG character sets, including creation, modification, and character set settings. It works with CipherTrust Manager APIs to create and manage character sets for data masking.

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
| `char_set_id` | string | No | Identifier of the Character Set to be patched | - |
| `name` | string | No | Unique name for the Character Set | - |
| `encoding` | string | No | The description of Character Set | - |
| `range` | list | No | Allowed range of characters in HEX format | - |

### op_type Choices

- `create` - Create a new character set
- `patch` - Patch an existing character set

## Examples

### Create Character Set

```yaml
- name: Create DPG character set
  thalesgroup.ciphertrust.dpg_character_set_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    name: "DPGAlphaNum"
    range:
      - "0030-0039"
      - "0041-005A"
    encoding: "UTF-8"
  register: result

- name: Display character set info
  debug:
    var: result
```

### Patch Character Set

```yaml
- name: Patch DPG character set
  thalesgroup.ciphertrust.dpg_character_set_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "patch"
    char_set_id: "charset-123"
    range:
      - "0030-0039"
      - "0041-005A"
      - "0061-007A"
  register: result

- name: Display patch result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the character set | `"charset-123"` |
| `name` | string | Name of the character set | `"DPGAlphaNum"` |
| `encoding` | string | Encoding type | `"UTF-8"` |
| `range` | list | List of character ranges | `["0030-0039", "0041-005A"]` |

## Notes

- Character sets define the character pool for data masking
- Character ranges are specified in HEX format
- Useful for creating realistic test data

## See Also

- [DPG Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
