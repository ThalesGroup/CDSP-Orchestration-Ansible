# vault_keys2_save Module

## Description

Manages keys in CipherTrust Manager vault.

This module manages keys, including creation, import, export, rotation, and deletion.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `action` | string | No | Action to perform (create, import, export, rotate, delete, enable, disable) | - |
| `key_name` | string | No | Name of the key | - |
| `key_id` | string | No | ID of the key | - |
| `key_type` | string | No | Type of key (symmetric, asymmetric) | - |
| `key_algorithm` | string | No | Algorithm for the key (AES, RSA, etc.) | - |
| `key_size` | int | No | Size of the key in bits | - |
| `key_material` | string | No | Key material for import | - |
| `export_format` | string | No | Format for export (PEM, DER, etc.) | - |
| `export_password` | string | No | Password for encrypted export | - |

## Examples

### Create Symmetric Key

```yaml
- name: Create symmetric key
  thalesgroup.ciphertrust.vault_keys2_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "create"
    key_name: "aes-encryption-key"
    key_type: "symmetric"
    key_algorithm: "AES"
    key_size: 256
  register: result

- name: Display key info
  debug:
    var: result
```

### Import Key

```yaml
- name: Import key
  thalesgroup.ciphertrust.vault_keys2_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "import"
    key_name: "imported-key"
    key_type: "symmetric"
    key_material: "base64-encoded-key-material"
  register: result

- name: Display import result
  debug:
    var: result
```

### Rotate Key

```yaml
- name: Rotate key
  thalesgroup.ciphertrust.vault_keys2_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "rotate"
    key_id: "key-123"
  register: result

- name: Display rotation result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `key_id` | string | ID of the key | `"key-123"` |
| `key_name` | string | Name of the key | `"aes-encryption-key"` |
| `key_type` | string | Type of key | `"symmetric"` |
| `key_algorithm` | string | Algorithm | `"AES"` |
| `key_size` | int | Key size in bits | `256` |
| `status` | string | Status of the operation | `"success"` |

## Notes

- Key rotation creates a new version while maintaining the key ID
- Exported keys can be encrypted with a password for security
- Asymmetric keys support RSA and EC algorithms

## See Also

- [Key Management](../roles/crdp.md)
- [Example Playbooks](../examples/index.md)
