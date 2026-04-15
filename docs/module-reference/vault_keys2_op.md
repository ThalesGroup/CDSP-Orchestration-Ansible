# vault_keys2_op Module

## Description

Performs operations on keys in CipherTrust Manager.

This module performs various key operations including destroy, archive, recover, revoke, reactivate, export, and clone operations on cryptographic keys.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `op_type` | string | Yes | Operation to perform (destroy, archive, recover, revoke, reactivate, export, clone) | - |
| `cm_key_id` | string | Yes | ID of the key to operate on | - |
| `key_version` | int | No | Key version | latest |
| `id_type` | string | No | Type of identifier for the key (name, id, uri, alias) | `id` |
| `includeMaterial` | bool | No | Include key material for clone operation | `false` |
| `reason` | string | No | Reason for revoke/reactivate operation | - |
| `compromiseOccurrenceDate` | string | No | Date when key was first believed compromised | - |
| `messageStr` | string | No | Message explaining revocation/reactivation | - |
| `combineXts` | bool | No | Combine XTS/CBC-CS1 key material for export | `false` |
| `encoding` | string | No | Encoding for material field (hex, base64) | - |
| `keyFormat` | string | No | Format of returned key material (pkcs1, pkcs8, pkcs12, jwe) | - |
| `macSignKeyIdentifier` | string | No | Identifier of key used for MAC/signature | - |
| `macSignKeyIdentifierType` | string | No | Type of MAC/signature key identifier (name, id, alias) | - |
| `padded` | bool | No | Use padding for key wrap | `false` |
| `password` | string | No | Password for PKCS12 format | - |
| `pemWrap` | bool | No | Wrap PEM encoding of private key | `false` |
| `secretDataEncoding` | string | No | Encoding for secretDataLink material | - |
| `secretDataLink` | string | No | ID or name of Secret Data for PKCS12 | - |
| `signingAlgo` | string | No | Algorithm for signature verification (RSA, RSA-PSS) | - |
| `wrapKeyName` | string | No | Key name for wrapping key material | - |
| `newKeyName` | string | No | Name for cloned key | - |
| `meta` | dict | No | Metadata for cloned key | - |

## Examples

### Destroy Key

```yaml
- name: Destroy key
  thalesgroup.ciphertrust.vault_keys2_op:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    op_type: "destroy"
    cm_key_id: "key-123"
  register: result

- name: Display destroy result
  debug:
    var: result
```

### Revoke Key

```yaml
- name: Revoke key
  thalesgroup.ciphertrust.vault_keys2_op:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    op_type: "revoke"
    cm_key_id: "key-123"
    reason: "KeyCompromise"
    messageStr: "Key may be compromised"
  register: result

- name: Display revoke result
  debug:
    var: result
```

### Export Key Material

```yaml
- name: Export key material
  thalesgroup.ciphertrust.vault_keys2_op:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    op_type: "export"
    cm_key_id: "key-123"
    keyFormat: "pkcs8"
    encoding: "base64"
  register: result

- name: Display exported key material
  debug:
    var: result
```

### Clone Key

```yaml
- name: Clone key
  thalesgroup.ciphertrust.vault_keys2_op:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    op_type: "clone"
    cm_key_id: "key-123"
    newKeyName: "cloned-key"
    includeMaterial: true
  register: result

- name: Display cloned key
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `success` | bool | Whether operation was successful | `true` |
| `operation` | string | Operation performed | `"destroy"` |
| `key_id` | string | ID of the key | `"key-123"` |
| `material` | string | Key material (for export/clone) | `"base64encodedmaterial"` |
| `message` | string | Operation message | `"Key destroyed successfully"` |

## Notes

- Operations are irreversible - use with caution
- Some operations require specific key states
- Export operations may require additional parameters for wrapping
- Clone operations can include key material for migration scenarios

## See Also

- [Key Management Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
