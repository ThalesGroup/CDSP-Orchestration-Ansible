# cte_signature_set Module

## Description

Manages CTE (CipherTrust Transparent Encryption) signature sets.

This module manages CTE signature sets, including creation, modification, deletion, and signature set membership.

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
| `op_type` | string | Yes | Operation to be performed (create, patch, add_signature, get_signature, delete_signature, sign_app, query_sign_app, cancel_sign_app) | - |
| `id` | string | No | Identifier of the CTE SignatureSet to be patched | - |
| `signature_id` | string | No | Identifier of the Signature within the CTE SignatureSet to be patched | - |
| `name` | string | No | Name of the signature set | - |
| `description` | string | No | Description of the signature set | - |
| `source_list` | list | No | Path of the directory or file to be signed. If a directory is specified, all files in the directory and its subdirectories are signed | - |
| `signatures` | list | No | List of signatures to be added to the signature set | - |
| `signatures.file_name` | string | No | File name | - |
| `signatures.hash_value` | string | No | Hash value | - |

## Examples

### Create Signature Set

```yaml
- name: "Create CTE SignatureSet"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: TestSignSet
    description: "via Ansible"
  register: signature_set
```

### Add Signature to SignatureSet

```yaml
- name: "Add signature to SignatureSet"
  thalesgroup.ciphertrust.cte_signature_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_signature
    id: "signatureSetID"
    signatures:
      - file_name: "test.bin"
        hash_value: "abc123"
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the signature set | `"set-202"` |
| `name` | string | Name of the signature set | `"TestSignSet"` |
| `description` | string | Description | `"via Ansible"` |
| `signatures` | list | List of signatures in the set | `[{"file_name": "test.bin", "hash_value": "abc123"}]` |

## Notes

- Signature sets help organize and manage file signatures
- Signatures can be added, edited, or removed from signature sets
- The `op_type` parameter specifies the operation to perform

## See Also

- [CTE Role Documentation](../roles/cte4u.md)
- [Example Playbooks](../examples/index.md)
