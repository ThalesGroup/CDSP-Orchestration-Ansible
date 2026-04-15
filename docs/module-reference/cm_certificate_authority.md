# cm_certificate_authority Module

## Description

Manages Certificate Authorities in CipherTrust Manager.

This module manages Certificate Authorities, including creation, configuration, certificate issuance, and CA status.

## Options

| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| `cm_ip` | string | Yes | CipherTrust Manager IP address | - |
| `cm_username` | string | Yes | CipherTrust Manager username | - |
| `cm_password` | string | Yes | CipherTrust Manager password | - |
| `cm_verify` | bool | No | Verify SSL certificate | `true` |
| `cm_ca_bundle` | string | No | Path to CA bundle file | - |
| `cm_session_id` | string | No | Session ID for authentication | - |
| `action` | string | No | Action to perform (create, update, delete, issue_cert, get_status) | - |
| `ca_name` | string | No | Name of the CA | - |
| `ca_id` | string | No | ID of the CA | - |
| `ca_type` | string | No | Type of CA (root, intermediate) | - |
| `subject` | string | No | Subject DN for the CA certificate | - |
| `key_algorithm` | string | No | Key algorithm (RSA, EC) | - |
| `key_size` | int | No | Key size in bits | - |
| `validity_days` | int | No | Certificate validity in days | `365` |
| `csr` | string | No | Certificate Signing Request | - |
| `issuer_ca` | string | No | Issuer CA name or ID | - |

## Examples

### Create Root CA

```yaml
- name: Create root CA
  thalesgroup.ciphertrust.cm_certificate_authority:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "create"
    ca_name: "root-ca"
    ca_type: "root"
    subject: "CN=Root CA,O=Example,C=US"
    key_algorithm: "RSA"
    key_size: 4096
    validity_days: 3650
  register: result

- name: Display CA info
  debug:
    var: result
```

### Issue Certificate

```yaml
- name: Issue certificate
  thalesgroup.ciphertrust.cm_certificate_authority:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "issue_cert"
    ca_id: "ca-123"
    subject: "CN=server.example.com,O=Example,C=US"
    key_algorithm: "RSA"
    key_size: 2048
    validity_days: 365
  register: result

- name: Display certificate info
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `ca_id` | string | ID of the CA | `"ca-123"` |
| `ca_name` | string | Name of the CA | `"root-ca"` |
| `ca_type` | string | Type of CA | `"root"` |
| `subject` | string | Subject DN | `"CN=Root CA,O=Example,C=US"` |
| `status` | string | CA status | `"active"` |

## Notes

- Root CAs are self-signed and can issue intermediate CAs
- Intermediate CAs are signed by a parent CA
- Certificates can be issued for servers, clients, or other CAs

## See Also

- [Certificate Management](../roles/crdp.md)
- [Example Playbooks](../examples/index.md)
