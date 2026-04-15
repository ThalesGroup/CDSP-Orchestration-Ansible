# license_create Module

## Description

Manages licenses in CipherTrust Manager.

This module manages licenses, including creation, activation, renewal, and license information retrieval.

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
| `license` | string | Yes | License content to be added | - |
| `bind_type` | string | No | Type of binding for the license | - |

## Examples

### Create License

```yaml
- name: Create license
  thalesgroup.ciphertrust.license_create:
    localNode:
      server_ip: "10.0.0.1"
      server_private_ip: "10.0.0.2"
      server_port: 5432
      user: "admin"
      password: "password"
      verify: false
    license: |
      LICENSE_KEY=XXXX-XXXX-XXXX-XXXX
      FEATURE=dpg
      EXPIRY=2024-12-31
    bind_type: hardware
  register: result

- name: Display license info
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `response` | dict | The response from the server | - |
| `id` | string | The ID of the license | `"license-123"` |
| `feature` | string | Licensed feature | `"dpg"` |
| `expiry_date` | string | Expiry date | `"2024-12-31"` |
| `status` | string | License status | `"active"` |
| `trial` | bool | Whether it's a trial license | `true` |

## Notes

- Trial licenses are temporary and expire after the specified days
- Production licenses require a valid license key from Thales
- License information includes features, expiry, and status

## See Also

- [License Management](../roles/crdp.md)
- [Example Playbooks](../examples/index.md)
