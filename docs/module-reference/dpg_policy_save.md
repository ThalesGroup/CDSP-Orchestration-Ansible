# dpg_policy_save Module

## Description

Manages DPG (Data Protection Gateway) policies.

This module manages DPG policies, including creation, modification, deletion, and policy enforcement. It works with CipherTrust Manager APIs to configure DPG execution behavior for REST URLs and associated encryption parameters.

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
| `policy_id` | string | No | Identifier of the DPG Policy to be patched | - |
| `name` | string | No | Name of the DPG policy | - |
| `description` | string | No | Description of the DPG policy | - |
| `api_url_id` | string | No | API URL ID to be updated | - |
| `proxy_config` | list | No | List of API urls to be added to the proxy configuration | - |

### op_type Choices

- `create` - Create a new DPG policy
- `patch` - Patch an existing DPG policy
- `add-api-url` - Add API URL to the policy
- `update-api-url` - Update API URL in the policy
- `delete-api-url` - Delete API URL from the policy

### proxy_config Suboptions

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_url` | string | Yes | URL of the application server from which the request will be received |
| `destination_url` | string | Yes | URL of the application server where the request will be served |
| `json_request_post_tokens` | list | No | API tokens to be protected in a POST Request |
| `json_response_post_tokens` | list | No | API tokens to be protected in a POST Response |
| `json_request_get_tokens` | list | No | API tokens to be protected in a GET Request |

## Examples

### Create DPG Policy

```yaml
- name: Create DPG policy
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "create"
    name: "pii-mask-policy"
    description: "Policy for masking PII data"
  register: result

- name: Display policy info
  debug:
    var: result
```

### Add API URL to Policy

```yaml
- name: Add API URL to DPG policy
  thalesgroup.ciphertrust.dpg_policy_save:
    localNode:
      server_ip: "10.0.0.1"
      user: "admin"
      password: "password"
      verify: false
      auth_domain_path: ""
    op_type: "add-api-url"
    policy_id: "policy-123"
    api_url_id: "api-url-456"
    proxy_config:
      - api_url: "https://app.example.com"
        destination_url: "https://backend.example.com"
  register: result

- name: Display result
  debug:
    var: result
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the policy | `"policy-123"` |
| `name` | string | Name of the policy | `"pii-mask-policy"` |
| `description` | string | Description of the policy | `"Policy for masking PII data"` |
| `api_url_id` | string | API URL ID | `"api-url-456"` |
| `proxy_config` | list | List of proxy configuration | `[{"api_url": "https://app.example.com", "destination_url": "https://backend.example.com"}]` |

## Notes

- Policy configuration defines the specific data protection operations
- Policies can be modified using different op_type operations
- Multiple proxy configurations can be applied to different API URLs

## See Also

- [DPG Role Documentation](../roles/dpg.md)
- [Example Playbooks](../examples/index.md)
