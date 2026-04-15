# cte_resource_set Module

## Description

Manages CTE (CipherTrust Transparent Encryption) resource sets.

This module manages CTE resource sets, including creation, modification, deletion, and resource set membership.

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
| `op_type` | string | Yes | Operation to be performed (create, patch, add_resource, patch_resource, delete_resource) | - |
| `id` | string | No | Identifier of the CTE ResourceSet to be patched or deleted | - |
| `resourceIndex` | int | No | Identifier of the CTE Resource within ResourceSet to be patched or deleted | - |
| `name` | string | No | Name of the resource set | - |
| `description` | string | No | Description of the resource set | - |
| `classification_tags` | list | No | Classification set to be added to the resource set | - |
| `classification_tags.attributes` | list | No | List of attributes to be added to the tag | - |
| `classification_tags.attributes.data_type` | string | No | Data type of the attribute | - |
| `classification_tags.attributes.name` | string | No | Name of the attribute | - |
| `classification_tags.name` | string | No | Name of the classification tag | - |
| `classification_tags.policy_id` | string | No | ID of the classification policy | - |
| `resources` | list | No | List of resources to be added to the resource set | - |
| `resources.directory` | string | No | Directory path of the resource | - |
| `resources.file` | string | No | File name of the resource | - |
| `resources.signature` | string | No | Signature-set ID or Name which shall be associated with the resource | - |

## Examples

### Create Resource Set

```yaml
- name: "Create CTE ResourceSet"
  thalesgroup.ciphertrust.cte_resource_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: TestResourceSet
    description: "via Ansible"
    resources:
      - signature: TestSignSet
        directory: "/home/testUser"
        file: "*"
      - signature: TestSignSet
        directory: "/home/test"
        file: "test.bin"
  register: resource_set
```

### Add Resource to ResourceSet

```yaml
- name: "Add resource to ResourceSet"
  thalesgroup.ciphertrust.cte_resource_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_resource
    id: "resourceSetID"
    resources:
      - signature: TestSignSet
        directory: "/home/testUser"
        file: "*"
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the resource set | `"set-101"` |
| `name` | string | Name of the resource set | `"TestResourceSet"` |
| `description` | string | Description | `"via Ansible"` |
| `resources` | list | List of resources in the set | `[{"directory": "/home/testUser", "file": "*"}]` |

## Notes

- Resource sets help organize and manage encrypted resources
- Resources can be added, edited, or removed from resource sets
- The `op_type` parameter specifies the operation to perform

## See Also

- [CTE Role Documentation](../roles/cte4u.md)
- [Example Playbooks](../examples/index.md)
