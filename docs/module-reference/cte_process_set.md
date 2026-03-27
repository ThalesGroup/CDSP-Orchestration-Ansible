# cte_process_set Module

## Description

Manages CTE (CipherTrust Transparent Encryption) process sets.

This module manages CTE process sets, including creation, modification, deletion, and process set membership.

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
| `op_type` | string | Yes | Operation to be performed (create, patch, add_process, patch_process, delete_process) | - |
| `id` | string | No | Identifier of the CTE ProcessSet to be patched or deleted | - |
| `processIndex` | int | No | Identifier of the CTE Process within ProcessSet to be patched or deleted | - |
| `name` | string | No | Name of the process set | - |
| `description` | string | No | Description of the process set | - |
| `processes` | list | No | List of processes to be added to the process set | - |
| `processes.directory` | string | No | Directory path of the process | - |
| `processes.file` | string | No | File name of the process | - |
| `processes.signature` | string | No | Signature-set ID or Name which shall be associated with the process-set | - |
| `directory` | string | No | Directory path of the process | - |
| `file` | string | No | File name of the process | - |
| `signature` | string | No | Signature-set ID or Name which shall be associated with the process-set | - |

## Examples

### Create Process Set

```yaml
- name: "Create CTE ProcessSet"
  thalesgroup.ciphertrust.cte_process_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: create
    name: TestProcessSet
    description: "via Ansible"
    processes:
      - signature: TestSignSet
        directory: "/home/testUser"
        file: "*"
      - signature: TestSignSet
        directory: "/home/test"
        file: "test.bin"
  register: process_set
```

### Add Process to ProcessSet

```yaml
- name: "Add process to ProcessSet"
  thalesgroup.ciphertrust.cte_process_set:
    localNode:
      server_ip: "IP/FQDN of CipherTrust Manager"
      server_private_ip: "Private IP in case that is different from above"
      server_port: 5432
      user: "CipherTrust Manager Username"
      password: "CipherTrust Manager Password"
      verify: false
      auth_domain_path:
    op_type: add_process
    id: "processSetID"
    processes:
      - signature: TestSignSet
        directory: "/home/testUser"
        file: "*"
```

## Return Values

| Name | Type | Description | Sample |
|------|------|-------------|--------|
| `id` | string | ID of the process set | `"set-789"` |
| `name` | string | Name of the process set | `"TestProcessSet"` |
| `description` | string | Description | `"via Ansible"` |
| `processes` | list | List of processes in the set | `[{"directory": "/home/testUser", "file": "*"}]` |

## Notes

- Process sets help organize and manage encrypted processes
- Processes can be added, edited, or removed from process sets
- The `op_type` parameter specifies the operation to perform

## See Also

- [CTE Role Documentation](../roles/cte4u.md)
- [Example Playbooks](../examples/index.md)
