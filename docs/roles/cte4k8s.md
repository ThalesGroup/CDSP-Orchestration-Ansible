# cte4k8s Role

Role for setting up CTE integration with Kubernetes.

## Role Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `cte_server` | Yes | None | CTE server IP address |
| `cte_username` | Yes | None | Username for CTE authentication |
| `cte_password` | Yes | None | Password for CTE authentication |
| `cte_client_group_name` | Yes | None | Name of the CTE client group |
| `cte_policy_name` | Yes | None | Name of the CTE policy |
| `storage_class_name` | Yes | None | Name of the Kubernetes storage class |
| `namespace` | No | default | Kubernetes namespace for deployment |

## Example Playbook

```yaml
- name: Deploy CTE for Kubernetes
  hosts: localhost
  gather_facts: no
  vars:
    cte_server: "10.0.0.1"
    cte_username: "admin"
    cte_password: "password"
    cte_client_group_name: "K8s-Client-Group"
    cte_policy_name: "K8s-Policy"
    storage_class_name: "cte-storage"
    namespace: "cte"
  roles:
    - cte4k8s
```

## Dependencies

None

## License

Apache-2.0

## Author Information

Thales Group
