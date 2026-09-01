# cte4u Role

!!! warning "Not yet implemented"
    This role is a placeholder: its `tasks/main.yml` is empty, so including it
    has no effect. The variables and example below describe the *intended*
    interface, not current behaviour. Use the collection's modules directly, or
    the [`crdp`](crdp.md) role, which is implemented.

Role for setting up CTE for Unix/Linux systems.

## Role Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `cte_server` | Yes | None | CTE server IP address |
| `cte_username` | Yes | None | Username for CTE authentication |
| `cte_password` | Yes | None | Password for CTE authentication |
| `cte_client_name` | Yes | None | Name of the CTE client |
| `guard_paths` | Yes | None | Paths to protect (comma-separated) |
| `policy_name` | Yes | None | Name of the CTE policy |
| `client_group_name` | No | None | Name of the CTE client group |
| `mount_point` | No | /cte | Mount point for CTE |

## Example Playbook

```yaml
- name: Deploy CTE for Unix/Linux
  hosts: localhost
  gather_facts: no
  vars:
    cte_server: "10.0.0.1"
    cte_username: "admin"
    cte_password: "password"
    cte_client_name: "Linux-Client"
    guard_paths: "/data,/home,/var/log"
    policy_name: "Linux-Policy"
    client_group_name: "Linux-Client-Group"
    mount_point: "/cte"
  roles:
    - cte4u
```

## Dependencies

None

## License

Apache-2.0

## Author Information

Thales Group
