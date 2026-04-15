# dpg Role

Role for setting up Data Protection Gateway (DPG).

## Role Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `dpg_key_name` | Yes | None | Name of the DPG key |
| `dpg_policy_name` | Yes | None | Name of the DPG policy |
| `char_set_name` | Yes | None | Name of the character set |
| `access_policy_name` | Yes | None | Name of the access policy |
| `var_username` | Yes | None | Username for DPG user |
| `var_password` | Yes | None | Password for DPG user |
| `var_email` | Yes | None | Email for DPG user |
| `var_name` | Yes | None | Display name for DPG user |
| `var_user_set_name` | Yes | None | Name of the user set |
| `cm_ip` | Yes | None | CipherTrust Manager IP address |
| `cm_username` | Yes | None | Username for CM authentication |
| `cm_password` | Yes | None | Password for CM authentication |

## Example Playbook

```yaml
- name: Deploy DPG
  hosts: localhost
  gather_facts: no
  vars:
    dpg_key_name: "DPG-Key"
    dpg_policy_name: "DPG-Policy"
    char_set_name: "DPG-Char-Set"
    access_policy_name: "DPG-Access-Policy"
    var_username: "dpgadmin"
    var_password: "password"
    var_email: "dpgadmin@example.com"
    var_name: "DPG Administrator"
    var_user_set_name: "DPG-Users"
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
  roles:
    - dpg
```

## Dependencies

None

## License

Apache-2.0

## Author Information

Thales Group
