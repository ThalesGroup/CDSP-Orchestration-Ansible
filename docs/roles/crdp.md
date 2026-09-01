# crdp Role

Role for setting up CipherTrust Ransomware Defense Platform (CRDP).

## Role Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `this_node_address` | Yes | None | CipherTrust Manager IP address |
| `this_node_username` | Yes | None | Username for authentication |
| `this_node_password` | Yes | None | Password for authentication |
| `this_node_connection_string` | Yes | None | Connection string with all connection parameters |
| `key_name` | Yes | None | Name of the key to create for CRDP |
| `user_set_name` | Yes | None | Name of the user set for masked data |
| `plaintext_user_set_name` | Yes | None | Name of the user set for plaintext data |
| `access_policy_name` | Yes | None | Name of the access policy |
| `masking_format_name` | Yes | None | Name of the masking format |
| `char_set_name` | Yes | None | Name of the character set |

## Example Playbook

```yaml
- name: Deploy CRDP
  hosts: localhost
  gather_facts: no
  vars:
    this_node_address: "10.0.0.1"
    this_node_username: "admin"
    this_node_password: "password"
    this_node_connection_string: "https://10.0.0.1:8443?conn_timeout=15"
    key_name: "CRDP-Key"
    user_set_name: "CRDP-Masked-Users"
    plaintext_user_set_name: "CRDP-Plaintext-Users"
    access_policy_name: "CRDP-Access-Policy"
    masking_format_name: "CRDP-Masking-Format"
    char_set_name: "CRDP-Char-Set"
  roles:
    - crdp
```

## Dependencies

None

## License

Apache-2.0

## Author Information

Thales Group
