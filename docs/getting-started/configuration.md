# Configuration

This guide covers configuring the ThalesGroup CipherTrust Ansible Collection.

## Connection Configuration

### Global Configuration

Configure connection parameters in your Ansible inventory or playbook variables:

```yaml
vars:
  cm_ip: "10.0.0.1"
  cm_username: "admin"
  cm_password: "password"
  cm_port: 8443
  cm_verify: false  # Set to true for production with valid SSL
```

### Connection String

For more complex configurations, use a connection string:

```yaml
vars:
  connection_string: "https://10.0.0.1:8443?conn_timeout=15&verify=false"
```

## Authentication

### Username/Password

```yaml
vars:
  cm_username: "admin"
  cm_password: "password"
```

### API Token

```yaml
vars:
  cm_token: "your-api-token"
```

## SSL/TLS Configuration

### Disable SSL Verification (Development)

```yaml
vars:
  cm_verify: false
```

### Enable SSL Verification (Production)

```yaml
vars:
  cm_verify: true
  cm_ca_bundle: "/path/to/ca-bundle.crt"
```

## Timeout Configuration

```yaml
vars:
  connection_timeout: 30  # seconds
  response_timeout: 60    # seconds
```

## Proxy Configuration

```yaml
vars:
  http_proxy: "http://proxy.example.com:8080"
  https_proxy: "https://proxy.example.com:8080"
```

## Environment Variables

Set environment variables for sensitive data:

```bash
export CM_IP="10.0.0.1"
export CM_USERNAME="admin"
export CM_PASSWORD="password"
export CM_VERIFY="false"
```

## Vault Integration

Store sensitive data in Ansible Vault:

```bash
ansible-vault create vars/secrets.yml
```

```yaml
# vars/secrets.yml
cm_password: "your-password"
cm_token: "your-token"
```

Use in playbook:

```yaml
- hosts: localhost
  vars_files:
    - vars/secrets.yml
  tasks:
    - name: Use vault variables
      # Your tasks here
```

## Best Practices

1. **Use Vault**: Never hardcode passwords in playbooks
2. **Environment Variables**: Use for sensitive data in CI/CD
3. **SSL Verification**: Always enable in production
4. **Connection Strings**: Use for complex configurations
5. **Timeouts**: Adjust based on network conditions

## Troubleshooting

### Connection Issues

```bash
ansible-playbook playbook.yml -vvv
```

### SSL Certificate Issues

```yaml
vars:
  cm_verify: false  # Temporary for testing
```

### Authentication Failures

- Verify credentials
- Check user permissions
- Ensure CM is running

## Next Steps

- [Quick Start](quick-start.md)
- [Examples](../examples/index.md)
