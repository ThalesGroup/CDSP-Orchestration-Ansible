# Troubleshooting

This guide covers common issues and their solutions when using the ThalesGroup CipherTrust Ansible Collection.

## Connection Issues

### Cannot Connect to CipherTrust Manager

**Symptoms:**
- Connection timeout errors
- "Connection refused" messages

**Solutions:**
1. Verify CipherTrust Manager is running
2. Check network connectivity:
   ```bash
   ping 10.0.0.1
   telnet 10.0.0.1 8443
   ```
3. Verify firewall rules allow traffic on port 8443
4. Check CipherTrust Manager SSL certificate

### SSL Certificate Errors

**Symptoms:**
- "SSL: CERTIFICATE_VERIFY_FAILED" errors
- "certificate verify failed" messages

**Solutions:**
1. For development, disable SSL verification:
   ```yaml
   vars:
     cm_verify: false
   ```
2. For production, use a valid SSL certificate:
   ```yaml
   vars:
     cm_verify: true
     cm_ca_bundle: "/path/to/ca-bundle.crt"
   ```

## Authentication Issues

### Authentication Failed

**Symptoms:**
- "Authentication failed" errors
- "Invalid credentials" messages

**Solutions:**
1. Verify username and password
2. Check user permissions
3. Ensure user has admin privileges
4. Try logging in via web UI to verify credentials

### Token Expiration

**Symptoms:**
- "Token expired" errors
- "Invalid token" messages

**Solutions:**
1. Refresh the token
2. Re-authenticate with username/password
3. Check token expiration time

## Module-Specific Issues

### Module Not Found

**Symptoms:**
- "Cannot find module" errors

**Solutions:**
1. Verify collection is installed:
   ```bash
   ansible-galaxy collection list thalesgroup.ciphertrust
   ```
2. Reinstall the collection:
   ```bash
   ansible-galaxy collection install thalesgroup.ciphertrust --force
   ```

### Module Parameter Errors

**Symptoms:**
- "Invalid parameter" errors
- "Missing required parameter" messages

**Solutions:**
1. Check module documentation for required parameters
2. Verify parameter names and values
3. Use `-vvv` flag for detailed error messages

## Role-Specific Issues

### Role Variables Not Set

**Symptoms:**
- "Variable not defined" errors

**Solutions:**
1. Check role documentation for required variables
2. Set all required variables in your playbook
3. Use role defaults if available

### Role Dependencies Not Met

**Symptoms:**
- "Dependency not met" errors

**Solutions:**
1. Check role documentation for dependencies
2. Install required collections
3. Set required variables

## Debugging

### Enable Debug Output

```bash
ansible-playbook playbook.yml -vvv
```

### Check Module Logs

```bash
ansible-playbook playbook.yml --log-path=/tmp/ansible.log
```

### Verify Connection

```yaml
- name: Verify connection
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
  tasks:
    - name: Test connection
      thalesgroup.ciphertrust.cm_cluster:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
      register: result

    - name: Display result
      debug:
        var: result
```

## Common Error Messages

### "Connection timeout"

**Cause:** Network issue or CipherTrust Manager not responding

**Solution:** Check network connectivity and CipherTrust Manager status

### "Authentication failed"

**Cause:** Invalid credentials or user permissions

**Solution:** Verify credentials and user permissions

### "Resource not found"

**Cause:** Resource doesn't exist or name is incorrect

**Solution:** Verify resource name and existence

### "Permission denied"

**Cause:** Insufficient user permissions

**Solution:** Use admin credentials or grant required permissions

## Getting Help

- [GitHub Issues](https://github.com/thalesgroup/ciphertrust-ansible-collection/issues)
- [Documentation](https://thalesgroup.github.io/ciphertrust-ansible-collection/)
- [Support Portal](https://support.thalesgroup.com/)
