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

Since 1.0.4 there is nothing to do here. A JWT is cached per session, and a
`401` triggers one re-authentication and a single retry, so a session that
expires sooner than the cached lifetime is renewed without failing the task.

If you still see an authentication failure after a long-running play, the
credentials themselves have stopped working — the account was disabled, its
password changed, or the auth domain moved. Check those rather than the token.

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

1. Read the failure message first. Since 1.0.4 the message carries CipherTrust
   Manager's own field-level explanation, not just the error class, so it
   usually names the parameter and what it needs:

   ```
   400: POST data-protection/protection-policies failed:
   NCERRBadRequest: Bad HTTP request: Validation errors:
   iv:  AES/CBC/PKCS5Padding algorithm requires a 16 byte IV
   ```

   Earlier versions reported only `NCERRBadRequest: Bad HTTP request`, which is
   the same string for every rejected payload. If that is all you see, you are
   on an older release.

2. Check the module documentation for required parameters and accepted
   `choices`. Some requirements are conditional on another value — the
   protection-policy algorithm decides whether `iv`, `tag_length` or
   `character_set_id` is mandatory.
3. Use `-vvv` to see the request the module built.

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

### "Permission denied" / `NCERRInsufficientPermissions`

**Cause:** Either the account lacks permission, or — despite the wording — the
feature is not licensed on that CipherTrust Manager. CipherTrust Manager
reports an unlicensed feature as a permissions error.

**Solution:** Read the detail after the error code. A licence problem says so:

```
403: POST transparent-encryption/clients failed:
NCERRInsufficientPermissions: License not installed yet for feature
TransparentEncryption
```

That cannot be fixed with credentials. Install or activate the licence for the
feature — `license_create` and `license_trial_action` manage this. If the
detail names no feature, treat it as a genuine permissions problem and use an
account with the required role.

## Getting Help

- [GitHub Issues](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/issues)
- [Documentation](https://thalesgroup.github.io/CDSP-Orchestration-Ansible/)
- [Support Portal](https://support.thalesgroup.com/)
