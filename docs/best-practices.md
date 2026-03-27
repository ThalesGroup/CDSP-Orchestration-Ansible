# Best Practices

This guide provides best practices for using the ThalesGroup CipherTrust Ansible Collection effectively and securely.

## Security Best Practices

### Credential Management

**Never hardcode credentials in playbooks:**

```yaml
# ❌ Bad: Hardcoded credentials
- name: Bad example
  hosts: localhost
  tasks:
    - name: Create cluster
      thalesgroup.ciphertrust.cm_cluster:
        cm_ip: "10.0.0.1"
        cm_username: "admin"
        cm_password: "password123"
```

**Use environment variables or vault:**

```yaml
# ✅ Good: Using vault
- name: Good example
  hosts: localhost
  vars_files:
    - vault.yml
  tasks:
    - name: Create cluster
      thalesgroup.ciphertrust.cm_cluster:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
```

### SSL Verification

**Always verify SSL certificates in production:**

```yaml
# ✅ Good: SSL verification enabled
- name: Production playbook
  hosts: localhost
  vars:
    cm_verify: true
    cm_ca_bundle: "/path/to/ca-bundle.crt"
```

### Token Management

**Refresh tokens periodically:**

```yaml
- name: Refresh token
  hosts: localhost
  tasks:
    - name: Login
      thalesgroup.ciphertrust.cm_cluster:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
      register: auth_result

    - name: Store token
      set_fact:
        cm_token: "{{ auth_result.token }}"
```

## Playbook Best Practices

### Structure

**Organize playbooks by purpose:**

```yaml
# ✅ Good: Well-structured playbook
- name: Setup DPG Environment
  hosts: localhost
  gather_facts: no
  vars_files:
    - vars/dpg.yml
  tasks:
    - name: Create DPG Policy
      include_tasks: tasks/create-policy.yml

    - name: Create DPG User Set
      include_tasks: tasks/create-user-set.yml

    - name: Create DPG Client Profile
      include_tasks: tasks/create-client-profile.yml
```

### Error Handling

**Use error handling:**

```yaml
- name: Create resource
  thalesgroup.ciphertrust.dpg_policy_save:
    cm_ip: "{{ cm_ip }}"
    cm_username: "{{ cm_username }}"
    cm_password: "{{ cm_password }}"
    name: "my-policy"
    description: "My policy"
  register: result
  ignore_errors: true

- name: Check result
  debug:
    msg: "Policy created successfully"
  when: result is not failed

- name: Handle error
  debug:
    msg: "Failed to create policy: {{ result.msg }}"
  when: result is failed
```

### Idempotency

**Ensure idempotency:**

```yaml
# ✅ Good: Idempotent task
- name: Create user if not exists
  thalesgroup.ciphertrust.usermgmt_users_save:
    cm_ip: "{{ cm_ip }}"
    cm_username: "{{ cm_username }}"
    cm_password: "{{ cm_password }}"
    username: "newuser"
    email: "newuser@example.com"
    password: "{{ user_password }}"
    role: "admin"
  register: result

- name: Display result
  debug:
    msg: "User {{ result.username }} {{ 'created' if result.changed else 'already exists' }}"
```

## Module Best Practices

### Parameter Validation

**Validate parameters before use:**

```yaml
- name: Validate parameters
  assert:
    that:
      - cm_ip is defined
      - cm_username is defined
      - cm_password is defined
      - cm_ip | ipaddr
    fail_msg: "Invalid parameters"
```

### Use Default Values

**Use default values for optional parameters:**

```yaml
- name: Create resource with defaults
  thalesgroup.ciphertrust.dpg_policy_save:
    cm_ip: "{{ cm_ip }}"
    cm_username: "{{ cm_username }}"
    cm_password: "{{ cm_password }}"
    name: "my-policy"
    description: "{{ policy_description | default('My policy') }}"
```

### Check Mode

**Support check mode:**

```yaml
- name: Create resource
  thalesgroup.ciphertrust.dpg_policy_save:
    cm_ip: "{{ cm_ip }}"
    cm_username: "{{ cm_username }}"
    cm_password: "{{ cm_password }}"
    name: "my-policy"
    description: "My policy"
  check_mode: true
```

## Role Best Practices

### Variable Documentation

**Document all variables:**

```yaml
# defaults/main.yml
---
# @var {string} cm_ip CipherTrust Manager IP address
cm_ip: ""

# @var {string} cm_username CipherTrust Manager username
cm_username: ""

# @var {string} cm_password CipherTrust Manager password
cm_password: ""
```

### Role Dependencies

**Declare dependencies:**

```yaml
# meta/main.yml
---
dependencies:
  - role: common
```

### Tags

**Use tags for flexibility:**

```yaml
- name: Create policy
  thalesgroup.ciphertrust.dpg_policy_save:
    cm_ip: "{{ cm_ip }}"
    cm_username: "{{ cm_username }}"
    cm_password: "{{ cm_password }}"
    name: "my-policy"
  tags:
    - dpg
    - policy
    - create
```

## CI/CD Best Practices

### Testing

**Test playbooks:**

```yaml
# tests/test.yml
- name: Test playbook
  hosts: localhost
  gather_facts: no
  tasks:
    - name: Test module
      thalesgroup.ciphertrust.cm_cluster:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
      register: result

    - name: Verify result
      assert:
        that:
          - result is not failed
```

### Linting

**Lint playbooks:**

```bash
ansible-lint playbook.yml
```

### Documentation

**Document playbooks:**

```yaml
# README.md
# Playbook: setup-dpg.yml
# Description: Setup DPG environment
# Usage: ansible-playbook setup-dpg.yml
```

## Monitoring and Logging

### Enable Logging

**Enable Ansible logging:**

```bash
export ANSIBLE_LOG_PATH=/var/log/ansible.log
```

### Monitor Execution

**Monitor playbook execution:**

```yaml
- name: Monitor execution
  debug:
    msg: "Task completed in {{ end_time - start_time }} seconds"
```

## Troubleshooting

### Debug Mode

**Use debug mode:**

```bash
ansible-playbook playbook.yml -vvv
```

### Check Mode

**Test in check mode:**

```bash
ansible-playbook playbook.yml --check
```

### Verbose Output

**Enable verbose output:**

```yaml
- name: Debug task
  debug:
    msg: "Debug information"
  verbosity: 3
```
