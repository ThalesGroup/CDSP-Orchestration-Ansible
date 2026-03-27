# Quick Start

This guide helps you get started with the ThalesGroup CipherTrust Ansible Collection.

## Prerequisites

- Ansible 2.15.0 or higher
- Python 3.7 or higher
- CipherTrust Manager 2.17.0.12772 or higher
- Admin credentials for CipherTrust Manager

## Installation

Install the collection:

```bash
ansible-galaxy collection install thalesgroup.ciphertrust
```

## Basic Playbook

Create a simple playbook to test the connection:

```yaml
# test-connection.yml
- name: Test CipherTrust Connection
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
        state: present
      register: result

    - name: Display result
      debug:
        var: result
```

Run the playbook:

```bash
ansible-playbook test-connection.yml
```

## Common Tasks

### Create a Key

```yaml
- name: Create a key
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
  tasks:
    - name: Create symmetric key
      thalesgroup.ciphertrust.vault_keys2_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        name: "My-Key"
        type: "symmetric"
        algorithm: "AES"
        length: 256
        state: present
```

### Create a User

```yaml
- name: Create a user
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
  tasks:
    - name: Create user
      thalesgroup.ciphertrust.usermgmt_users_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        username: "jdoe"
        password: "password123"
        email: "jdoe@example.com"
        name: "John Doe"
        state: present
```

### Create a Group

```yaml
- name: Create a group
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
  tasks:
    - name: Create group
      thalesgroup.ciphertrust.group_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        name: "developers"
        description: "Development team"
        state: present
```

## Next Steps

- [Installation](installation.md)
- [Configuration](configuration.md)
- [Examples](../examples/index.md)
