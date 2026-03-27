# Examples

This section provides example playbooks for common use cases with the ThalesGroup CipherTrust Ansible Collection.

## Cluster Management

### Create Cluster

```yaml
- name: Create CipherTrust Cluster
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    node1_ip: "10.0.0.1"
    node2_ip: "10.0.0.2"
    node3_ip: "10.0.0.3"
    admin_password: "admin123"
  tasks:
    - name: Create cluster
      include_role:
        name: cluster
      vars:
        cluster_nodes:
          - { ip: "{{ node1_ip }}", password: "{{ admin_password }}" }
          - { ip: "{{ node2_ip }}", password: "{{ admin_password }}" }
          - { ip: "{{ node3_ip }}", password: "{{ admin_password }}" }
```

## DPG Setup

### Complete DPG Configuration

```yaml
- name: Complete DPG Setup
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    dpg_key_name: "DPG-Key"
    dpg_policy_name: "DPG-Policy"
    char_set_name: "DPG-Char-Set"
    access_policy_name: "DPG-Access-Policy"
    user_name: "dpgadmin"
    user_password: "password"
    user_email: "dpgadmin@example.com"
    user_full_name: "DPG Administrator"
    user_set_name: "DPG-Users"
  tasks:
    - name: Create DPG key
      include_role:
        name: dpg
      vars:
        dpg_key_name: "{{ dpg_key_name }}"
        dpg_policy_name: "{{ dpg_policy_name }}"
        char_set_name: "{{ char_set_name }}"
        access_policy_name: "{{ access_policy_name }}"
        var_username: "{{ user_name }}"
        var_password: "{{ user_password }}"
        var_email: "{{ user_email }}"
        var_name: "{{ user_full_name }}"
        var_user_set_name: "{{ user_set_name }}"
```

## CTE Setup

### CTE for Kubernetes

```yaml
- name: CTE for Kubernetes
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
  tasks:
    - name: Deploy CTE for Kubernetes
      include_role:
        name: cte4k8s
      vars:
        cte_server: "{{ cte_server }}"
        cte_username: "{{ cte_username }}"
        cte_password: "{{ cte_password }}"
        cte_client_group_name: "{{ cte_client_group_name }}"
        cte_policy_name: "{{ cte_policy_name }}"
        storage_class_name: "{{ storage_class_name }}"
        namespace: "{{ namespace }}"
```

### CTE for Unix/Linux

```yaml
- name: CTE for Unix/Linux
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
  tasks:
    - name: Deploy CTE for Unix/Linux
      include_role:
        name: cte4u
      vars:
        cte_server: "{{ cte_server }}"
        cte_username: "{{ cte_username }}"
        cte_password: "{{ cte_password }}"
        cte_client_name: "{{ cte_client_name }}"
        guard_paths: "{{ guard_paths }}"
        policy_name: "{{ policy_name }}"
        client_group_name: "{{ client_group_name }}"
        mount_point: "{{ mount_point }}"
```

## Key Management

### Create Vault Keys

```yaml
- name: Create Vault Keys
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    key_name: "My-Key"
    key_type: "symmetric"
    key_algorithm: "AES"
    key_length: 256
  tasks:
    - name: Create key
      thalesgroup.ciphertrust.vault_keys2_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        name: "{{ key_name }}"
        type: "{{ key_type }}"
        algorithm: "{{ key_algorithm }}"
        length: "{{ key_length }}"
```

## User and Group Management

### Create User

```yaml
- name: Create User
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    username: "jdoe"
    password: "password123"
    email: "jdoe@example.com"
    name: "John Doe"
  tasks:
    - name: Create user
      thalesgroup.ciphertrust.usermgmt_users_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        username: "{{ username }}"
        password: "{{ password }}"
        email: "{{ email }}"
        name: "{{ name }}"
        state: present
```

### Create Group

```yaml
- name: Create Group
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    group_name: "developers"
    description: "Development team"
  tasks:
    - name: Create group
      thalesgroup.ciphertrust.group_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        name: "{{ group_name }}"
        description: "{{ description }}"
        state: present
```

## Interface Management

### Create Interface

```yaml
- name: Create Interface
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    interface_name: "eth0"
    ip_address: "10.0.0.1"
    netmask: "255.255.255.0"
    gateway: "10.0.0.254"
  tasks:
    - name: Create interface
      thalesgroup.ciphertrust.interface_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        name: "{{ interface_name }}"
        ip_address: "{{ ip_address }}"
        netmask: "{{ netmask }}"
        gateway: "{{ gateway }}"
        state: present
```

## License Management

### Apply License

```yaml
- name: Apply License
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    license_file: "/path/to/license.lic"
  tasks:
    - name: Apply license
      thalesgroup.ciphertrust.license_create:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        license_file: "{{ license_file }}"
```

## Cloud Connectors

### AWS Cloud Connector

```yaml
- name: Configure AWS Cloud Connector
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    aws_access_key: "AKIA..."
    aws_secret_key: "secret"
    aws_region: "us-east-1"
  tasks:
    - name: Configure AWS connector
      thalesgroup.ciphertrust.cckm_aws:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        aws_access_key: "{{ aws_access_key }}"
        aws_secret_key: "{{ aws_secret_key }}"
        aws_region: "{{ aws_region }}"
        state: present
```

### Azure Cloud Connector

```yaml
- name: Configure Azure Cloud Connector
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    azure_tenant_id: "tenant-id"
    azure_client_id: "client-id"
    azure_client_secret: "secret"
    azure_subscription_id: "subscription-id"
  tasks:
    - name: Configure Azure connector
      thalesgroup.ciphertrust.cckm_azure:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        azure_tenant_id: "{{ azure_tenant_id }}"
        azure_client_id: "{{ azure_client_id }}"
        azure_client_secret: "{{ azure_client_secret }}"
        azure_subscription_id: "{{ azure_subscription_id }}"
        state: present
```

### GCP Cloud Connector

```yaml
- name: Configure GCP Cloud Connector
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    gcp_project_id: "project-id"
    gcp_service_account_key: "/path/to/key.json"
  tasks:
    - name: Configure GCP connector
      thalesgroup.ciphertrust.cckm_gcp:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        gcp_project_id: "{{ gcp_project_id }}"
        gcp_service_account_key: "{{ gcp_service_account_key }}"
        state: present
```

## CTE Resource Management

### Create CTE Client

```yaml
- name: Create CTE Client
  hosts: localhost
  gather_facts: no
  vars:
    cte_server: "10.0.0.1"
    cte_username: "admin"
    cte_password: "password"
    client_name: "My-Client"
    client_description: "My CTE client"
  tasks:
    - name: Create CTE client
      thalesgroup.ciphertrust.cte_client:
        cte_server: "{{ cte_server }}"
        cte_username: "{{ cte_username }}"
        cte_password: "{{ cte_password }}"
        name: "{{ client_name }}"
        description: "{{ client_description }}"
        state: present
```

### Create CTE Client Group

```yaml
- name: Create CTE Client Group
  hosts: localhost
  gather_facts: no
  vars:
    cte_server: "10.0.0.1"
    cte_username: "admin"
    cte_password: "password"
    client_group_name: "My-Client-Group"
    client_group_description: "My CTE client group"
  tasks:
    - name: Create CTE client group
      thalesgroup.ciphertrust.cte_client_group:
        cte_server: "{{ cte_server }}"
        cte_username: "{{ cte_username }}"
        cte_password: "{{ cte_password }}"
        name: "{{ client_group_name }}"
        description: "{{ client_group_description }}"
        state: present
```

## DPG Resource Management

### Create DPG Policy

```yaml
- name: Create DPG Policy
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    policy_name: "My-Policy"
    policy_description: "My DPG policy"
  tasks:
    - name: Create DPG policy
      thalesgroup.ciphertrust.dpg_policy_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        name: "{{ policy_name }}"
        description: "{{ policy_description }}"
        state: present
```

### Create DPG Protection Policy

```yaml
- name: Create DPG Protection Policy
  hosts: localhost
  gather_facts: no
  vars:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    protection_policy_name: "My-Protection-Policy"
    protection_policy_description: "My DPG protection policy"
  tasks:
    - name: Create DPG protection policy
      thalesgroup.ciphertrust.dpg_protection_policy_save:
        cm_ip: "{{ cm_ip }}"
        cm_username: "{{ cm_username }}"
        cm_password: "{{ cm_password }}"
        name: "{{ protection_policy_name }}"
        description: "{{ protection_policy_description }}"
        state: present
```

## Troubleshooting

### Common Issues

1. **Connection Timeout**: Ensure CipherTrust Manager is accessible and firewall rules allow traffic on port 8443.
2. **Authentication Failed**: Verify credentials and user permissions.
3. **Resource Already Exists**: Use `state: update` to modify existing resources or `state: absent` to remove before creating.

### Debugging

Enable debug output by setting `ANSIBLE_DEBUG=true` or using `-vvv` flag with ansible-playbook.
