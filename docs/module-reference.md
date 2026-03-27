# Module Reference

This document provides detailed documentation for all modules in the ThalesGroup CipherTrust Ansible Collection.

## Cluster Modules

### cm_cluster

Manages CipherTrust Manager cluster configuration.

**Description:**
This module manages cluster configuration for CipherTrust Manager, including cluster creation, node management, and cluster status.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `action` (string, optional): Action to perform (create, delete, status, join)
- `cluster_name` (string, optional): Name of the cluster
- `cluster_ip` (string, optional): IP address of the cluster
- `node_ip` (string, optional): IP address of the node
- `node_username` (string, optional): Username for the node
- `node_password` (string, optional): Password for the node

**Examples:**
```yaml
- name: Create cluster
  thalesgroup.ciphertrust.cm_cluster:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    action: "create"
    cluster_name: "my-cluster"
    cluster_ip: "10.0.0.1"
```

**Return Values:**
- `cluster_id` (string): ID of the cluster
- `cluster_name` (string): Name of the cluster
- `status` (string): Status of the cluster

---

## Key Management Modules

### vault_keys2_save

Manages keys in the CipherTrust Manager vault.

**Description:**
This module manages keys in the CipherTrust Manager vault, including key creation, update, and deletion.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `name` (string, required): Name of the key
- `key_type` (string, optional): Type of key (symmetric, asymmetric)
- `algorithm` (string, optional): Algorithm (AES, RSA, EC)
- `key_size` (int, optional): Key size
- `operation` (string, optional): Operation (create, update, delete, get)
- `tags` (list, optional): Tags for the key

**Examples:**
```yaml
- name: Create key
  thalesgroup.ciphertrust.vault_keys2_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    name: "my-key"
    key_type: "symmetric"
    algorithm: "AES"
    key_size: 256
```

**Return Values:**
- `key_id` (string): ID of the key
- `key_name` (string): Name of the key
- `key_type` (string): Type of the key

---

## User Management Modules

### usermgmt_users_save

Manages users in CipherTrust Manager.

**Description:**
This module manages users in CipherTrust Manager, including user creation, update, and deletion.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `username` (string, required): Username
- `email` (string, required): Email address
- `password` (string, required): Password
- `role` (string, optional): Role (admin, user, auditor)
- `operation` (string, optional): Operation (create, update, delete, get)

**Examples:**
```yaml
- name: Create user
  thalesgroup.ciphertrust.usermgmt_users_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    username: "newuser"
    email: "newuser@example.com"
    password: "password123"
    role: "admin"
```

**Return Values:**
- `user_id` (string): ID of the user
- `username` (string): Username
- `email` (string): Email address

---

## Group Management Modules

### group_save

Manages groups in CipherTrust Manager.

**Description:**
This module manages groups in CipherTrust Manager, including group creation, update, and deletion.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `name` (string, required): Name of the group
- `description` (string, optional): Description of the group
- `operation` (string, optional): Operation (create, update, delete, get)
- `members` (list, optional): List of group members

**Examples:**
```yaml
- name: Create group
  thalesgroup.ciphertrust.group_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    name: "my-group"
    description: "My group"
    members:
      - "user1"
      - "user2"
```

**Return Values:**
- `group_id` (string): ID of the group
- `group_name` (string): Name of the group
- `members` (list): List of group members

---

## Interface Management Modules

### interface_save

Manages network interfaces in CipherTrust Manager.

**Description:**
This module manages network interfaces in CipherTrust Manager, including interface creation, update, and deletion.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `name` (string, required): Name of the interface
- `ip` (string, required): IP address
- `netmask` (string, required): Netmask
- `gateway` (string, required): Gateway
- `operation` (string, optional): Operation (create, update, delete, get)

**Examples:**
```yaml
- name: Create interface
  thalesgroup.ciphertrust.interface_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    name: "eth0"
    ip: "10.0.0.1"
    netmask: "255.255.255.0"
    gateway: "10.0.0.254"
```

**Return Values:**
- `interface_id` (string): ID of the interface
- `name` (string): Name of the interface
- `ip` (string): IP address

---

## License Management Modules

### license_create

Creates licenses in CipherTrust Manager.

**Description:**
This module creates licenses in CipherTrust Manager.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `license_type` (string, required): Type of license
- `license_key` (string, required): License key
- `operation` (string, optional): Operation (create, get, delete)

**Examples:**
```yaml
- name: Create license
  thalesgroup.ciphertrust.license_create:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    license_type: "enterprise"
    license_key: "XXXX-XXXX-XXXX-XXXX"
```

**Return Values:**
- `license_id` (string): ID of the license
- `license_type` (string): Type of license
- `expires` (string): Expiration date

---

## DPG Modules

### dpg_policy_save

Manages DPG policies.

**Description:**
This module manages DPG policies, including policy creation, update, and deletion.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `name` (string, required): Name of the policy
- `description` (string, optional): Description of the policy
- `operation` (string, optional): Operation (create, update, delete, get)

**Examples:**
```yaml
- name: Create DPG policy
  thalesgroup.ciphertrust.dpg_policy_save:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    name: "my-policy"
    description: "My DPG policy"
```

**Return Values:**
- `policy_id` (string): ID of the policy
- `name` (string): Name of the policy
- `description` (string): Description of the policy

---

## CTE Modules

### cte_client

Manages CTE clients.

**Description:**
This module manages CTE clients, including client creation, update, and deletion.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `name` (string, required): Name of the client
- `description` (string, optional): Description of the client
- `operation` (string, optional): Operation (create, update, delete, get)

**Examples:**
```yaml
- name: Create CTE client
  thalesgroup.ciphertrust.cte_client:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    name: "my-client"
    description: "My CTE client"
```

**Return Values:**
- `client_id` (string): ID of the client
- `name` (string): Name of the client
- `description` (string): Description of the client

---

## Resource Management Modules

### cm_resource_delete

Deletes resources from CipherTrust Manager.

**Description:**
This module deletes resources from CipherTrust Manager.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `resource_type` (string, required): Type of resource
- `resource_id` (string, required): ID of the resource

**Examples:**
```yaml
- name: Delete resource
  thalesgroup.ciphertrust.cm_resource_delete:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    resource_type: "key"
    resource_id: "key-id"
```

**Return Values:**
- `deleted` (bool): Whether the resource was deleted
- `resource_id` (string): ID of the deleted resource

---

### cm_resource_get_id_from_name

Gets resource ID from name.

**Description:**
This module gets resource ID from name.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `resource_type` (string, required): Type of resource
- `name` (string, required): Name of the resource

**Examples:**
```yaml
- name: Get resource ID
  thalesgroup.ciphertrust.cm_resource_get_id_from_name:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    resource_type: "key"
    name: "my-key"
```

**Return Values:**
- `resource_id` (string): ID of the resource
- `name` (string): Name of the resource

---

## Service Modules

### cm_services

Manages services in CipherTrust Manager.

**Description:**
This module manages services in CipherTrust Manager.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `service_name` (string, required): Name of the service
- `operation` (string, optional): Operation (start, stop, restart, status)

**Examples:**
```yaml
- name: Restart service
  thalesgroup.ciphertrust.cm_services:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    service_name: "cte"
    operation: "restart"
```

**Return Values:**
- `service_name` (string): Name of the service
- `status` (string): Status of the service

---

## Certificate Authority Modules

### cm_certificate_authority

Manages certificate authorities in CipherTrust Manager.

**Description:**
This module manages certificate authorities in CipherTrust Manager.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `name` (string, required): Name of the CA
- `operation` (string, optional): Operation (create, update, delete, get)

**Examples:**
```yaml
- name: Create CA
  thalesgroup.ciphertrust.cm_certificate_authority:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    name: "my-ca"
```

**Return Values:**
- `ca_id` (string): ID of the CA
- `name` (string): Name of the CA

---

## Registration Token Modules

### cm_regtoken

Manages registration tokens in CipherTrust Manager.

**Description:**
This module manages registration tokens in CipherTrust Manager.

**Options:**
- `cm_ip` (string, required): CipherTrust Manager IP address
- `cm_username` (string, required): CipherTrust Manager username
- `cm_password` (string, required): CipherTrust Manager password
- `cm_verify` (bool, optional): Verify SSL certificate (default: true)
- `cm_ca_bundle` (string, optional): Path to CA bundle file
- `cm_session_id` (string, optional): Session ID for authentication
- `name` (string, required): Name of the token
- `operation` (string, optional): Operation (create, update, delete, get)

**Examples:**
```yaml
- name: Create registration token
  thalesgroup.ciphertrust.cm_regtoken:
    cm_ip: "10.0.0.1"
    cm_username: "admin"
    cm_password: "password"
    name: "my-token"
```

**Return Values:**
- `token_id` (string): ID of the token
- `name` (string): Name of the token
