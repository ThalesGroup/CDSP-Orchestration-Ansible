# Roles Documentation

This section provides documentation for all roles in the ThalesGroup CipherTrust Ansible Collection.

## Available Roles

| Role | Status |
|------|--------|
| [`crdp`](crdp.md) | Implemented |
| [`cte4k8s`](cte4k8s.md) | Not yet implemented (placeholder) |
| [`cte4u`](cte4u.md) | Not yet implemented (placeholder) |
| [`dpg`](dpg.md) | Not yet implemented (placeholder) |

Placeholder roles ship with an empty `tasks/main.yml`; the features and
variables listed for them below describe the intended interface, not
current behaviour.

### crdp

Role for setting up CipherTrust Ransomware Defense Platform (CRDP).

**Features:**
- Key creation for CRDP
- User set creation for masked and plaintext data
- Access policy configuration
- Masking format setup

**Requirements:**
- CipherTrust Manager >= 2.17.0.12772
- Admin credentials

**Variables:**
- `this_node_address` - CipherTrust Manager IP address
- `this_node_private_ip` - Private IP address
- `this_node_username` - Username for authentication
- `this_node_password` - Password for authentication
- `this_node_connection_string` - Connection string with all connection parameters

**Example Usage:**
```yaml
- hosts: localhost
  roles:
    - { role: crdp, cm_ip: "10.0.0.1", cm_username: "admin", cm_password: "password" }
```

### cte4k8s

**Not yet implemented — placeholder role.**

Role for setting up CTE integration with Kubernetes.

**Features:**
- CTE client group configuration
- CSI storage group setup
- Policy configuration for Kubernetes workloads

**Requirements:**
- CTE installed and configured
- Kubernetes cluster access

**Variables:**
- `cte_client_group_name` - Name of the CTE client group
- `cte_policy_name` - Name of the CTE policy
- `storage_class_name` - Name of the Kubernetes storage class

**Example Usage:**
```yaml
- hosts: localhost
  roles:
    - { role: cte4k8s, cte_server: "10.0.0.1", cte_username: "admin", cte_password: "password" }
```

### cte4u

**Not yet implemented — placeholder role.**

Role for setting up CTE for Unix/Linux systems.

**Features:**
- CTE client configuration
- Guard point setup
- Policy assignment

**Requirements:**
- CTE installed and configured
- Unix/Linux system access

**Variables:**
- `cte_client_name` - Name of the CTE client
- `guard_paths` - Paths to protect
- `policy_name` - Name of the CTE policy

**Example Usage:**
```yaml
- hosts: localhost
  roles:
    - { role: cte4u, cte_server: "10.0.0.1", cte_username: "admin", cte_password: "password" }
```

### dpg

**Not yet implemented — placeholder role.**

Role for setting up Data Protection Gateway (DPG).

**Features:**
- Key creation for DPG
- Interface configuration
- Protection policy setup
- Access policy configuration
- User set management

**Requirements:**
- CipherTrust Manager >= 2.17.0.12772
- Admin credentials

**Variables:**
- `dpg_key_name` - Name of the DPG key
- `dpg_policy_name` - Name of the DPG policy
- `char_set_name` - Name of the character set
- `access_policy_name` - Name of the access policy
- `var_username` - Username for DPG user
- `var_password` - Password for DPG user
- `var_email` - Email for DPG user
- `var_name` - Display name for DPG user
- `var_user_set_name` - Name of the user set

**Example Usage:**
```yaml
- hosts: localhost
  roles:
    - { role: dpg, dpg_key_name: "DPG-Key", dpg_policy_name: "DPG-Policy" }
```

## Role Documentation

Click on any role name to view its detailed documentation.
