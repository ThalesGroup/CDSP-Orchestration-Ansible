# Ansible Collection
For IT admins and DevOps teams who use Red Hat® Ansible® to manage their infrastructure, we have provided Ansible Modules and Playbooks that interface with each of the products within the CipherTrust Data Security Platform and IBM Guardium Data Encryption.

## Ansible version compatibility
Tested with the Ansible Core 2.12, and 2.13 releases, and the current development version of Ansible. Ansible Core versions before 2.11.0 are not tested.

## Python version compatibility
Tested with Python version 3.6

## Modules
| Name  | Description  |
|---|---|
| group_save  | Create and manage User Groups  |
| group_add_remove_object  | Add or remove clients or users to a group  |
| interface_save  | Create and manage interfaces on CipherTrust Manager  |
| interface_actions  | Perform operations on interfaces  |
| license_trial_action  | Apply trial license to CipherTrust Manager  |
| license_trial_get  | Get the trial license state for CipherTrust Manager  |
| licensing_lockdata_get  | Get lockdata for license file  |
| usermgmt_users_save  | Create and manager CipherTrust Manager users  |
| vault_keys2_save  | Create and manage keys  |
| vault_keys2_op  | Perform key operations  |
| cm_cluster  | Create and add nodes to a CipherTrust Manager cluster  |
| domain_save  | Create and manage domains for CM  |
| cm_regtoken  | Create and manage registration tokens to be used by CM connectors like DPG and CTE   |
| cm_resource_delete  | Delete an asset on CM using ID or name  |
| cm_resource_get_id_from_name  | Get asset ID using name  |
| cte_client  | Create and manage CipherTrust Transparent Encryption (CTE) clients  |
| cte_client_group  | Create and manage CTE client groups  |
| cte_csi_storage_group  | Create and manage Container Storage Interface (CSI) storage group for CTE for Kubernetes  |
| cte_policy_save  | Create and manage CTE policies  |
| cte_process_set  | Create and manage process sets to which CTE policy may apply  |
| cte_resource_set  | Create and manage resource sets like directories and files to be protected by CTE |
| cte_signature_set  | Create and manage signature sets to which CTE policy may apply  |
| cte_user_set  | Create and manage users with a user set to which CTE policy may apply  |
| dpg_access_policy_save  | Create and manage Access Policies for CipherTrust Data Protection Gateway (DPG)  |
| dpg_character_set_save  | Create character sets for DPG  |
| dpg_client_profile_save  | Create and manage client profiles for DPG  |
| dpg_masking_format_save  | Manage masking formats for data reveal operations in DPG  |
| dpg_policy_save  | Create and manage DPG data protection policies  |
| dpg_protection_policy_save  | Create and manage protection policies on DPG  |
| dpg_user_set_save  | Create and manage user sets for DPG  |

## Installing this collection
Install Ansible on your host machine using instructions specific to the OS of the host machine.

Download thalesgroup-ciphertrust-1.0.0.tar.gz from this repository
* [Ansible](/)

Install the collection using command -
```
ansible-galaxy collection install thalesgroup-ciphertrust-1.0.0.tar.gz
```

## Using this collection
You can call modules by their Fully Qualified Collection Name (FQCN), such as thalesgroup.ciphertrust.cm_cluster

```
---
- name: "Create new cluster"
  thalesgroup.ciphertrust.cm_cluster:
    localNode:
      server_ip: "{{ <IP or FQDN of CipherTrust Manager Server> }}"
      server_private_ip: "{{ <Private IP of CipherTrust Manager Server...If different from server_ip> }}"
      server_port: "{{ port number where CipherTrust Manager is listening, defaults to 5432}}"
      user: "{{ <Admin User of CipherTrust Manager> }}"
      password: "{{ <Password of Admin User> }}"
      verify: False
    op_type: new
```

## Run Playbooks
Sample playbooks provided as part of the repo
* [Ansible](playbooks/)
```
ansible-playbook cluster.yml -vv
```

## Contributing to this collection
We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the this repository.
