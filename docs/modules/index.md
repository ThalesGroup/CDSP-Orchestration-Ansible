# Modules Documentation

This collection ships 42 modules for CipherTrust Manager. The catalogue below
groups them by area.

## Where the reference documentation lives

Per-module reference — every option, its type, defaults, aliases and return
values — is generated from the modules themselves and published at
<https://thalesgroup.github.io/CDSP-Orchestration-Ansible/branch/main>.

It is not duplicated here. Hand-written copies drifted from the modules, so
they were removed; the module source is the single source of truth.

To read the documentation for a module locally:

```bash
ansible-doc thalesgroup.ciphertrust.vault_keys2_save
```

## Module Categories

### CipherTrust Manager Modules

- `cm_cluster` - Cluster management for CipherTrust Manager
- `cm_certificate_authority` - Certificate authority management
- `cm_regtoken` - Registration token management
- `cm_services` - Service management
- `cm_resource_delete` - Delete resources
- `cm_resource_get_id_from_name` - Get resource ID by name

### Key Management Modules

- `vault_keys2_save` - Key creation, update, and operations
- `vault_keys2_op` - Key operations (archive, recover, revoke, etc.)

### User and Group Management Modules

- `usermgmt_users_save` - User management
- `group_save` - Group management
- `group_add_remove_object` - Add/remove objects from groups

### DPG Modules

- `dpg_policy_save` - DPG policy management
- `dpg_access_policy_save` - Access policy management
- `dpg_user_set_save` - User set management
- `dpg_client_profile_save` - Client profile management
- `dpg_character_set_save` - Character set management
- `dpg_masking_format_save` - Masking format management
- `dpg_protection_policy_save` - Protection policy management

### CTE Modules

- `cte_client` - CTE client management
- `cte_client_group` - CTE client group management
- `cte_csi_storage_group` - CTE CSI storage group management
- `cte_policy_save` - CTE policy management
- `cte_process_set` - CTE process set management
- `cte_resource_set` - CTE resource set management
- `cte_signature_set` - CTE signature set management
- `cte_user_set` - CTE user set management

### Cloud Connection Modules

Connections in CipherTrust Manager's connection manager hold the credentials
CipherTrust Manager uses to reach a cloud provider, and are referenced by
products such as CCKM.

- `connection_aws_save` - AWS connections (access key, assumed role, or IAM Roles Anywhere)
- `connection_azure_save` - Azure connections (client secret or certificate)
- `connection_gcp_save` - Google Cloud connections (service account key)
- `connection_oci_save` - Oracle Cloud Infrastructure connections (API signing key)
- `connection_test` - Test a stored connection's credentials against the provider
- `connection_aws_test` - Check AWS credentials before storing them
- `connection_azure_test` - Check Azure credentials before storing them
- `connection_gcp_test` - Check a GCP service account key before storing it
- `connection_oci_test` - Check OCI credentials before storing them

Delete a connection with `cm_resource_delete` using `resource_type` of
`aws-connection`, `azure-connection`, `gcp-connection` or `oci-connection`.

### Interface and License Modules

- `interface_save` - Interface management
- `interface_actions` - Interface actions (enable, disable, CSR, etc.)
- `license_create` - License creation
- `license_trial_action` - Trial license actions
- `license_trial_get` - Get trial license information
- `licensing_lockdata_get` - Get licensing lock data

## Module Documentation

Click on any module name to view its detailed documentation.
