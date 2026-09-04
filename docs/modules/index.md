# Modules Documentation

This collection ships 76 modules for CipherTrust Manager. The catalogue below
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

### CCKM Azure Modules

CCKM manages Azure Key Vault material from CipherTrust Manager. A vault is
added to CCKM rather than created, so the usual first step is discovery with
`cckm_azure_subscription_info` and `cckm_azure_vault_info`.

- `cckm_azure_vault` / `cckm_azure_vault_info` - vaults, and discovery of vaults and managed HSMs
- `cckm_azure_key` / `cckm_azure_key_info` - keys, their cloud backups, and the rotation and backup jobs
- `cckm_azure_secret` / `cckm_azure_secret_info` - Key Vault secrets
- `cckm_azure_certificate` / `cckm_azure_certificate_info` - Key Vault certificates
- `cckm_azure_subscription` / `cckm_azure_subscription_info` - Azure subscriptions
- `cckm_azure_report` / `cckm_azure_report_info` - reports
- `cckm_azure_bulkjob` / `cckm_azure_bulkjob_info` - bulk jobs
- `cckm_azure_synchronization_job` / `cckm_azure_synchronization_job_info` - synchronising keys, certificates or secrets

Azure deletion is two-stage: `soft_delete` moves an object to the vault's
recycle bin, `recover` restores it, and `hard_delete` purges it.

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

### CCKM AWS Modules

CipherTrust Cloud Key Manager (CCKM) manages AWS KMS keys from CipherTrust
Manager. Everything is scoped to an *account container* -- CCKM's record of one
AWS account, the connection it is reached with, and the regions managed within
it -- so `cckm_aws_kms` comes first and the rest hang off it. The connection
itself is created with `connection_aws_save`.

- `cckm_aws_kms` - AWS account containers (add, update, archive, recover, ACLs)
- `cckm_aws_key` - AWS KMS keys: create, upload (BYOK), rotate, enable/disable,
  alias and tag maintenance, policy updates, replication, scheduled deletion
- `cckm_aws_policy_template` - Reusable key policy templates
- `cckm_aws_custom_key_store` - CloudHSM-backed and external (XKS) key stores
- `cckm_aws_synchronization_job` - Make keys and key stores created outside
  CCKM visible to it
- `cckm_aws_bulkjob` - Apply one operation across many keys in one request
- `cckm_aws_report` - Key usage reports built from CloudWatch logs
- `cckm_aws_xks_proxy` - Exercise the XKS proxy endpoints AWS KMS will call

Read-only counterparts:

- `cckm_aws_key_info` - Keys, their versions and rotation history
- `cckm_aws_kms_info` - Account containers
- `cckm_aws_policy_template_info` - Policy templates
- `cckm_aws_custom_key_store_info` - Key stores, their health and credentials
- `cckm_aws_synchronization_job_info` - Synchronization job status
- `cckm_aws_bulkjob_info` - Bulk job status and per-key results
- `cckm_aws_report_info` - Report status, contents and CSV download
- `cckm_aws_account_info` - What CipherTrust Manager can see in AWS: accounts,
  regions, IAM users and roles, CloudWatch log groups
- `cckm_aws_alias_info` - Whether a key alias is already in use
- `cckm_aws_cloudhsm_cluster_info` - CloudHSM clusters free to back a key store

Delete a CCKM AWS resource with `cm_resource_delete` using `resource_type` of
`aws-kms`, `aws-key`, `aws-policy-template`, `aws-custom-key-store` or
`aws-report`. Note that deleting an `aws-key` removes CCKM's record of it and
leaves the key in AWS; to destroy the AWS key, use `cckm_aws_key` with
`op_type: schedule_deletion`.

### Interface and License Modules

- `interface_save` - Interface management
- `interface_actions` - Interface actions (enable, disable, CSR, etc.)
- `license_create` - License creation
- `license_trial_action` - Trial license actions
- `license_trial_get` - Get trial license information
- `licensing_lockdata_get` - Get licensing lock data

## Module Documentation

Click on any module name to view its detailed documentation.
