=====================================
Thalesgroup.Ciphertrust Release Notes
=====================================

.. contents:: Topics

v1.0.1
======

Release Summary
---------------

This release has deprecated some of the existing CCKM and cloud connection related modules that will be return in upcoming releases with better coverage and testing done. We have also implemented and verified the collection to work with Thales new connection CipherTrust RESTful Data Protection or CRDP

Major Changes
-------------

- cm_certificate_authority - Added new module to manage certificate authorities on CipherTrust Manager
- cm_services - Added new module to reset or restart CipherTrust Manager services or check the current status of the service
- connection management module utils now allow domain to be part of the connection

Breaking Changes / Porting Guide
--------------------------------

- cckm_aws_custom_keystore - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_aws_key - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_aws_kms - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_az_certificate - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_az_key - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_az_secret - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_az_vault - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_gcp_ekm - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_gcp_key - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_gcp_keyring - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_gcp_project - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_gcp_workspace_cse - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_sfdc_cloud_organization - module removed from 1.0.1, in favor of a better version to be added in future releases
- cckm_sfdc_secret - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_aws - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_azure - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_elasticsearch - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_google - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_hadoop - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_ldap - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_loki - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_luna_hsm - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_oidc - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_oracle - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_salesforce - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_sap_data_custodian - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_scp - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_smb - module removed from 1.0.1, in favor of a better version to be added in future releases
- connection_manager_syslog - module removed from 1.0.1, in favor of a better version to be added in future releases

v1.0.0
======

Release Summary
---------------

This is the first release of the ThalesGroup CipherTrust Ansible Collection!

New Modules
-----------

- thalesgroup.ciphertrust.cckm_aws_custom_keystore - Create and manage Amazon Web Services Custom Keystore via CipherTrust Cloud Key Manager (CCKM) APIs hosted on Thales CipherTrust Manager.
- thalesgroup.ciphertrust.cckm_aws_key - Create, store, and manage keys on Amazon Web Services via CCKM APIs.
- thalesgroup.ciphertrust.cckm_aws_kms - Perform get, delete, and update operation on AWS Key Management Service as well as grant permissions to CCKM users to perform specific actions on the AWS KMS via CCKM APIs.
- thalesgroup.ciphertrust.cckm_az_certificate - Create, list, delete, update, revoke, restore, and other operations on Azure certificates via CCKM APIs.
- thalesgroup.ciphertrust.cckm_az_key - Perform tasks such as creating, deleting, uploading, synchronizing, update key parameters, scheduling key rotation and restoring keys on Azure via CCKM APIs.
- thalesgroup.ciphertrust.cckm_az_secret - Create, list, update, soft-delete, hard-delete, recover, and synchronize Azure secrets via CCKM APIs.
- thalesgroup.ciphertrust.cckm_az_vault - Add, delete, update and list the Azure vaults based on subscription via CCKM APIs.
- thalesgroup.ciphertrust.cckm_gcp_ekm - For managing Google Cloud EKM endpoints that do not reside in a cryptospace, a user must belong to CCKM Admin group and Key User group to perform any operation (create ekm, list ekm, get ekm, update ekm, delete ekm, get policy, update policy, rotate ekm, enable ekm, and disable ekm).
- thalesgroup.ciphertrust.cckm_gcp_key - Create and manage Google Cloud Keys .
- thalesgroup.ciphertrust.cckm_gcp_keyring - Add, list, and patch Google Cloud Key Rings via CCKM APIs.
- thalesgroup.ciphertrust.cckm_gcp_project - Create, list, delete, and patch Google Cloud Projects via CCKM APIs.
- thalesgroup.ciphertrust.cckm_gcp_workspace_cse - Work with Google Workspace client side encryption using CCKM APIs.
- thalesgroup.ciphertrust.cckm_sfdc_cloud_organization - Create and manage SFDC Cloud organizations via CCKM APIs.
- thalesgroup.ciphertrust.cckm_sfdc_secret - Create and manage SFDC tenant secret via CCKM APIs.
- thalesgroup.ciphertrust.cm_cluster - Create new or join existing CipherTrust Manager cluster.
- thalesgroup.ciphertrust.cm_regtoken - Create or update a CipherTrust Manager Application Registration Token.
- thalesgroup.ciphertrust.cm_resource_delete - Delete an existing resource on CipherTrust Manager by given Identifier.
- thalesgroup.ciphertrust.cm_resource_get_id_from_name - Get the ID of an existing resource on CipherTrust Manager using its name.
- thalesgroup.ciphertrust.connection_manager_aws - Create, delete, get, and update an AWS connection using AWS connection parameters on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_azure - Create, delete, get, and update an Azure connection using Azure connection parameters on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_elasticsearch - Create, delete, get, and update an Elasticsearch connection using Elasticsearch connection parameters on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_google - Create, delete, get, and update a Google cloud connection using connection parameters on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_hadoop - Create, delete, get, and update a Hadoop connection on CipherTrust Manager via APIs.
- thalesgroup.ciphertrust.connection_manager_ldap - Create, delete, get, and update a LDAP connection on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_loki - Create, delete, get, and update a Loki log forwarder connection on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_luna_hsm - Create, delete, get, and update a Luna HSM connection, that could be an HA or non-HA via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_oidc - Create, delete, get, and update an OIDC connection on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_oracle - Create, delete, get, and update an Oracle Cloud Infrastructure on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_salesforce - Create, delete, get, and update a Salesforce Cloud connection on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_sap_data_custodian - Create, delete, get, and update SAP Data Custodian connections on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_scp - Create, delete, get, and update SCP connections on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_smb - Create, delete, get, and update Server Message Block (SMB) connections on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.connection_manager_syslog - Create, delete, get, and update Syslog connections on CipherTrust Manager via CipherTrust APIs.
- thalesgroup.ciphertrust.cte_client - Perform create, patch, delete, add guard points, unguard guard points, pause LDT, and other operations for CipherTrust Transparent Encryption (CTE) client on CipherTrust Manager.
- thalesgroup.ciphertrust.cte_client_group - Perform create, patch, add/remove clients, add guard points, and other operations for CTE client groups on CipherTrust Manager.
- thalesgroup.ciphertrust.cte_csi_storage_group - Perform create, patch, add/remove clients, add/remove guard points, and other operations for CTE CSI storage group on CipherTrust Manager..
- thalesgroup.ciphertrust.cte_policy_save - Create, patch, and add rules to CTE client policies on CipherTrust Manager.
- thalesgroup.ciphertrust.cte_process_set - Perform create, update, add/patch/delete processes to CTE process sets on CipherTrust Manager.
- thalesgroup.ciphertrust.cte_resource_set - Perform create, update, add/patch/delete resources to CTE resource sets on CipherTrust Manager.
- thalesgroup.ciphertrust.cte_signature_set - Perform create, update, add/delete signatures to CTE signature sets on CipherTrust Manager.
- thalesgroup.ciphertrust.cte_user_set - Perform create, update, add/patch/delete users to CTE user sets on CipherTrust Manager.
- thalesgroup.ciphertrust.domain_save - Create of patch a domain on CipherTrust Manager.
- thalesgroup.ciphertrust.dpg_access_policy_save - Create or patch access policy on CipherTrust Manager.
- thalesgroup.ciphertrust.dpg_character_set_save - Create or patch character sets on CipherTrust Manager.
- thalesgroup.ciphertrust.dpg_client_profile_save - Create or patch Data Protection Gateway Client Profiles on CipherTrust Manager.
- thalesgroup.ciphertrust.dpg_masking_format_save - Create or patch masking formats on CipherTrust Manager.
- thalesgroup.ciphertrust.dpg_policy_save - Create or patch DPG policy for clients on CipherTrust Manager.
- thalesgroup.ciphertrust.dpg_protection_policy_save - Create or patch protection policy on CipherTrust Manager.
- thalesgroup.ciphertrust.dpg_user_set_save - Create or patch userset on CipherTrust Manager.
- thalesgroup.ciphertrust.group_add_remove_object - Add or remove a user or client from an existing group on CipherTrust Manager.
- thalesgroup.ciphertrust.group_save - Create or patch a group on CipherTrust Manager.
- thalesgroup.ciphertrust.interface_actions - Perform actions like enable/disable, put/use certificate, CSR generation, etc. on an existing interface on CipherTrust Manager.
- thalesgroup.ciphertrust.interface_save - Create new or patch an existing interface on CipherTrust Manager.
- thalesgroup.ciphertrust.license_create - Add new license to CipherTrust Manager.
- thalesgroup.ciphertrust.license_trial_action - Activate/de-activate a trial license on CipherTrust Manager.
- thalesgroup.ciphertrust.license_trial_get - Get a trial license ID for CipherTrust Manager.
- thalesgroup.ciphertrust.licensing_lockdata_get - Get licensing Lockdata.
- thalesgroup.ciphertrust.usermgmt_users_save - Create a new or update existing user on CipherTrust Manager.
- thalesgroup.ciphertrust.vault_keys2_op - Perform operations like destroy, archive, recover, revoke, reactivate, export, and clone existing keys on CipherTrust Manager.
- thalesgroup.ciphertrust.vault_keys2_save - Create a new or update existing cryptography key on CipherTrust Manager..
