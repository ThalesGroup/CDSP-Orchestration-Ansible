# Quick Start Guide for Integration Tests

## Overview

This guide provides quick commands for running integration tests for the ThalesGroup CipherTrust Ansible Collection.

## Prerequisites

1. **Ansible installed**:
   ```bash
   pip install ansible ansible-test
   ```

2. **Collection dependencies**:
   ```bash
   ansible-galaxy collection install -r tests/requirements.yml
   ```

3. **Environment variables** (optional, defaults will be used):
   ```bash
   export CIPHERTRUST_CONNECTION_STRING="localhost:8200"
   export CIPHERTRUST_USERNAME="admin"
   export CIPHERTRUST_PASSWORD="Thales123"
   export CIPHERTRUST_DOMAIN=""
   export CIPHERTRUST_VERIFY_SSL="false"
   ```

## Running Tests

### Run All Integration Tests
```bash
cd tests
ansible-test integration --color yes --timeout 300
```

### Run Specific Test
```bash
ansible-test integration module_vault_keys2_save
```

### Run Multiple Specific Tests
```bash
ansible-test integration module_vault_keys2_save module_dpg_policy_save module_cte_client
```

### Run Tests with Verbose Output
```bash
ansible-test integration --verbose
```

### Run Tests with Debug Output
```bash
ansible-test integration --debug
```

### Run Tests with Retry
```bash
ansible-test integration --retry 2
```

### Run Tests with Specific Python Version
```bash
ansible-test integration --python 3.9
```

## Test Targets

All 33 modules have integration tests:

### Key Management
- `module_vault_keys2_save` - Key creation and management
- `module_vault_keys2_op` - Key operations

### Data Protection Gateway (DPG)
- `module_dpg_policy_save` - DPG policy management
- `module_dpg_access_policy_save` - Access policy management
- `module_dpg_protection_policy_save` - Protection policy management
- `module_dpg_character_set_save` - Character set management
- `module_dpg_masking_format_save` - Masking format management
- `module_dpg_client_profile_save` - Client profile management
- `module_dpg_user_set_save` - User set management

### CipherTrust Enterprise (CTE)
- `module_cte_client` - CTE client management
- `module_cte_client_group` - CTE client group management
- `module_cte_csi_storage_group` - CSI storage group management
- `module_cte_policy_save` - CTE policy management
- `module_cte_process_set` - Process set management
- `module_cte_resource_set` - Resource set management
- `module_cte_signature_set` - Signature set management
- `module_cte_user_set` - User set management

### Group Management
- `module_group_save` - Group creation and management
- `module_group_add_remove_object` - Group membership management

### Interface Management
- `module_interface_save` - Interface configuration
- `module_interface_actions` - Interface operations

### Licensing
- `module_license_create` - License creation
- `module_license_trial_action` - Trial license actions
- `module_license_trial_get` - Trial license information
- `module_licensing_lockdata_get` - Licensing lock data

### Certificate Management
- `module_cm_certificate_authority` - Certificate authority management
- `module_cm_cluster` - Cluster management
- `module_cm_regtoken` - Registration token management
- `module_cm_resource_delete` - Resource deletion
- `module_cm_resource_get_id_from_name` - Resource ID lookup
- `module_cm_services` - Service information

### User Management
- `module_usermgmt_users_save` - User management

### Domain Management
- `module_domain_save` - Domain management

## CI/CD Integration

### GitHub Actions

The integration tests are automatically run on:
- Push to main branch
- Pull requests
- Weekly schedule (Sunday at midnight)
- Manual trigger

### Workflow File
`.github/workflows/integration-tests.yml`

### Test Matrix

The workflow runs tests in parallel using a matrix strategy:
- Each test target runs independently
- Results are uploaded as artifacts
- Coverage is reported to Codecov

## Troubleshooting

### Test Timeout
If tests timeout, increase the timeout value:
```bash
ansible-test integration --timeout 600
```

### Connection Issues
Verify environment variables are set correctly:
```bash
echo $CIPHERTRUST_CONNECTION_STRING
echo $CIPHERTRUST_USERNAME
```

### SSL Verification Errors
Disable SSL verification if using self-signed certificates:
```bash
export CIPHERTRUST_VERIFY_SSL="false"
```

### Debugging
Run with debug output:
```bash
ansible-test integration --debug
```

## Test Results

### Artifacts
Test results are uploaded as artifacts in GitHub Actions:
- `test-results` - All test results
- `test-results-{module_name}` - Specific module results

### Coverage
Coverage reports are uploaded to Codecov:
- Flag: `integration-tests`
- Name: `codecov-umbrella`

## Best Practices

1. **Run tests locally before committing**
2. **Use descriptive test names**
3. **Include both success and failure scenarios**
4. **Clean up test resources after testing**
5. **Use fixtures for common API responses**
6. **Validate response fields in assertions**

## Additional Resources

- [Ansible Test Documentation](https://docs.ansible.com/ansible/latest/dev_guide/testing.html)
- [Integration Test Targets](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html)
- [CipherTrust API Documentation](https://docs.thalesgroup.com)
