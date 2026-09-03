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

The authoritative list is `tests/integration.yml`, and
`tests/unit/test_integration_targets.py` fails if it falls out of step with
the directories under `tests/integration/targets/`. To list them:

```bash
ansible-test integration --list-targets
```

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
