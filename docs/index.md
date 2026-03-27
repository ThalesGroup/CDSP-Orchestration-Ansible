# ThalesGroup CipherTrust Ansible Collection

Welcome to the documentation for the ThalesGroup CipherTrust Ansible Collection. This collection provides modules and roles for automating the management of Thales CipherTrust Manager, Data Protection Gateway (DPG), and Cloud Threat Extraction (CTE).

## Overview

The ThalesGroup CipherTrust Ansible Collection enables you to automate the configuration and management of:

- **CipherTrust Manager**: Centralized key management, user management, and security operations
- **Data Protection Gateway (DPG)**: Data masking, tokenization, and format-preserving encryption
- **Cloud Threat Extraction (CTE)**: Secure file processing and threat extraction
- **Cloud Connectors (CCKM)**: Integration with cloud key management services (AWS, Azure, GCP)

## Requirements

- Ansible >= 2.15.0
- Python >= 3.7
- CipherTrust Manager >= 2.17.0.12772

## Installation

```bash
ansible-galaxy collection install thalesgroup.ciphertrust
```

## Usage

### Playbooks

See the [Examples](examples/index.md) section for sample playbooks.

### Modules

See the [Modules](modules/index.md) section for a complete list of available modules.

### Roles

See the [Roles](roles/index.md) section for a complete list of available roles.

## Documentation Structure

- `docs/index.md` - This file
- `docs/modules/` - Module documentation
- `docs/roles/` - Role documentation
- `docs/examples/` - Example playbooks and usage patterns

## Contributing

Please read [CONTRIBUTING.md](../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository or contact Thales support.
