# ThalesGroup CipherTrust Collection

[![Lint](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/lint.yml/badge.svg)](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/lint.yml)
[![Sanity](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/sanity.yml/badge.svg)](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/sanity.yml)
[![Unit Tests](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/unit-tests.yml)
[![Build Validation](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/build.yml/badge.svg)](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/build.yml)
[![Changelog](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/changelog.yml/badge.svg)](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/changelog.yml)
[![Integration Tests](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/actions/workflows/integration-tests.yml)
[![Coverage](https://codecov.io/gh/ThalesGroup/CDSP-Orchestration-Ansible/branch/main/graph/badge.svg)](https://codecov.io/gh/ThalesGroup/CDSP-Orchestration-Ansible)

The ThalesGroup CipherTrust collection includes a variety of Ansible modules to help automate the configuration of Thales CipherTrust Manager as well as the configuration of various CipherTrust Data Security Platform (CDSP) connectors such as CipherTrust Transparent Encryption (CTE) and Data Protection Gateway (DPG). This collection is maintained by the ThalesGroup Developer Advocacy team.

## Description

The primary purpose of this collection is to simplify the configuration of CipherTrust Data Security Platform connectors as well as management of cryptography keys through automation. By leveraging this collection, organizations can automate security related tasks like definining access and protection policies, user and group based data access management and thus reducing manual intervention, minimizing errors, and ensuring consistent and repeatable deployments. This leads to increased efficiency, faster deployments, and a more agile IT infrastructure.

## Requirements

### Ansible version compatibility
Tested with the Ansible Core >= 2.15.0 versions, and the current development version of Ansible. Ansible Core versions prior to 2.15.0 are not supported.

### Python version compatibility
Requires Python 3.9 or later on the Ansible controller, which is the minimum
for ansible-core 2.15. Tested against Python 3.9 through 3.12.

### CipherTrust Manager version compatibility
Tested with Thales CipherTrust Manager version 2.17.0.12772 and higher

### Parameter naming deprecation
This collection now supports `snake_case` parameter names alongside legacy `camelCase` names.
Use `snake_case` in new playbooks (for example: `local_node`, `activation_date`, `usage_mask`, `wrap_key_name`).
Legacy `camelCase` names are deprecated and emit deprecation warnings; they are planned for removal in `2.0.0`.

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install thalesgroup.ciphertrust
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:


```yaml
collections:
  - name: thalesgroup.ciphertrust
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install thalesgroup.ciphertrust --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 1.0.0:

```
ansible-galaxy collection install thalesgroup.ciphertrust:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

This collection expects a running instance of Thales CipherTrust Manager Community Edition or any other version.

## Use Cases

You can use CipherTrust to automate some of redundant tasks desired by security experts or developers to protect their data in data stores such as databases or other cloud or local data stores or file systems. Some of the use cases include -

### Authenticating with CipherTrust Manager using CM IP/FQDN and username plus password along with other details
```
- name: "Create new user"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "192.168.2.100"
      user: "admin"
      password: "StrongPwd_1!"
      verify: False
      auth_domain_path: ""
```

### Creating user on CipherTrust Manager
```
- name: "Create new user"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "192.168.2.100"
      user: "admin"
      password: "StrongPwd_1!"
      verify: False
      auth_domain_path: ""
    op_type: "create"
    username: "john.doe"
    password: "StrongPassword_123!"
    email: "john.doe@example.com"
    name: "John Doe"
```
The above task creates a new user on CipherTrust Manager with username john.doe and password StrongPassword_123!

### Creating a key for encrypting or tokenizing data
```
- name: "Create Key"
  thalesgroup.ciphertrust.vault_keys2_save:
    op_type: create
    name: dpgKey
    algorithm: aes
    size: 256
    usageMask: 3145740
    unexportable: false
    undeletable: false
    meta:
      ownerId: admin
      versionedKey: true
    localNode:
      server_ip: "192.168.2.100"
      user: "admin"
      password: "StrongPwd_1!"
      verify: False
      auth_domain_path: ""
```
The above task creates a new key on CipherTrust Manager with details like AES algorith and key size of 256. It will also make the key exportable and deletable on CM and make the user admin as the owner of the key

### Creating a policy to protect a microservice in Kubernetes using Data Protection Gateway
```
- name: "Create Protection Policy"
  thalesgroup.ciphertrust.dpg_protection_policy_save:
    localNode:
      server_ip: "192.168.2.100"
      user: "admin"
      password: "StrongPwd_1!"
      verify: False
      auth_domain_path: ""
    op_type: create
    access_policy_name: protectionPolicy
    masking_format_id: "masking_format"
    name: protectionPolicy
    key: dpgKey
    tweak: "1628462495815733"
    tweak_algorithm: "SHA1"
    algorithm: "FPE/AES/UNICODE"
    character_set_id: "charset"
```
The above task creates a new protection policy on CipherTrust Manager with details like what masking format to use and what algorithm to use to protect the data. Check [ThalesDocs](https://thalesdocs.com/ctp/cm/latest/admin/adp_ag/adp-prtcn-policy/index.html#managing-protection-policy) to know more about protection policies on CipherTrust Manager

## Security

This collection works with highly sensitive material — CipherTrust Manager admin credentials, user passwords, PKCS#12 passphrases, private key material, and KMIP registration tokens. Please review the following guidance before using it in any non-sandbox environment.

### Credential handling

All fields that carry a secret (the `localNode.password` connection credential, module-level `password`, `new_password`, `passwordIdentifier`, `privateKeyBytes`, and `registration_token` parameters) are marked `no_log: true`. Ansible will redact them from task output, including when running with `-vvvv`, and from the JSON event stream emitted to callbacks. JWT bearer tokens minted against CipherTrust Manager are kept inside per-request session objects and are never returned from a module, placed in a result, or included in error messages.

### Storing credentials with Ansible Vault

Do not commit plaintext passwords to playbooks or inventory. Use [Ansible Vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html) to encrypt credential variables, or source them from a secrets backend (HashiCorp Vault, AWS Secrets Manager, etc.) at play time. A typical pattern:

```yaml
- name: "Create new user"
  thalesgroup.ciphertrust.usermgmt_users_save:
    localNode:
      server_ip: "{{ cm_server_ip }}"
      user: "{{ cm_admin_user }}"
      password: "{{ cm_admin_password }}"   # pulled from a vault-encrypted var file
      verify: true
      auth_domain_path: ""
    op_type: "create"
    username: "john.doe"
    password: "{{ new_user_password }}"     # also vault-encrypted
    email: "john.doe@example.com"
    name: "John Doe"
```

### TLS certificate validation

The `localNode.verify` flag controls TLS certificate verification for every call this collection makes to CipherTrust Manager — the initial `/api/v1/auth/tokens` login as well as every subsequent API call. It currently defaults to `false` for backwards compatibility with lab environments that run CM with a self-signed certificate.

**In production, always set `verify: true`.** Running with `verify: false` leaves the session vulnerable to man-in-the-middle interception of the admin credential exchange and every key/policy operation that follows it. If your CipherTrust Manager serves a certificate signed by an internal CA, make that CA trusted on the Ansible controller host rather than disabling verification.

### Reporting security issues

See [SECURITY.md](SECURITY.md) for the coordinated disclosure process.

## Testing

This collection is tested for the following -
| Jobs  | Description  | Python Version  | Ansible Version  | CipherTrust Manager Version  |
|---|---|---|---|---|
| Changelog | Enforces changelog fragments and validates changelog config | 3.12 | N/A | |
| Lint | Runs ansible-lint checks | 3.12 | 2.18 | |
| Sanity | Runs the full default `ansible-test sanity` test set in matrix | 3.9 - 3.12 | 2.15 - 2.18 | |
| Unit Tests | Runs `ansible-test units` matrix and coverage gates | 3.9 - 3.12 | 2.15 - 2.18 | |
| Build Validation | Verifies `ansible-galaxy collection build` output | 3.12 | 2.18 | |
| Integration | Runs scheduled/manual live CM integration tests | 3.12 | 2.18 | 2.17+ |

## Contributing
We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the this repository.

## Support
You can use GitHub issues page and [Thales Community Forum](https://supportportal.thalesgroup.com/community) for getting support on the community.

## Release Notes and Roadmap

See [CHANGELOG.rst](CHANGELOG.rst) for rendered release notes.
See [ROADMAP.md](ROADMAP.md) for planned milestones and backlog.


## Related Information

[Thales Community Forum](https://supportportal.thalesgroup.com/community)
[YouTube Channel](https://www.youtube.com/@ThalesCloudSec)
[Thales CipherTrust Platform Community Edition](https://cpl.thalesgroup.com/encryption/ciphertrust-platform-community-edition)

## License Information

[MIT](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/blob/main/LICENSE)
