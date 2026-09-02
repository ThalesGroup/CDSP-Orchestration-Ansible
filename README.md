# ThalesGroup CipherTrust Collection

The ThalesGroup CipherTrust collection includes a variety of Ansible modules to help automate the configuration of Thales CipherTrust Manager as well as the configuration of various CipherTrust Data Security Platform (CDSP) connectors such as CipherTrust Transparent Encryption (CTE) and Data Protection Gateway (DPG). This collection is maintained by the ThalesGroup Developer Advocacy team.

## Description

The primary purpose of this collection is to simplify the configuration of CipherTrust Data Security Platform connectors as well as management of cryptography keys through automation. By leveraging this collection, organizations can automate security related tasks like definining access and protection policies, user and group based data access management and thus reducing manual intervention, minimizing errors, and ensuring consistent and repeatable deployments. This leads to increased efficiency, faster deployments, and a more agile IT infrastructure.

## Requirements

### Ansible version compatibility
Tested with the Ansible Core >= 2.15.0 versions, and the current development version of Ansible. Ansible Core versions prior to 2.15.0 are not supported.

### Python version compatibility
Tested with Python version 3.7 and above

### CipherTrust Manager version compatibility
Tested with Thales CipherTrust Manager version 2.17.0.12772 and higher

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
      server_private_ip: ""
      server_port: "5432"
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
      server_private_ip: ""
      server_port: "5432"
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
      server_private_ip: ""
      server_port: "5432"
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
      server_private_ip: ""
      server_port: "5432"
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

## Testing

This collection is tested for the following -
| Jobs  | Description  | Python Version  | Ansible Version  | CipherTrust Manager Version  |
|---|---|---|---|---|
| changelog  | Checks for the presence of Changelog  | 3.10.12 | 2.16.5 | |
| Linters  | Runs python and YAML lint  | 3.10.12 | 2.16.5 | |
| Sanity  | Runs ansible sanity checks  | 3.10.12 | 2.15+ | |
| Integration  | Executes teh integration test suites  | | | 2.17 |

## Contributing
We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the this repository.

## Support

> [!IMPORTANT]
> **This is a community-supported collection. It is not covered by Thales Customer Support.**

This collection is maintained by the Thales Developer Advocacy team and the open-source community. It is **not** a Thales product, is not part of any Thales product entitlement, and is **not** covered by any Thales support contract, SLA, or maintenance agreement.
Support requests raised through official Thales Customer Support channels or the Thales Support Portal regarding this collection will not be actioned.

For help, please use the community channels:

- [GitHub Issues](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/issues) — bug reports, feature requests, and questions about this collection
- [Thales Community Forum](https://supportportal.thalesgroup.com/community) — general discussion with other users

Issues relating to the underlying **CipherTrust Manager** or **CDSP** products themselves (as opposed to this collection) should continue to go through your normal Thales support channels.

Community support is provided on a best-effort basis by volunteers. There is no guaranteed response time or commitment to fix any issue.

### Warranty and liability

This collection is distributed under the [MIT License](LICENSE) and is provided
**"AS IS", WITHOUT WARRANTY OF ANY KIND**, express or implied, including but not limited
to the warranties of merchantability, fitness for a particular purpose, and
non-infringement. As set out in the licence, in no event shall the authors or copyright
holders be liable for any claim, damages, or other liability arising from, out of, or in
connection with the collection or its use.

You are responsible for evaluating and testing this collection before using it in any
production or security-sensitive environment.

## Release Notes and Roadmap

See the rendered changelog


## Related Information

[Thales Community Forum](https://supportportal.thalesgroup.com/community)
[YouTube Channel](https://www.youtube.com/@ThalesCloudSec)
[Thales CipherTrust Platform Community Edition](https://cpl.thalesgroup.com/encryption/ciphertrust-platform-community-edition)

## License Information

[MIT] (https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/blob/main/LICENSE)
