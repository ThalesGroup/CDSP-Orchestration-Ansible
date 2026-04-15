# Installation

This guide covers installing the ThalesGroup CipherTrust Ansible Collection.

## Requirements

### System Requirements

- **Operating System**: Linux, macOS, Windows (with WSL)
- **Python**: 3.7 or higher
- **Ansible**: 2.15.0 or higher

### CipherTrust Manager Requirements

- **Version**: 2.17.0.12772 or higher
- **Access**: Admin credentials required
- **Network**: Port 8443 accessible

## Installation Methods

### Method 1: Install from Galaxy

```bash
ansible-galaxy collection install thalesgroup.ciphertrust
```

### Method 2: Install from Source

1. Clone the repository:

```bash
git clone https://github.com/thalesgroup/ciphertrust-ansible-collection.git
cd ciphertrust-ansible-collection
```

2. Build the collection:

```bash
ansible-galaxy collection build
```

3. Install the collection:

```bash
ansible-galaxy collection install thalesgroup-ciphertrust-1.0.3.tar.gz
```

### Method 3: Install from Local Path

```bash
ansible-galaxy collection install -p ~/.ansible/collections -f path/to/ciphertrust-ansible-collection
```

## Directory Structure

After installation, the collection will be located at:

- **Galaxy**: `~/.ansible/collections/ansible_collections/thalesgroup/ciphertrust/`
- **Local**: `./collections/ansible_collections/thalesgroup/ciphertrust/`

## Verification

Verify the installation:

```bash
ansible-galaxy collection list thalesgroup.ciphertrust
```

Expected output:

```
thalesgroup.ciphertrust 1.0.3
```

## Next Steps

- [Configuration](configuration.md)
- [Quick Start](quick-start.md)
