# Contributing to ThalesGroup CipherTrust Ansible Collection

Thank you for your interest in contributing to the ThalesGroup CipherTrust Ansible Collection! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to the ThalesGroup Code of Conduct. By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before reporting a bug:
1. Check if the issue already exists
2. Verify you're using the latest version
3. Test with the latest release

To report a bug:
1. Use GitHub Issues
2. Include:
   - Description of the issue
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment details (Ansible version, Python version, etc.)
   - Relevant logs

### Suggesting Enhancements

To suggest an enhancement:
1. Use GitHub Issues
2. Include:
   - Description of the enhancement
   - Use case
   - Potential implementation approach
   - Any relevant examples

### Contributing Code

#### Pull Request Process

1. Fork the repository
2. Create a branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Run tests
5. Update documentation
6. Commit changes (`git commit -m 'Add some AmazingFeature'`)
7. Push to branch (`git push origin feature/AmazingFeature`)
8. Open a Pull Request

#### Code Style

- Follow Ansible best practices
- Use consistent naming conventions
- Add documentation for all modules and roles
- Write clear commit messages

#### Testing

1. Run sanity tests:
   ```bash
   ansible-test sanity --docker -v
   ```

2. Run integration tests:
   ```bash
   ansible-test integration --docker -v
   ```

3. Run unit tests:
   ```bash
   ansible-test units --docker -v
   ```

#### Documentation

All new features must include:
- Module documentation
- Role documentation
- Example playbooks
- Troubleshooting information

## Development Setup

### Prerequisites

- Python 3.7+
- Ansible 2.15+
- Git

### Clone Repository

```bash
git clone https://github.com/thalesgroup/ciphertrust-ansible-collection.git
cd ciphertrust-ansible-collection
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Tests

```bash
ansible-test sanity
ansible-test units
ansible-test integration
```

## Documentation

### Building Documentation

```bash
pip install mkdocs
mkdocs build
```

### Local Documentation Server

```bash
mkdocs serve
```

## Community

- [Discussions](https://github.com/thalesgroup/ciphertrust-ansible-collection/discussions)
- [Issues](https://github.com/thalesgroup/ciphertrust-ansible-collection/issues)
- [Pull Requests](https://github.com/thalesgroup/ciphertrust-ansible-collection/pulls)

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- README.md
- GitHub Contributors page

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
