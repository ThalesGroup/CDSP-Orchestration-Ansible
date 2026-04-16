# Branch Protection Required Status Checks

Configure the `main` branch protection rule in GitHub to require these checks:

- `ansible-lint`
- `sanity (py3.9, ansible-2.15)`
- `sanity (py3.10, ansible-2.16)`
- `sanity (py3.11, ansible-2.17)`
- `sanity (py3.12, ansible-2.18)`
- `units (py3.9, ansible-2.15)`
- `units (py3.10, ansible-2.16)`
- `units (py3.11, ansible-2.17)`
- `units (py3.12, ansible-2.18)`
- `build-collection`
- `changelog-lint`
