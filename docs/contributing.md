# Contributing

`CONTRIBUTING.md` in the repository root is the authoritative guide, and this
page does not restate it. Keeping two copies is how the previous version of
this page came to describe test commands that no longer worked.

Read it here:
<https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/blob/main/CONTRIBUTING.md>

It covers reporting issues, pull requests, changelog fragments, commit
messages, naming conventions, sanity-test waivers, and how to run the unit,
sanity and integration suites.

## Building this documentation site

The one thing that belongs here rather than in `CONTRIBUTING.md`: these pages
are built with MkDocs.

```bash
pip install mkdocs mkdocs-material
mkdocs serve          # preview at http://127.0.0.1:8000
mkdocs build --strict # fail on a broken link or reference
```

The published site is built from `main` by the `docs-push` workflow and served
at <https://thalesgroup.github.io/CDSP-Orchestration-Ansible/branch/main/>.

Per-module reference pages are generated from the modules themselves, so they
are not edited here — change the `DOCUMENTATION` block in the module.

## Community

- [Issues](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/issues)
- [Pull Requests](https://github.com/ThalesGroup/CDSP-Orchestration-Ansible/pulls)
- [Thales Community Forum](https://supportportal.thalesgroup.com/community)
