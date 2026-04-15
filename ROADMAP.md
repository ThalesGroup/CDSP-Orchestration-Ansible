# CDSP-Orchestration-Ansible — Production-Grade Roadmap

> **Goal**: Harden the existing `thalesgroup.ciphertrust` Ansible collection to production-grade quality before adding new API endpoints.
> This roadmap was produced by auditing every module, module_util, role, test, CI workflow, and documentation file in the repository against the standards used by major community collections (`community.general`, `amazon.aws`, `netbox.netbox`).

---

## Current State Summary

| Area | Status | Key Findings |
|---|---|---|
| **Modules** | 33 modules across CM, CTE, DPG, and Vault domains | Functional but missing idempotency, `check_mode` behavior, `no_log`, and `RETURN` documentation |
| **Module Utils** | 22 utility files | Massive code duplication in `cm_api.py`; JWT tokens fetched on every API call (no caching); inconsistent naming |
| **Roles** | 4 scaffolded roles (`crdp`, `cte4k8s`, `cte4u`, `dpg`) | Empty — tasks/defaults/meta are all placeholder stubs |
| **Tests** | 2 unit test files, 33 integration targets | Unit tests only cover `validation.py` and `cache.py`; no module-level unit tests; integration tests require live CM |
| **CI/CD** | 3 GitHub Actions workflows | No `ansible-lint`, no sanity test CI job on PR; integration tests rely on secrets |
| **Documentation** | `DOCUMENTATION` and `EXAMPLES` blocks present | `RETURN` blocks empty on all modules; `localNode` docs duplicated 33 times; role docs placeholder |
| **Security** | MIT-licensed but sanity-ignored | `no_log` never used for password fields; passwords visible in logs; 66 sanity ignore entries |
| **Sanity** | 5 ignore files (2.15–2.19) | Every module suppresses `missing-gplv3-license` and `no-log-needed` |

---

## Epics Overview

| # | Epic | Priority | Estimated Effort | Epic File |
|---|---|---|---|---|
| 1 | [Security Hardening](#epic-1-security-hardening) | 🔴 Critical | Medium | [`epics/01-security-hardening.md`](epics/01-security-hardening.md) |
| 2 | [Idempotency & Check Mode](#epic-2-idempotency--check-mode) | 🔴 Critical | Large | [`epics/02-idempotency-check-mode.md`](epics/02-idempotency-check-mode.md) |
| 3 | [API Client Refactoring](#epic-3-api-client-refactoring) | 🟠 High | Large | [`epics/03-api-client-refactoring.md`](epics/03-api-client-refactoring.md) |
| 4 | [Module Documentation & RETURN Values](#epic-4-module-documentation--return-values) | 🟠 High | Medium | [`epics/04-module-documentation.md`](epics/04-module-documentation.md) |
| 5 | [Error Handling Consolidation](#epic-5-error-handling-consolidation) | 🟠 High | Medium | [`epics/05-error-handling.md`](epics/05-error-handling.md) |
| 6 | [Testing Infrastructure](#epic-6-testing-infrastructure) | 🟡 Medium | Large | [`epics/06-testing-infrastructure.md`](epics/06-testing-infrastructure.md) |
| 7 | [CI/CD Pipeline Hardening](#epic-7-cicd-pipeline-hardening) | 🟡 Medium | Small | [`epics/07-cicd-pipeline.md`](epics/07-cicd-pipeline.md) |
| 8 | [Module Code Cleanup](#epic-8-module-code-cleanup) | 🟡 Medium | Medium | [`epics/08-module-code-cleanup.md`](epics/08-module-code-cleanup.md) |
| 9 | [Role Completion or Removal](#epic-9-role-completion-or-removal) | 🟢 Low | Small | [`epics/09-role-completion.md`](epics/09-role-completion.md) |
| 10 | [Collection Metadata & Packaging](#epic-10-collection-metadata--packaging) | 🟢 Low | Small | [`epics/10-collection-metadata.md`](epics/10-collection-metadata.md) |

---

## Recommended Execution Order

```
Phase 1 — Security & Correctness    (Epics 1, 2)
Phase 2 — Architecture & Quality    (Epics 3, 5, 8)
Phase 3 — Documentation & Testing   (Epics 4, 6, 7)
Phase 4 — Polish & Packaging        (Epics 9, 10)
──────── Ready for new API endpoints ────────
```

### Phase 1 — Security & Correctness (Weeks 1–3)

These are blockers for any production deployment.

- **Epic 1 — Security Hardening**: Add `no_log` to password fields, fix JWT token exposure, clear sanity ignore files.
- **Epic 2 — Idempotency & Check Mode**: Modules currently always make API calls regardless of current state. Every module must check-before-write and support `--check` mode properly.

### Phase 2 — Architecture & Quality (Weeks 3–6)

Eliminate technical debt that makes new endpoints hard to add.

- **Epic 3 — API Client Refactoring**: Collapse 8 nearly-identical HTTP helper functions into a single `CipherTrustAPI` class with session reuse and JWT caching.
- **Epic 5 — Error Handling Consolidation**: Replace the massive duplicated `except` blocks (70+ lines per module) with a single decorator/context manager.
- **Epic 8 — Module Code Cleanup**: Remove `global module` anti-pattern from all 33 modules, eliminate dead code, remove `AnsibleCMException` (now unused).

### Phase 3 — Documentation & Testing (Weeks 6–9)

- **Epic 4 — Module Documentation**: Fill in every empty `RETURN` block, eliminate duplicated `localNode` docs, fix FQCN in `EXAMPLES`.
- **Epic 6 — Testing Infrastructure**: Add unit tests for every module (mocked), add Molecule-based idempotency tests, add coverage reporting.
- **Epic 7 — CI/CD Pipeline**: Add `ansible-lint` to PR checks, add sanity test job, add matrix testing across Python/Ansible versions.

### Phase 4 — Polish & Packaging (Weeks 9–10)

- **Epic 9 — Role Completion or Removal**: Either populate the 4 empty roles with real tasks or remove them from the collection.
- **Epic 10 — Collection Metadata**: Fix `meta/main.yml` version mismatch, update `galaxy.yml` build_ignore, add changelogs fragment workflow.

---

## Success Criteria

- [ ] Zero sanity ignore entries (`tests/sanity/ignore-*.txt` files empty or removed)
- [ ] All modules pass `ansible-test sanity` without suppression
- [ ] Every module has populated `RETURN` documentation
- [ ] `no_log: true` set on all password/secret parameters
- [ ] Every module correctly reports `changed: true/false` based on actual state changes
- [ ] `--check` mode works correctly for all modules (no API writes)
- [ ] Unit test coverage ≥ 80% for `module_utils` and ≥ 60% per module
- [ ] CI pipeline runs `ansible-lint`, sanity tests, and unit tests on every PR
- [ ] JWT tokens are cached per-session (not fetched per API call)
- [ ] No `global module` statements in any module
- [ ] All roles either have real tasks or are removed from collection
- [ ] `meta/main.yml` and `meta/runtime.yml` agree on `requires_ansible` version

---

## Dependencies & Risks

| Risk | Mitigation |
|---|---|
| Idempotency requires GET-before-write, but not all CM API endpoints support filtering by name | Work with ThalesDocs to confirm query parameters; fall back to `name` search where possible |
| JWT caching needs careful TTL management | Use short TTL (900s default, matching CM token expiry) with automatic refresh |
| Sanity ignore removal may surface previously hidden issues | Run `ansible-test sanity` after each ignore removal batch; fix issues before removing next batch |
| Empty roles may have downstream users depending on namespace | Check Galaxy download stats before removing; deprecate first if users exist |
| Error handling refactor touches every module | Do this as a single atomic PR with full regression testing |

---

## References

- [Ansible Collection Developer Guide](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html)
- [Ansible Module Architecture](https://docs.ansible.com/ansible/latest/dev_guide/developing_program_flow_modules.html)
- [community.general Collection](https://github.com/ansible-collections/community.general) — reference for patterns
- [amazon.aws Collection](https://github.com/ansible-collections/amazon.aws) — reference for API client patterns
- [Ansible Test Guide](https://docs.ansible.com/ansible/latest/dev_guide/testing.html)
