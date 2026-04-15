# Epic 7: CI/CD Pipeline Hardening

**Priority**: 🟡 Medium
**Estimated Effort**: Small (3–5 days)
**Depends On**: Epic 6 (Testing Infrastructure)
**Blocks**: None

---

## Problem Statement

The CI pipeline has only 3 workflows: docs deployment, integration tests, and static content. There is no `ansible-lint` job, no sanity test job on PRs, no unit test job, and no matrix testing across Python/Ansible versions. The integration test workflow also has a misconfigured `cd tests` step that will fail because `ansible-test` should run from the collection root.

---

## Current State Evidence

### 1. Missing CI jobs
| Job | Exists? | Notes |
|---|---|---|
| `ansible-lint` | ❌ | Not configured |
| Sanity tests (`ansible-test sanity`) | ❌ | Not in CI, only mentioned in README |
| Unit tests (`ansible-test units`) | ❌ | No CI job |
| Build/package validation | ❌ | `ansible-galaxy collection build` never tested |
| Python version matrix | ❌ | Only Python 3.9 |
| Ansible version matrix | ❌ | No matrix |

### 2. Integration test workflow issues
- Line 56: `cd tests` then `ansible-test integration` — `ansible-test` expects to run from collection root
- Secrets may not be configured, causing all integration tests to fail silently

### 3. No PR checks
The integration test workflow runs on push to `main` and PRs, but there's no lightweight check (lint, sanity, unit tests) that can run without secrets.

---

## Tasks

### 7.1 Add `ansible-lint` workflow
- [ ] Create `.github/workflows/lint.yml`:
  ```yaml
  name: Lint
  on: [push, pull_request]
  jobs:
    ansible-lint:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with:
            python-version: '3.10'
        - run: pip install ansible-lint
        - run: ansible-lint
  ```
- [ ] Create `.ansible-lint` config file with collection-appropriate rules

### 7.2 Add sanity test workflow
- [ ] Create `.github/workflows/sanity.yml` with matrix:
  ```yaml
  strategy:
    matrix:
      ansible-version: ['2.15', '2.16', '2.17', '2.18']
      python-version: ['3.9', '3.10', '3.11', '3.12']
  ```
- [ ] Run `ansible-test sanity --color yes -v`

### 7.3 Add unit test workflow
- [ ] Create `.github/workflows/unit-tests.yml`:
  ```yaml
  name: Unit Tests
  on: [push, pull_request]
  jobs:
    unit-tests:
      runs-on: ubuntu-latest
      strategy:
        matrix:
          python-version: ['3.9', '3.10', '3.11', '3.12']
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
        - run: pip install ansible pytest pytest-cov
        - run: ansible-test units --color yes -v --coverage
        - run: ansible-test coverage report
  ```

### 7.4 Add build validation workflow
- [ ] Validate that `ansible-galaxy collection build` succeeds on every PR
- [ ] Check that the built artifact has the expected structure and version

### 7.5 Fix integration test workflow
- [ ] Fix the `cd tests` issue — run from collection root
- [ ] Add a check for required secrets, skip gracefully if missing
- [ ] Add `continue-on-error: true` for workflows that depend on live CM

### 7.6 Add PR status checks
- [ ] Configure branch protection rules to require:
  - Lint passing
  - Sanity tests passing
  - Unit tests passing
  - Build validation passing

### 7.7 Add changelog validation
- [ ] Enforce changelogs fragment on PRs that modify `plugins/`
- [ ] Use `antsibull-changelog lint` in CI

---

## New Files

| File | Purpose |
|---|---|
| `.github/workflows/lint.yml` | ansible-lint on every PR |
| `.github/workflows/sanity.yml` | Sanity tests across Ansible matrix |
| `.github/workflows/unit-tests.yml` | Unit tests with coverage |
| `.github/workflows/build.yml` | Build validation |
| `.ansible-lint` | ansible-lint configuration |

---

## Acceptance Criteria

- [ ] Every PR runs: lint, sanity, unit tests, build validation
- [ ] Integration tests run on schedule and manual trigger (not required for PR merge)
- [ ] Matrix covers Python 3.9–3.12 and Ansible 2.15–2.18
- [ ] Build validation confirms `ansible-galaxy collection build` succeeds
- [ ] All workflow badges added to `README.md`
