# Epic 10: Collection Metadata & Packaging

**Priority**: 🟢 Low
**Estimated Effort**: Small (2–3 days)
**Depends On**: Epic 1 (Security — license sanity ignores)
**Blocks**: None

---

## Problem Statement

Collection metadata has several inconsistencies and missing best practices that affect packaging, discoverability, and maintainability.

---

## Current State Evidence

### 1. `meta/main.yml` and `meta/runtime.yml` disagree on Ansible version
```yaml
# meta/main.yml
requires_ansible: '>=2.9.10'    # ← old, doesn't match

# meta/runtime.yml
requires_ansible: '>=2.15.0'    # ← correct
```

### 2. `build_ignore` is minimal
```yaml
# galaxy.yml
build_ignore:
  - .gitignore
```
Missing common exclusions: `.github/`, `.vscode/`, `tests/`, `docs/`, `mkdocs.yml`, `run_tests.py`, `epics/`, `ROADMAP.md`, etc.

### 3. No changelog fragments workflow
The collection has `changelogs/` directory and `CHANGELOG.rst` but no `antsibull-changelog` configuration or fragment enforcement.

### 4. `missing-gplv3-license` sanity suppression
All 33 modules suppress this check. The collection uses MIT license which is valid — the ignore entries are correct but should be documented or the DOCUMENTATION blocks should include the license info.

### 5. No `MANIFEST.json` or `.github/CODEOWNERS`
Missing standard files for collection governance.

---

## Tasks

### 10.1 Fix `meta/main.yml` version
- [ ] Update `requires_ansible: '>=2.15.0'` to match `runtime.yml`
- [ ] Or delete `meta/main.yml` if it's not needed (it's for standalone roles, not collections)

### 10.2 Expand `build_ignore` in `galaxy.yml`
- [ ] Add exclusions:
  ```yaml
  build_ignore:
    - .gitignore
    - .github
    - .vscode
    - tests
    - docs
    - mkdocs.yml
    - run_tests.py
    - ROADMAP.md
    - epics
    - '*.pyc'
    - __pycache__
  ```

### 10.3 Configure `antsibull-changelog`
- [ ] Add `changelogs/config.yaml` for `antsibull-changelog`
- [ ] Document the changelog fragment workflow in `CONTRIBUTING.md`
- [ ] Add a CI check for changelog fragments on PRs

### 10.4 Address `missing-gplv3-license` sanity ignores
- [ ] Option A: Add GPL-3.0 license header to all modules (but collection is MIT)
- [ ] Option B: Keep the ignores but document why in a comment in each ignore file
- [ ] Option C: Add `license` field to each module's `DOCUMENTATION` block:
  ```yaml
  DOCUMENTATION = """
  ---
  module: cm_services
  license: MIT
  ```

### 10.5 Add `CODEOWNERS` file
- [ ] Create `.github/CODEOWNERS`:
  ```
  * @anugram
  plugins/modules/ @anugram
  ```

### 10.6 Update `galaxy.yml` for next release
- [ ] Bump version appropriately after all changes
- [ ] Update description if scope has changed
- [ ] Add any new dependencies (if applicable)

### 10.7 Validate collection packaging
- [ ] Run `ansible-galaxy collection build`
- [ ] Inspect the built artifact to confirm correct contents
- [ ] Test installation from the built tarball

### 10.8 Update `README.md`
- [ ] Add CI badges (lint, sanity, unit tests, build)
- [ ] Update compatibility matrix
- [ ] Add link to ROADMAP.md
- [ ] Fix typo on line 148: "Executes teh integration" → "Executes the integration"

---

## Acceptance Criteria

- [ ] `meta/main.yml` and `meta/runtime.yml` agree on `requires_ansible`
- [ ] `build_ignore` excludes test, docs, CI, and dev files
- [ ] `antsibull-changelog` is configured and documented
- [ ] License sanity ignores are documented or resolved
- [ ] `ansible-galaxy collection build` produces a clean package
- [ ] Built package installs and works correctly
- [ ] README has current badges, compatibility info, and no typos

---

## Files To Modify

| File | Changes |
|---|---|
| `meta/main.yml` | Fix `requires_ansible` version |
| `galaxy.yml` | Expand `build_ignore`, bump version |
| `changelogs/config.yaml` | New: antsibull-changelog config |
| `.github/CODEOWNERS` | New: code ownership |
| `CONTRIBUTING.md` | Add changelog fragment docs |
| `README.md` | Add badges, fix typos, update compat |
| `tests/sanity/ignore-2.1[5-9].txt` | Document license ignores |
