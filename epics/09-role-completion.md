# Epic 9: Role Completion or Removal

**Priority**: 🟢 Low
**Estimated Effort**: Small (3–5 days)
**Depends On**: None
**Blocks**: None

---

## Problem Statement

The collection contains 4 roles (`crdp`, `cte4k8s`, `cte4u`, `dpg`) that are completely empty scaffolds. All tasks files contain only a comment, all defaults are empty, and the `meta/main.yml` files still have placeholder text (`author: your name`, `license: license (GPL-2.0-or-later, MIT, etc)`).

Empty roles bloat the collection package, confuse users, and fail Galaxy quality checks.

---

## Current State Evidence

```yaml
# roles/dpg/tasks/main.yml (complete file)
---
# tasks file for dpg

# roles/dpg/defaults/main.yml (complete file)
---
# defaults file for dpg

# roles/dpg/meta/main.yml
galaxy_info:
  author: your name
  description: your role description
  company: your company (optional)
  license: license (GPL-2.0-or-later, MIT, etc)
  min_ansible_version: 2.1
  galaxy_tags: []
```

All 4 roles (`crdp`, `cte4k8s`, `cte4u`, `dpg`) are identical in this regard.

---

## Decision Required

**Option A: Populate the roles with real tasks**
- Roles would use the collection's modules to set up complete scenarios
- Example: The `dpg` role would configure a full DPG pipeline (key, protection policy, access policy, client profile, DPG policy)
- Provides value to users who want turnkey solutions

**Option B: Remove the roles entirely**
- Simplifies the collection
- Example playbooks in `playbooks/` already serve as usage guides
- Fewer things to test and maintain

**Option C: Keep 1–2 roles, remove the rest**
- The `dpg` role is the most common use case — populate it as a reference
- Remove the more specialized `crdp`, `cte4k8s`, `cte4u` roles

---

## Tasks (if populating roles)

### 9.1 Populate `dpg` role
- [ ] `tasks/main.yml` — full DPG setup workflow using collection modules
- [ ] `defaults/main.yml` — all configurable variables with sensible defaults
- [ ] `meta/main.yml` — proper metadata (author, license, platforms, tags)
- [ ] `meta/argument_specs.yml` — role argument validation
- [ ] `README.md` — usage instructions and variable documentation
- [ ] `vars/main.yml` — internal role variables (if any)

### 9.2 Populate `cte4k8s` role (if keeping)
- [ ] Full CTE for Kubernetes setup workflow
- [ ] Similar structure as `dpg` role

### 9.3 Populate `cte4u` role (if keeping)
- [ ] Full CTE for Unix/Linux setup workflow

### 9.4 Populate `crdp` role (if keeping)
- [ ] Full CRDP setup workflow

### 9.5 Add `meta/argument_specs.yml` to all populated roles
- [ ] Define all role variables with types, descriptions, and defaults
- [ ] This enables automatic documentation generation and fail-fast validation

### 9.6 Add role-level tests
- [ ] Create `molecule/` scenario for each populated role
- [ ] Test with `molecule test` or `ansible-test integration`

---

## Tasks (if removing roles)

### 9.7 Remove empty role directories
- [ ] Delete `roles/crdp/`, `roles/cte4k8s/`, `roles/cte4u/`, `roles/dpg/`
- [ ] Update `galaxy.yml` if roles are referenced
- [ ] Update `README.md` to remove role references

---

## Acceptance Criteria

- [ ] No empty scaffold roles exist in the collection
- [ ] If populated: roles have real tasks, argument_specs, defaults, and documentation
- [ ] If removed: roles directory is clean or absent
- [ ] `meta/main.yml` files have no placeholder text
- [ ] Role tests pass (if populated)
