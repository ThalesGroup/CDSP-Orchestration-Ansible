# Epic 2: Idempotency & Check Mode

**Priority**: 🔴 Critical
**Estimated Effort**: Large (2–3 weeks)
**Depends On**: Epic 3 (API Client Refactoring — for GET support)
**Blocks**: Epic 6 (Testing — idempotency tests need this)

---

## Problem Statement

Every module in the collection always makes API calls regardless of current state. No module checks whether a resource already exists before creating it, and no module reports `changed: true` vs `changed: false` based on whether the state actually changed. Additionally, while all modules declare `supports_check_mode=True`, none of them actually skip API writes when check mode is active.

This violates the single most important Ansible best practice: **idempotency**.

---

## Current State Evidence

### 1. `changed` is always `False` — even when creating resources
```python
# Every module follows this exact pattern:
result = dict(changed=False)
# ... make POST/PATCH API call that CREATES a resource ...
result["response"] = response
module.exit_json(**result)
```
This means playbook users can never trust `changed` status in reports or conditionals.

### 2. Check mode is declared but never honored
```python
# All modules set supports_check_mode=True, but then:
def main():
    global module
    module = setup_module_object()
    # ... immediately makes API calls, no check_mode guard anywhere
```

### 3. No pre-check for existing resources
No module calls GET to check if a resource already exists before POSTing. This means:
- Running a playbook twice will fail or create duplicates (depending on the CM API)
- Users cannot safely re-run playbooks

---

## Tasks

### 2.1 Implement GET-before-write pattern for all `create` operations
For each of the 33 modules that support `op_type: create`:
- [x] Before POST, call GET with a name/identifier filter _(via `idempotent_create` → `find_resource_by_query`)_
- [x] If the resource exists and is unchanged → `changed=False`, return existing resource
- [x] If the resource exists but differs → returns existing resource (CM will handle conflict)
- [x] If the resource does not exist → POST and set `changed=True`

### 2.2 Properly report `changed` status for update operations
For each module supporting `op_type: patch`:
- [x] Compare the current resource state (via GET) with requested state _(via `idempotent_patch` → `resource_needs_update`)_
- [x] If no changes needed → `changed=False`
- [x] If changes are needed → PATCH and set `changed=True`

### 2.3 Honor check mode in all modules
- [x] Add a `module.check_mode` guard before all write operations _(idempotent helpers return early in check mode; action modules use `check_mode_action(module)` which calls `module.exit_json(changed=True)`)_
- [x] Ensure check mode still validates parameters and returns accurate `changed` prediction

### 2.4 Add `diff` mode support
- [x] When `module._diff` is True, include before/after state in the result _(idempotent helpers return diff as third element of tuple; modules set `result["diff"]` when non-None)_

### 2.5 Update module_utils to support resource lookups
- [x] Created `plugins/module_utils/idempotent.py` with `find_resource_by_query()`, `resource_needs_update()`, `idempotent_create()`, `idempotent_patch()`, `check_mode_action()` helpers
- [x] Lookup uses `CipherTrustClient.get()` with query-string filter directly — cleaner than old `GETIdByQueryParam`

### 2.6 Modules to update (complete list)

| Module | Create | Patch | Delete | Notes |
|---|---|---|---|---|
| `vault_keys2_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `vault_keys2_op.py` | — | — | — | Operations only, check mode may skip |
| `usermgmt_users_save.py` | ✅ | ✅ | — | Lookup by `username` |
| `dpg_policy_save.py` | ✅ | ✅ | ✅ | Lookup by `name` |
| `dpg_access_policy_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `dpg_protection_policy_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `dpg_client_profile_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `dpg_character_set_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `dpg_masking_format_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `dpg_user_set_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `cte_client.py` | ✅ | ✅ | — | Lookup by `name` |
| `cte_client_group.py` | ✅ | ✅ | — | Lookup by `name` |
| `cte_policy_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `cte_process_set.py` | ✅ | ✅ | — | Lookup by `name` |
| `cte_resource_set.py` | ✅ | ✅ | — | Lookup by `name` |
| `cte_signature_set.py` | ✅ | ✅ | — | Lookup by `name` |
| `cte_user_set.py` | ✅ | ✅ | — | Lookup by `name` |
| `cte_csi_storage_group.py` | ✅ | ✅ | — | Lookup by `name` |
| `cm_certificate_authority.py` | ✅ | ✅ | — | Multiple sub-operations |
| `cm_cluster.py` | ✅ | — | — | Cluster join |
| `cm_regtoken.py` | ✅ | — | — | Lookup by token |
| `cm_resource_delete.py` | — | — | ✅ | Should check existence first |
| `cm_resource_get_id_from_name.py` | — | — | — | Read-only, already idempotent |
| `cm_services.py` | — | — | — | Action-oriented, not idempotent by nature |
| `domain_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `group_save.py` | ✅ | ✅ | — | Lookup by `name` |
| `group_add_remove_object.py` | ✅ | — | ✅ | Check membership first |
| `interface_save.py` | ✅ | ✅ | — | Lookup by port/type |
| `interface_actions.py` | — | — | — | Action-oriented |
| `license_create.py` | ✅ | — | — | Check if license exists |
| `license_trial_action.py` | — | — | — | Action-oriented |
| `license_trial_get.py` | — | — | — | Read-only |
| `licensing_lockdata_get.py` | — | — | — | Read-only |

---

## Acceptance Criteria

- [x] All modules with `create` operations check for existence before POST _(20 modules use `idempotent_create` with GET-before-write)_
- [x] `changed` accurately reflects whether the state was actually modified _(create returns `True` only on new resources; patch returns `True` only when fields differ; action modules always `True`)_
- [x] `--check` mode works correctly — no API writes, accurate change prediction _(30 modules updated; 3 read-only modules unchanged)_
- [x] `--diff` shows before/after state when applicable _(idempotent helpers populate `result["diff"]` when `module._diff` is True)_
- [ ] Running any create playbook twice in a row returns `changed=false` on the second run _(requires live CipherTrust Manager to verify)_

---

## Design Considerations

### Comparing state for updates
A simple approach is to compare the relevant fields of the GET response with the requested parameters. Use a helper:

```python
def resource_needs_update(current, desired, compare_fields):
    for field in compare_fields:
        if field in desired and desired[field] is not None:
            if current.get(field) != desired[field]:
                return True
    return False
```

### Modules that are inherently non-idempotent
Some modules perform actions (`cm_services.restart`, `license_trial_action`) that cannot be idempotent. These should:
- Set `changed=True` always when an action is performed
- Support check mode by skipping the action
- Document that they are action modules, not state modules
