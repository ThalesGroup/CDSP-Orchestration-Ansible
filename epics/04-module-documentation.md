# Epic 4: Module Documentation & RETURN Values

**Priority**: 🟠 High
**Estimated Effort**: Medium (1–2 weeks)
**Depends On**: None (can run in parallel with other epics)
**Blocks**: None

---

## Problem Statement

All 33 modules have empty `RETURN` blocks (`RETURN = """`), making it impossible for users to know what data the module returns. The `localNode` suboption documentation is copied verbatim into every module's `DOCUMENTATION` block (25 lines × 33 modules = 825 lines of duplication). Several `EXAMPLES` blocks use incorrect FQCNs.

---

## Current State Evidence

### 1. Empty RETURN blocks everywhere
```python
# plugins/modules/vault_keys2_save.py (line 819-820)
RETURN = """
"""
```
This is repeated in all 33 modules. Users running `ansible-doc thalesgroup.ciphertrust.vault_keys2_save` see no return value documentation.

### 2. Duplicated localNode documentation
The exact same 25-line `localNode` suboption block appears in every module's `DOCUMENTATION`. Any change must be made 33 times.

### 3. Incorrect FQCNs in EXAMPLES
```yaml
# vault_keys2_save.py (line 791) — uses wrong FQCN
- name: "Create Key"
  thalesgroup.ciphertrust.vault_keys2_create:  # ← wrong, should be vault_keys2_save
```

---

## Tasks

### 4.1 Populate RETURN blocks for all 33 modules — Original scope
For each module, document the actual API response structure. Reference the [CipherTrust Manager API docs](https://thalesdocs.com) for response schemas.

Example for `vault_keys2_save.py`:
```python
RETURN = r"""
response:
    description: The response from CipherTrust Manager API.
    returned: on success
    type: dict
    contains:
        id:
            description: Unique identifier of the key.
            type: str
            returned: always
            sample: "4ae2649a705e479589ef65759d3287f6"
        name:
            description: Name of the key.
            type: str
            returned: always
            sample: "myKey"
        algorithm:
            description: Cryptographic algorithm of the key.
            type: str
            returned: always
            sample: "aes"
        size:
            description: Bit length of the key.
            type: int
            returned: always
            sample: 256
        state:
            description: Current state of the key.
            type: str
            returned: always
            sample: "Active"
"""
```

### 4.1 Populate RETURN blocks for all 33 modules
- [x] Every module now has a populated `RETURN` block describing `changed`, `response` (with nested `id`/`name`/`uri`/`createdAt`/`updatedAt`), and `diff` (before/after, when applicable)
- [x] Three template shapes applied: STATE (create/patch), ACTION (non-idempotent ops), READ-ONLY (get operations)
- [x] `missing-return-legacy` warning eliminated for all 33 modules (was 30 before)

### 4.2 Create a shared documentation fragment for `localNode`
- [x] Created [plugins/doc_fragments/ciphertrust.py](plugins/doc_fragments/ciphertrust.py) with the common `localNode` documentation
- [x] Updated all 33 modules to use `extends_documentation_fragment: - thalesgroup.ciphertrust.ciphertrust`
- [x] Removed the duplicated 25-line block from each module (net ~ -800 lines of duplication)

### 4.3 Fix FQCN references in EXAMPLES blocks
- [x] Audited all 33 EXAMPLES blocks via programmatic grep
- [x] Ensured FQCN format `thalesgroup.ciphertrust.<module_name>` for every example
- [x] Fixed 3 mismatches: [vault_keys2_save.py](plugins/modules/vault_keys2_save.py) (2 uses of `vault_keys2_create` → `vault_keys2_save`), [vault_keys2_op.py](plugins/modules/vault_keys2_op.py) (`vault_keys2_create` → `vault_keys2_op`), [dpg_character_set_save.py](plugins/modules/dpg_character_set_save.py) (first example used `dpg_user_set_save` → corrected to `dpg_character_set_save`)

### 4.4 Improve DOCUMENTATION descriptions
- [x] Doc fragment provides richer description for `localNode` (TLS guidance, secret handling, Vault recommendation) than the per-module stubs that were there before
- [ ] Per-module short_description / description rewrites deferred — current short_descriptions are already module-specific (e.g. "Create and manage DPG character-sets") and `description` fields reference thalesdocs links; wholesale rewrites are out of scope for this epic's acceptance criteria
- [ ] `seealso` and `notes` additions deferred — not required by acceptance criteria

### 4.5 Modules to update (complete list)

| Module | RETURN | Doc Fragment | EXAMPLES Fix |
|---|---|---|---|
| `cm_certificate_authority.py` | ✅ | ✅ | ✅ |
| `cm_cluster.py` | ✅ | ✅ | ✅ |
| `cm_regtoken.py` | ✅ | ✅ | ✅ |
| `cm_resource_delete.py` | ✅ | ✅ | ✅ |
| `cm_resource_get_id_from_name.py` | ✅ | ✅ | ✅ |
| `cm_services.py` | ✅ | ✅ | ✅ |
| `cte_client.py` | ✅ | ✅ | ✅ |
| `cte_client_group.py` | ✅ | ✅ | ✅ |
| `cte_csi_storage_group.py` | ✅ | ✅ | ✅ |
| `cte_policy_save.py` | ✅ | ✅ | ✅ |
| `cte_process_set.py` | ✅ | ✅ | ✅ |
| `cte_resource_set.py` | ✅ | ✅ | ✅ |
| `cte_signature_set.py` | ✅ | ✅ | ✅ |
| `cte_user_set.py` | ✅ | ✅ | ✅ |
| `domain_save.py` | ✅ | ✅ | ✅ |
| `dpg_access_policy_save.py` | ✅ | ✅ | ✅ |
| `dpg_character_set_save.py` | ✅ | ✅ | ✅ |
| `dpg_client_profile_save.py` | ✅ | ✅ | ✅ |
| `dpg_masking_format_save.py` | ✅ | ✅ | ✅ |
| `dpg_policy_save.py` | ✅ | ✅ | ✅ |
| `dpg_protection_policy_save.py` | ✅ | ✅ | ✅ |
| `dpg_user_set_save.py` | ✅ | ✅ | ✅ |
| `group_add_remove_object.py` | ✅ | ✅ | ✅ |
| `group_save.py` | ✅ | ✅ | ✅ |
| `interface_actions.py` | ✅ | ✅ | ✅ |
| `interface_save.py` | ✅ | ✅ | ✅ |
| `license_create.py` | ✅ | ✅ | ✅ |
| `license_trial_action.py` | ✅ | ✅ | ✅ |
| `license_trial_get.py` | ✅ | ✅ | ✅ |
| `licensing_lockdata_get.py` | ✅ | ✅ | ✅ |
| `usermgmt_users_save.py` | ✅ | ✅ | ✅ |
| `vault_keys2_op.py` | ✅ | ✅ | ✅ |
| `vault_keys2_save.py` | ✅ | ✅ | ✅ |

---

## New Files

| File | Purpose |
|---|---|
| `plugins/doc_fragments/ciphertrust.py` | Shared documentation fragment for `localNode` |

---

## Acceptance Criteria

- [x] All 33 modules have populated, accurate `RETURN` blocks (STATE / ACTION / READ-ONLY templates applied by module type)
- [x] `ansible-doc thalesgroup.ciphertrust.<module>` shows return values for every module (verified: ran `ansible-doc` on all 33 modules — zero failures)
- [x] `localNode` documentation exists in exactly one place ([plugins/doc_fragments/ciphertrust.py](plugins/doc_fragments/ciphertrust.py)) and is pulled in via `extends_documentation_fragment`
- [x] All `EXAMPLES` blocks use correct FQCNs (3 mismatches fixed; all 33 audited)
- [x] `ansible-test sanity --test validate-modules` passes for documentation checks — zero `missing-return-legacy`, zero `invalid-documentation`, zero `no-log-needed` errors. Only `missing-gplv3-license` remains (Epic 10's scope).
