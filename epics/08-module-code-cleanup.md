# Epic 8: Module Code Cleanup

**Priority**: 🟡 Medium
**Estimated Effort**: Medium (1–2 weeks)
**Depends On**: Epic 5 (Error Handling Consolidation)
**Blocks**: None

---

## Problem Statement

All 33 modules share the same anti-patterns: `global module` statement in `main()`, empty `validate_parameters()` functions, unused `result` variables in module_utils, and camelCase parameter names that are inconsistent with Ansible conventions.

---

## Current State Evidence

### 1. `global module` anti-pattern in all 33 modules
```python
# This exact pattern appears in every single module:
def main():
    global module                    # ← anti-pattern
    module = setup_module_object()
    validate_parameters(cm_services=module)  # ← does nothing
```
Using `global` is an unnecessary side effect. The module should be passed as a parameter.

### 2. Empty `validate_parameters()` functions
```python
# 33 modules have this exact function:
def validate_parameters(cm_services):
    return True
```
These functions do nothing but exist in every module.

### 3. Unused variables in module_utils
```python
# dpg.py, keys2.py, cte.py, etc. — 40+ functions have:
def createSomeResource(**kwargs):
    result = dict()     # ← never used, never returned
    request = {}
    # ...
    return response     # ← returns response, not result
```

### 4. camelCase parameter names
Ansible convention is `snake_case` for module parameters, but this collection uses `camelCase`:
- `localNode` → should be `local_node`
- `activationDate` → should be `activation_date`
- `usageMask` → should be `usage_mask`
- `wrapKeyName` → should be `wrap_key_name`

**Note**: Changing parameter names is a breaking change. Consider adding aliases for backward compatibility.

### 5. Massive `main()` functions
Some modules have `main()` functions spanning 300+ lines (e.g., `vault_keys2_save.py` lines 1358–1681) because they inline all the error handling and parameter extraction.

---

## Tasks

### 8.1 Remove `global module` from all 33 modules
- [ ] Change `main()` to pass `module` as a local variable
- [ ] Update all function calls to use the local variable
- [ ] Pattern:
  ```python
  # Before:
  def main():
      global module
      module = setup_module_object()
  
  # After:
  def main():
      module = setup_module_object()
  ```

### 8.2 Remove empty `validate_parameters()` functions
- [ ] Delete the function from all 33 modules
- [ ] Remove the call from `main()`
- [ ] If actual validation is needed, it should be in the `argument_spec` or the module_util

### 8.3 Remove unused `result` variables in module_utils
- [ ] Audit all functions in module_utils for unused `result = dict()`
- [ ] Remove them (40+ instances)

### 8.4 Standardize `main()` function pattern
After Epics 3 and 5, every module should follow this concise pattern:
```python
def main():
    module = ThalesCipherTrustModule(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )
    
    op_type = module.params["op_type"]
    result = {"changed": False}
    
    with ciphertrust_operation(module):
        if op_type == "create":
            result = handle_create(module)
        elif op_type == "patch":
            result = handle_patch(module)
        # ...
    
    module.exit_json(**result)
```

### 8.5 Add parameter aliases for snake_case (non-breaking)
- [ ] Add `aliases` to argument_spec for backward compatibility:
  ```python
  localNode=dict(type="dict", required=True, aliases=["local_node"]),
  ```
- [ ] Document that `camelCase` names are deprecated in favor of `snake_case`
- [ ] Add deprecation warnings for camelCase usage

### 8.6 Remove dead/unused imports
- [ ] Audit all modules and module_utils for unused imports
- [ ] Remove commented-out import lines in `modules.py` (lines 27–30)

### 8.7 Fix copyright year
- [ ] Update `(c) 2023 Thales Group` to `(c) 2023-2026 Thales Group` in all files

---

## Acceptance Criteria

- [ ] Zero `global module` statements in the codebase
- [ ] Zero empty `validate_parameters()` functions
- [ ] Zero unused `result = dict()` in module_utils
- [ ] No unused imports in any file
- [ ] Every module's `main()` follows the standardized pattern
- [ ] `snake_case` aliases available for all `camelCase` parameters
- [ ] No commented-out code in the codebase

---

## Files To Modify

All 33 modules in `plugins/modules/` and all 14 domain-specific files in `plugins/module_utils/`.
