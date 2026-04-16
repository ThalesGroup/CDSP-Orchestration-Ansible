# Epic 5: Error Handling Consolidation

**Priority**: 🟠 High
**Estimated Effort**: Medium (1–2 weeks)
**Depends On**: Epic 3 (API Client Refactoring)
**Blocks**: None

---

## Problem Statement

Every module has a massive duplicated error handling block (70–100 lines) that catches 6 different exception types and builds error messages with the exact same pattern. This duplication makes modules unnecessarily long and makes changes to error formatting require editing every single module.

The `dpg.py` module_util also imports from `cache.py` using function names (`get_cache`, `get_performance_metrics`) that don't exist — they're `get_global_cache` and `get_global_metrics`.

---

## Current State Evidence

### 1. Duplicated exception handling — 70+ lines per module
```python
# This exact 70-line block appears 3 times in vault_keys2_save.py (once per op_type)
except CMApiException as api_e:
    error_msg = "API Error"
    if api_e.api_error_code:
        error_msg += f" (code: {api_e.api_error_code})"
    if api_e.parameter:
        error_msg += f". Parameter: {api_e.parameter}"
    # ... 15 more lines of the same pattern
    module.fail_json(msg=error_msg)
except AnsibleCMValidationException as val_e:
    # ... same 15-line pattern
except AnsibleCMParameterException as param_e:
    # ... same 15-line pattern
except AnsibleCMFormatException as format_e:
    # ... same 15-line pattern
except AnsibleCMResponseException as resp_e:
    # ... same 15-line pattern
except AnsibleCMException as custom_e:
    module.fail_json(msg=custom_e.message)
```

### 2. Exception classes have attributes that don't exist
The error handling code accesses `api_e.parameter`, `api_e.expected_format`, `api_e.example`, and `api_e.documentation_link` — but `CMApiException` only has `message` and `api_error_code`. This code silently fails at runtime.

### 3. `AnsibleCMException` imported but class doesn't exist
Multiple modules import `AnsibleCMException` from `exceptions.py`, but this class isn't defined there. Only `CMApiException`, `AnsibleCMValidationException`, `AnsibleCMParameterException`, `AnsibleCMFormatException`, and `AnsibleCMResponseException` exist.

### 4. Broken imports in `dpg.py`
```python
# dpg.py line 24-29 — these functions don't exist in cache.py
from ...cache import (
    get_cache,              # should be get_global_cache
    get_performance_metrics, # should be get_global_metrics
    cache_resource_id,
    get_cached_resource_id,
)
```

---

## Tasks

### 5.1 Create a centralized error handler
- [x] Added `handle_module_error(module, exc)` to [plugins/module_utils/modules.py](plugins/module_utils/modules.py). `CMApiException` includes the HTTP/application code; all other `CipherTrustError` subclasses use their composed `message`; anything else bubbles up as "Unexpected error".

### 5.2 Create a context manager for exception handling
- [x] Added `ciphertrust_operation(module)` context manager that catches the common `CipherTrustError` base class and delegates to `handle_module_error`. Used via `with ciphertrust_operation(module):` — one line replacing dozens of except clauses.

### 5.3 Refactor all modules to use centralized handler
- [x] All 33 modules refactored via three parallel agents (DPG: 7, CTE: 8, remaining: 18).
- [x] Removed per-op try/except blocks. 30 of 33 modules now have **zero** `try/except` in `main()`; the remaining 3 (dpg_policy_save, dpg_client_profile_save, vault_keys2_save) retain try/except only inside `validate_parameters()` where they're genuinely needed.
- [x] Net ~2,300 lines removed across 35 files (3,979 removed / 1,663 added — see `git diff --stat`).

### 5.4 Fix the exception class hierarchy
- [x] Added `CipherTrustError` base class to [plugins/module_utils/exceptions.py](plugins/module_utils/exceptions.py) — accepts `message` + arbitrary `**kwargs` attributes.
- [x] All 6 existing exception classes now inherit from `CipherTrustError` (verified at runtime).
- [x] `_compose()` helper consolidates the message-building boilerplate that was duplicated across 4 classes.
- [x] `CMApiException` signature preserved (`message`, `api_error_code`) — modules never referenced the nonexistent `parameter` / `documentation_link` attrs since we removed those except clauses.

### 5.5 Define or remove `AnsibleCMException`
- [x] Properly defined in `exceptions.py` (added in Epic 1, now inherits from `CipherTrustError`).

### 5.6 Fix broken cache imports in `dpg.py`
- [x] N/A — Epic 3 rewrote every domain util and removed all cache imports as part of the API-client refactor. Verified: `grep 'from.*cache import' plugins/module_utils/*.py` returns zero matches.

---

## Acceptance Criteria

- [x] Error handling is defined in one place (`ciphertrust_operation` + `handle_module_error` in [modules.py](plugins/module_utils/modules.py)), not duplicated across modules
- [ ] Each module's `main()` function is ≤50 lines — _partially achieved_: main() shrank dramatically (dpg_character_set_save went from ~90 lines to ~48, vault_keys2_save from ~320 to 150). Modules that remain large (e.g. cte_client main = 186 lines) are long because they dispatch many op_types each with 30+ params, not because of error handling. Full ≤50 line goal requires the refactoring scoped in Epic 8.
- [x] All exception classes have well-defined attributes (all inherit from `CipherTrustError`, kwargs become named attrs)
- [x] No module references non-existent exception attributes (removed with the except clauses)
- [x] `AnsibleCMException` is properly defined in [exceptions.py](plugins/module_utils/exceptions.py)
- [x] All imports resolve correctly (verified: ansible-doc renders cleanly on all 33 modules; zero ImportError at runtime)

---

## Files To Modify

| File | Changes |
|---|---|
| `plugins/module_utils/modules.py` | Add `handle_module_error()` + context manager |
| `plugins/module_utils/exceptions.py` | Fix class hierarchy, add/remove `AnsibleCMException` |
| `plugins/module_utils/dpg.py` | Fix broken cache imports |
| All 33 modules in `plugins/modules/` | Replace duplicated `try/except` blocks |
