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
- [ ] Add a `handle_module_error(module, exception)` function to `modules.py`:
  ```python
  def handle_module_error(module, exc):
      """Convert any CipherTrust exception to a module failure."""
      if isinstance(exc, CMApiException):
          msg = f"API Error (code: {exc.api_error_code}): {exc.message}"
      elif isinstance(exc, (AnsibleCMValidationException, AnsibleCMParameterException,
                           AnsibleCMFormatException, AnsibleCMResponseException)):
          msg = str(exc)
      else:
          msg = f"Unexpected error: {str(exc)}"
      module.fail_json(msg=msg)
  ```

### 5.2 Create a context manager or decorator for exception handling
- [ ] Option A — Context manager:
  ```python
  @contextmanager
  def ciphertrust_operation(module):
      try:
          yield
      except (CMApiException, AnsibleCMValidationException, ...) as exc:
          handle_module_error(module, exc)
  ```
- [ ] Option B — Decorator:
  ```python
  def ciphertrust_error_handler(func):
      @wraps(func)
      def wrapper(module, *args, **kwargs):
          try:
              return func(module, *args, **kwargs)
          except (...) as exc:
              handle_module_error(module, exc)
      return wrapper
  ```

### 5.3 Refactor all modules to use centralized handler
- [ ] Replace the 70-line `try/except` blocks in all 33 modules with the context manager or decorator
- [ ] Each module's main block should shrink from ~100 lines to ~20 lines

### 5.4 Fix the exception class hierarchy
- [ ] Add a common base class for all custom exceptions:
  ```python
  class CipherTrustError(Exception):
      """Base exception for all CipherTrust errors."""
      def __init__(self, message, **kwargs):
          self.message = message
          for k, v in kwargs.items():
              setattr(self, k, v)
          super().__init__(message)
  ```
- [ ] Make all exceptions inherit from it
- [ ] Remove references to non-existent attributes (`parameter`, `documentation_link`, etc. on `CMApiException`)

### 5.5 Define or remove `AnsibleCMException`
- [ ] Either add the class to `exceptions.py` or remove all references to it from modules and module_utils

### 5.6 Fix broken cache imports in `dpg.py`
- [ ] Replace `get_cache` with `get_global_cache`
- [ ] Replace `get_performance_metrics` with `get_global_metrics`
- [ ] Or, add the missing function aliases to `cache.py`

---

## Acceptance Criteria

- [ ] Error handling is defined in one place, not duplicated across modules
- [ ] Each module's `main()` function is ≤50 lines (after this + Epic 8)
- [ ] All exception classes have well-defined attributes
- [ ] No module references non-existent exception attributes
- [ ] `AnsibleCMException` is either properly defined or completely removed
- [ ] All imports resolve correctly (no `ImportError` at runtime)

---

## Files To Modify

| File | Changes |
|---|---|
| `plugins/module_utils/modules.py` | Add `handle_module_error()` + context manager |
| `plugins/module_utils/exceptions.py` | Fix class hierarchy, add/remove `AnsibleCMException` |
| `plugins/module_utils/dpg.py` | Fix broken cache imports |
| All 33 modules in `plugins/modules/` | Replace duplicated `try/except` blocks |
