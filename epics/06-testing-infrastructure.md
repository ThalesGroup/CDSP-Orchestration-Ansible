# Epic 6: Testing Infrastructure

**Priority**: 🟡 Medium
**Estimated Effort**: Large (2–3 weeks)
**Depends On**: Epic 2 (Idempotency), Epic 3 (API Client Refactoring)
**Blocks**: None

---

## Problem Statement

The collection has 33 modules but only 2 unit test files — both for utility modules (`validation.py` and `cache.py`). There are zero unit tests for any of the 33 modules or 14 domain-specific module_utils. The integration tests require a live CipherTrust Manager instance, making them expensive and slow to run.

---

## Current State Evidence

### 1. Test coverage
| Area | Test Files | Coverage |
|---|---|---|
| `plugins/modules/` (33 modules) | 0 | 0% |
| `plugins/module_utils/` (22 utils) | 2 (`test_validation.py`, `test_performance.py`) | ~10% |
| Integration tests | 33 targets | Requires live CM |

### 2. Unit tests use `sys.path` hacks
```python
# tests/unit/test_validation.py (line 17)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "plugins", "module_utils"))
```
This is fragile and unnecessary — `ansible-test units` handles paths correctly.

### 3. No mocking infrastructure
There is no test helper or fixture for mocking the CipherTrust Manager API, making it impossible to unit test modules without a real server.

---

## Tasks

### 6.1 Create a module test helper/fixture
- [ ] Create `tests/unit/conftest.py` with:
  - Mock `ThalesCipherTrustModule` that captures `exit_json`/`fail_json` calls
  - Mock API responses for common endpoints
  - Reusable `localNode` fixture
  - Helper to run module's `main()` with mocked parameters

```python
# tests/unit/conftest.py
import pytest
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_module():
    """Create a mock ThalesCipherTrustModule."""
    module = MagicMock()
    module.check_mode = False
    module.params = {
        "localNode": {
            "server_ip": "test.example.com",
            "user": "admin",
            "password": "test123",
            "verify": False,
            "auth_domain_path": "",
        }
    }
    return module

@pytest.fixture
def mock_api_response():
    """Factory for creating mock API responses."""
    def _make_response(status_code=200, data=None):
        # ...
    return _make_response
```

### 6.2 Add unit tests for all module_utils
Priority order (by complexity and risk):
- [ ] `cm_api.py` — test all HTTP methods, error parsing, JWT caching
- [ ] `dpg.py` — test CRUD operations with mocked API
- [ ] `cte.py` — test CRUD operations with mocked API
- [ ] `keys2.py` — test create/patch/version operations
- [ ] `users.py` — test user CRUD operations
- [ ] `groups.py` — test group CRUD operations
- [ ] `connection_management.py` — test connection type routing
- [ ] `interfaces.py` — test interface operations
- [ ] `domains.py` — test domain operations
- [ ] `cluster.py` — test cluster operations
- [ ] `ca.py` — test CA operations
- [ ] `licensing.py` — test licensing operations
- [ ] `regtokens.py` — test registration tokens
- [ ] `services.py` — test service restart
- [ ] `modules.py` — test `ThalesCipherTrustModule` class
- [ ] `exceptions.py` — test exception classes and string representations
- [ ] `cache.py` — expand existing tests

### 6.3 Add unit tests for all modules
For each of the 33 modules, create tests covering:
- [ ] Successful `create` operation → `changed=True`
- [ ] `create` when resource already exists → `changed=False` (after Epic 2)
- [ ] Successful `patch` operation → `changed=True`
- [ ] `patch` with no changes → `changed=False` (after Epic 2)
- [ ] Check mode → no API calls, correct `changed` prediction
- [ ] Required parameter validation
- [ ] API error handling → `fail_json` with useful message

### 6.4 Add idempotency tests
- [ ] For each module with `create` op: run twice, assert second run returns `changed=False`
- [ ] For each module with `patch` op: run with same data twice, assert second returns `changed=False`

### 6.5 Improve integration test structure
- [ ] Add `teardown.yml` to each integration target (cleanup created resources)
- [ ] Add negative test cases (invalid parameters, API errors)
- [ ] Add `aliases` file to each target for test categorization

### 6.6 Add coverage reporting
- [ ] Configure `pytest-cov` for unit tests
- [ ] Set minimum coverage thresholds:
  - `module_utils/` ≥ 80%
  - `modules/` ≥ 60%
- [ ] Add coverage badge to `README.md`

### 6.7 Fix existing test imports
- [ ] Remove `sys.path.insert` hacks from `test_validation.py`
- [ ] Use proper `ansible_collections.thalesgroup.ciphertrust.plugins.module_utils` imports

---

## Test File Structure

```
tests/
├── unit/
│   ├── conftest.py                    # NEW: shared fixtures
│   ├── module_utils/                  # NEW: directory
│   │   ├── test_cm_api.py
│   │   ├── test_dpg.py
│   │   ├── test_cte.py
│   │   ├── test_keys2.py
│   │   ├── test_users.py
│   │   ├── test_groups.py
│   │   ├── test_exceptions.py
│   │   ├── test_modules.py
│   │   └── ...
│   ├── modules/                       # NEW: directory
│   │   ├── test_vault_keys2_save.py
│   │   ├── test_dpg_policy_save.py
│   │   ├── test_cte_client.py
│   │   ├── test_cm_services.py
│   │   └── ...
│   ├── test_validation.py             # EXISTING: fix imports
│   └── test_performance.py            # EXISTING: fix imports
```

---

## Acceptance Criteria

- [ ] Unit tests exist for every module_util file
- [ ] Unit tests exist for every module
- [ ] `module_utils/` coverage ≥ 80%
- [ ] `modules/` coverage ≥ 60%
- [ ] All tests run without a live CipherTrust Manager
- [ ] Integration tests have cleanup (teardown) for created resources
- [ ] `pytest` + `ansible-test units` both pass cleanly
