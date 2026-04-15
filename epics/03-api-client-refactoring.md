# Epic 3: API Client Refactoring

**Priority**: 🟠 High
**Estimated Effort**: Large (2–3 weeks)
**Depends On**: Epic 1 (Security Hardening)
**Blocks**: Epic 2 (Idempotency needs proper GET support)

---

## Problem Statement

The core API client (`plugins/module_utils/cm_api.py`) is the foundation of the entire collection, but it has critical architectural issues:

1. **8 nearly-identical HTTP functions** (`POSTData`, `PUTData`, `PATCHData`, `POSTWithoutData`, `DELETEByNameOrId`, `DeleteWithoutData`, `GETData`, `GETAPIData`) that duplicate error handling, session creation, and response parsing.
2. **JWT token fetched on EVERY API call** — `CMAPIObject()` calls `getJwt()` each time, meaning a playbook with 10 tasks makes 10 authentication calls before 10 actual API calls.
3. **`is_json()` function duplicated** in 3 different files (`cm_api.py`, `connection_management.py`, `dpg.py`).
4. **Inconsistent function naming** — `POSTData` vs `DeleteWithoutData` vs `GETIdByQueryParam` vs `GETAPIData`.
5. **Broken code** — `response.json` called on `dict` objects (line 159, 217, 276, 334, 392), `GETData` uses `response["resources"][0][id]` where `id` is the builtin (line 449).
6. **Connection type routing duplicated** — `connection_management.py` has the same `if/elif` chain duplicated twice across `createConnection()` and `patchConnection()`.

---

## Current Architecture

```
Module ──→ module_util (e.g., dpg.py) ──→ cm_api.py ──→ CMAPIObject() ──→ getJwt()
                                                                           ↑
                                                                    (called EVERY time)
```

Each module_util function (`createDPGPolicy`, `createAccessPolicy`, etc.) follows this pattern:
```python
def createSomeResource(**kwargs):
    request = {}
    for key, value in kwargs.items():
        if key != "node" and value is not None:
            request[key] = value
    payload = json.dumps(request)
    response = POSTData(payload=payload, cm_node=kwargs["node"], cm_api_endpoint="...", id="id")
    return response
```

This identical 10-line pattern is repeated 40+ times across module_utils.

---

## Tasks

### 3.1 Create a `CipherTrustClient` class to replace `CMAPIObject` and all HTTP functions
- [ ] Single class with methods: `get()`, `post()`, `put()`, `patch()`, `delete()`
- [ ] Session-level JWT caching with automatic refresh (respect CM token TTL)
- [ ] Centralized error handling and response parsing
- [ ] Respect `verify` parameter for TLS
- [ ] Accept optional `timeout` parameter

```python
class CipherTrustClient:
    def __init__(self, server_ip, user, password, verify=False, auth_domain_path=""):
        self._server_ip = server_ip
        self._token = None
        self._token_expires = 0
        self._verify = verify
        # ...
    
    def _ensure_authenticated(self):
        if self._token is None or time.time() > self._token_expires:
            self._token = self._get_jwt()
            self._token_expires = time.time() + 890  # ~15min, slightly under CM TTL
    
    def request(self, method, endpoint, data=None):
        self._ensure_authenticated()
        # ... single implementation of HTTP call + error handling
```

### 3.2 Refactor module_utils to use `CipherTrustClient`
- [ ] Update all domain-specific utils (`dpg.py`, `cte.py`, `keys2.py`, `groups.py`, etc.)
- [ ] Replace `POSTData`/`PATCHData`/etc. calls with `client.post()`/`client.patch()`/etc.
- [ ] Remove the duplicated `for key, value in kwargs.items()` pattern — use a helper

### 3.3 Add a `build_request_payload()` helper
- [ ] Single function to build API payloads from kwargs, excluding internal params
- [ ] Replace the 40+ instances of the manual loop pattern

### 3.4 Consolidate connection type routing
- [ ] Replace the duplicated `if/elif` chain in `connection_management.py` with a lookup dictionary:
  ```python
  CONNECTION_ENDPOINTS = {
      "aws": "connectionmgmt/services/aws/connections",
      "azure": "connectionmgmt/services/azure/connections",
      # ...
  }
  ```

### 3.5 Fix missing `/` in `patchConnection` endpoint URLs
- [ ] Lines 114–138 in `connection_management.py` are missing `/` before `connection_id` for several types (hadoop, ldap, oidc, oracle, scp, smb, salesforce, syslog, luna_nw_hsm)

### 3.6 Remove dead code and commented-out code
- [ ] Delete `GETIdByName()` (`cm_api.py` line 522 — marked "outdated")
- [ ] Delete commented-out `requests` exception handling (lines 605–612)
- [ ] Remove `from ansible.module_utils.basic import env_fallback` and other commented imports

### 3.7 Eliminate duplicated `is_json()` function
- [ ] Keep one copy in `cm_api.py` (or a shared utility)
- [ ] Import it in `connection_management.py` and `dpg.py`

### 3.8 Fix broken code paths
- [ ] `PUTData` line 159: `response.json` should be `response` (already a dict)
- [ ] `GETData` line 449: `response["resources"][0][id]` — `id` is the Python builtin, should be `"id"`
- [ ] `GETIdByName` line 545: `response.json()` — response is already a dict
- [ ] `GETAPIData` line 486: Same `response.json()` bug

---

## Acceptance Criteria

- [ ] All API calls go through a single `CipherTrustClient` class
- [ ] JWT tokens are cached per session, not fetched per API call
- [ ] A playbook with 10 tasks makes ≤2 authentication calls (initial + 1 refresh at most)
- [ ] Zero duplicated `is_json()` functions
- [ ] All broken code paths (`response.json`, `[id]` builtin) are fixed
- [ ] Connection type routing uses a lookup dictionary, not `if/elif` chains
- [ ] All dead/commented code is removed

---

## Files To Modify

| File | Changes |
|---|---|
| `plugins/module_utils/cm_api.py` | Replace with `CipherTrustClient` class |
| `plugins/module_utils/connection_management.py` | Use lookup dict + new client |
| `plugins/module_utils/dpg.py` | Use new client, remove `is_json` |
| `plugins/module_utils/cte.py` | Use new client |
| `plugins/module_utils/keys2.py` | Use new client |
| `plugins/module_utils/groups.py` | Use new client |
| `plugins/module_utils/users.py` | Use new client |
| `plugins/module_utils/interfaces.py` | Use new client |
| `plugins/module_utils/domains.py` | Use new client |
| `plugins/module_utils/cluster.py` | Use new client |
| `plugins/module_utils/ca.py` | Use new client |
| `plugins/module_utils/regtokens.py` | Use new client |
| `plugins/module_utils/services.py` | Use new client |
| `plugins/module_utils/licensing.py` | Use new client |

---

## Migration Strategy

1. Create `CipherTrustClient` alongside existing functions (backward compatible)
2. Migrate one module_util at a time, starting with the smallest (`services.py`)
3. Add integration test after each migration to verify behavior
4. Once all utils are migrated, delete old functions
