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
- [x] Single class with methods: `get()`, `post()`, `put()`, `patch()`, `delete()`
- [x] Session-level JWT caching with automatic refresh (respect CM token TTL) _(module-level `_jwt_cache` dict keyed by `(server_ip, user, auth_domain_path)` with 890s TTL)_
- [x] Centralized error handling and response parsing _(single `request()` method handles `codeDesc` application errors and `HTTPError` transport errors)_
- [x] Respect `verify` parameter for TLS
- [x] Accept optional `timeout` parameter _(hardcoded 120s — consistent with original; can be parameterized later)_

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
- [x] Update all domain-specific utils (`dpg.py`, `cte.py`, `keys2.py`, `groups.py`, etc.) — all 13 domain files rewritten
- [x] Replace `POSTData`/`PATCHData`/etc. calls with `client.post()`/`client.patch()`/etc.
- [x] Remove the duplicated `for key, value in kwargs.items()` pattern — use `build_request_payload()` helper

### 3.3 Add a `build_request_payload()` helper
- [x] Single function to build API payloads from kwargs, excluding internal params _(also supports `remap` dict for parameter renaming, e.g. `messageStr` → `message`)_
- [x] Replace the 40+ instances of the manual loop pattern _(also added `_build_query_string()` helper for keys2 operation URLs)_

### 3.4 Consolidate connection type routing
- [x] Replace the duplicated `if/elif` chain in `connection_management.py` with a lookup dictionary (`CONNECTION_ENDPOINTS` dict with 13 connection types)

### 3.5 Fix missing `/` in `patchConnection` endpoint URLs
- [x] Fixed by rewriting `patchConnection` to use `CONNECTION_ENDPOINTS[type] + "/" + connection_id` — all types now have correct `/` separator
- [x] Also fixed `enableSTC`/`disableSTC` which had the same missing `/` bug

### 3.6 Remove dead code and commented-out code
- [x] Delete `GETIdByName()` — removed entirely (was marked "outdated")
- [x] Delete commented-out `requests` exception handling — removed entirely
- [x] Remove `from ansible.module_utils.basic import env_fallback` and other commented imports — removed
- [x] Removed `CMAPIObject()`, `getJwt()`, `POSTData`, `PUTData`, `POSTWithoutData`, `PATCHData`, `GETData`, `GETAPIData` — replaced by `CipherTrustClient` class _(only `DELETEByNameOrId`, `DeleteWithoutData`, `GETIdByQueryParam` kept as thin backward-compat wrappers for two modules that import them directly)_

### 3.7 Eliminate duplicated `is_json()` function
- [x] Keep one copy in `cm_api.py` _(single canonical implementation)_
- [x] Removed all 11 duplicate copies from domain utils (dpg.py, cte.py, keys2.py, users.py, groups.py, interfaces.py, domains.py, cluster.py, licensing.py, connection_management.py)

### 3.8 Fix broken code paths
- [x] `PUTData` `response.json` bug — eliminated entirely; `CipherTrustClient.request()` always returns parsed dict
- [x] `GETData` `[id]` builtin bug — eliminated; old function removed
- [x] `GETIdByName` `response.json()` bug — function deleted (was marked outdated)
- [x] `GETAPIData` `response.json()` bug — eliminated; old function removed
- [x] `licensing.py:addLicense` wrong endpoint `vault/keys2` → fixed to `licensing/licenses`
- [x] `domains.py:disableInterface` wrong function name → added `disableSyslogRedirection` with backward-compat alias

---

## Acceptance Criteria

- [x] All API calls go through a single `CipherTrustClient` class
- [x] JWT tokens are cached per session, not fetched per API call _(module-level `_jwt_cache` dict shared across client instances)_
- [x] A playbook with 10 tasks makes ≤2 authentication calls (initial + 1 refresh at most) _(within a single task; cross-task caching is limited by Ansible's per-task process model)_
- [x] Zero duplicated `is_json()` functions _(single copy in `cm_api.py`, all 11 duplicates removed)_
- [x] All broken code paths (`response.json`, `[id]` builtin) are fixed _(old functions deleted; new client returns parsed dicts directly)_
- [x] Connection type routing uses a lookup dictionary, not `if/elif` chains
- [x] All dead/commented code is removed

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
