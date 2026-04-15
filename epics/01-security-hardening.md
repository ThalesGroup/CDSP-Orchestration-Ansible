# Epic 1: Security Hardening

**Priority**: 🔴 Critical
**Estimated Effort**: Medium (1–2 weeks)
**Depends On**: None
**Blocks**: All other epics (must be done first)

---

## Problem Statement

The collection handles sensitive credentials (CipherTrust Manager admin passwords, API keys, JWT tokens) but lacks fundamental security controls. Passwords appear in Ansible logs, JWT tokens are not protected, and every module has its `no-log-needed` sanity check suppressed rather than fixed.

---

## Current State Evidence

### 1. No `no_log` on password fields
The `localNode` parameter contains `password` and is used by all 33 modules. Neither the `ThalesCipherTrustModule` base class nor any individual module marks this field `no_log: true`.

```python
# plugins/module_utils/modules.py (line 103)
password=dict(type="str", required=True),  # ← no no_log!
```

### 2. Sanity ignores masking the problem
Every module has two sanity suppressions:
```
# tests/sanity/ignore-2.19.txt (66 lines)
plugins/modules/cm_services.py validate-modules:no-log-needed
plugins/modules/cm_services.py validate-modules:missing-gplv3-license
# ... repeated 33 times each
```

### 3. JWT tokens logged in debug output
`cm_api.py` passes tokens in headers without any log protection. If `ANSIBLE_DEBUG=1` or a task fails, the bearer token appears in stdout.

### 4. Hardcoded `validate_certs=False`
Every API call in `cm_api.py` hardcodes `validate_certs=False`, ignoring the user's `verify` parameter from `localNode`.

---

## Tasks

### 1.1 Add `no_log` to password fields in `ThalesCipherTrustModule`
- [ ] In `plugins/module_utils/modules.py`, add `no_log=True` to the `password` field in `_ciphertrust_common_argument_spec()`
- [ ] Verify that password values no longer appear in `-vvvv` output

### 1.2 Add `no_log` to module-level password parameters
- [ ] `vault_keys2_save.py` has a top-level `password` parameter (for PKCS#12). Add `no_log=True`
- [ ] `usermgmt_users_save.py` — user creation password. Add `no_log=True`
- [ ] Audit all 33 modules for any other sensitive parameters (secrets, tokens, certificates)

### 1.3 Respect the `verify` parameter for TLS validation
- [ ] In `CMAPIObject()` (cm_api.py, line 615), use `node["verify"]` instead of hardcoded `False`
- [ ] Pass `verify` through all API functions (`POSTData`, `PATCHData`, `GETData`, etc.)
- [ ] Add `verify` as a parameter to the `getJwt()` function

### 1.4 Protect JWT tokens from accidental logging
- [ ] Store the token in the session object without exposing it in string representations
- [ ] Ensure the `Authorization` header is excluded from any debug/error output

### 1.5 Clear sanity ignore files for `no-log-needed`
- [ ] Remove all 33 `validate-modules:no-log-needed` lines from each of the 5 ignore files
- [ ] Run `ansible-test sanity --test validate-modules` to confirm zero new failures
- [ ] Keep `missing-gplv3-license` ignores for now (addressed in Epic 10)

### 1.6 Add sensitive data handling documentation
- [ ] Add a "Security" section to the collection `README.md` explaining:
  - How credentials are handled
  - Recommendation to use Ansible Vault for password storage
  - Recommendation to enable TLS verification in production

---

## Acceptance Criteria

- [ ] `no_log: true` is set on every password/secret parameter across all modules
- [ ] `ansible-test sanity --test validate-modules` passes without any `no-log-needed` ignores
- [ ] Running a playbook with `-vvvv` does NOT show any passwords or JWT tokens in output
- [ ] The `verify` parameter from `localNode` is respected for TLS certificate validation
- [ ] All 5 sanity ignore files have the 33 `no-log-needed` lines removed

---

## Files To Modify

| File | Changes |
|---|---|
| `plugins/module_utils/modules.py` | Add `no_log=True` to password field |
| `plugins/module_utils/cm_api.py` | Respect `verify` param, protect JWT tokens |
| `plugins/modules/vault_keys2_save.py` | Add `no_log=True` to `password` param |
| `plugins/modules/usermgmt_users_save.py` | Add `no_log=True` to `password` param |
| `tests/sanity/ignore-2.1[5-9].txt` | Remove `no-log-needed` lines |
| `README.md` | Add security section |
