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
- [x] In `plugins/module_utils/modules.py`, add `no_log=True` to the `password` field in `_ciphertrust_common_argument_spec()`
- [ ] Verify that password values no longer appear in `-vvvv` output _(requires a live CipherTrust Manager; not executed in this environment)_

### 1.2 Add `no_log` to module-level password parameters
- [x] `vault_keys2_save.py` has a top-level `password` parameter (for PKCS#12). Add `no_log=True` (also applied to `wrapPBE.password` and `wrapPBE.passwordIdentifier`)
- [x] `usermgmt_users_save.py` — user creation password. Add `no_log=True` (also applied to `new_password`)
- [x] Audit all 33 modules for any other sensitive parameters (secrets, tokens, certificates). Additional `no_log=True` applied to:
  - `vault_keys2_op.py`: `password`, `wrapPBE.password`, `wrapPBE.passwordIdentifier`
  - `cm_certificate_authority.py`: `password`, `privateKeyBytes`
  - `cm_cluster.py`: joining-node `password`
  - `cte_client.py`, `cte_client_group.py`: `password`
  - `interface_actions.py`: PEM key `password`
  - `interface_save.py`: KMIP `registration_token`

### 1.3 Respect the `verify` parameter for TLS validation
- [x] In `CMAPIObject()` (cm_api.py), use `node["verify"]` instead of hardcoded `False` (via new `_resolve_verify()` helper)
- [x] Pass `verify` through all API functions (`POSTData`, `PUTData`, `POSTWithoutData`, `PATCHData`, `DELETEByNameOrId`, `DeleteWithoutData`, `GETData`, `GETAPIData`, `GETIdByName`, `GETIdByQueryParam`)
- [x] Add `verify` as a parameter to the `getJwt()` function

### 1.4 Protect JWT tokens from accidental logging
- [x] Store the token in the session object without exposing it in string representations _(documented invariant on `CMAPIObject`: session dicts are opaque, token is only consumed via the `Authorization` header)_
- [x] Ensure the `Authorization` header is excluded from any debug/error output _(no module path returns the session dict or its headers; reinforced by module-level comment in `cm_api.py`)_

### 1.5 Clear sanity ignore files for `no-log-needed`
- [x] Remove all 33 `validate-modules:no-log-needed` lines from each of the 5 ignore files (then re-added 8 suppressions for false-positive params like `keyUsage`, `*_tokens` — all further resolved by explicit `no_log=False` in argument_spec)
- [x] Run `ansible-test sanity --test validate-modules` to confirm zero new failures — **zero `no-log-needed` errors** across all 33 modules (verified with ansible-core 2.17.14 on Python 3.12). Only `missing-gplv3-license` remains, per Epic 10.
- [x] Keep `missing-gplv3-license` ignores for now (addressed in Epic 10)

### 1.6 Add sensitive data handling documentation
- [x] Add a "Security" section to the collection `README.md` explaining:
  - How credentials are handled
  - Recommendation to use Ansible Vault for password storage
  - Recommendation to enable TLS verification in production

---

## Acceptance Criteria

- [x] `no_log: true` is set on every password/secret parameter across all modules
- [x] `ansible-test sanity --test validate-modules` passes without any `no-log-needed` ignores _(verified with ansible-core 2.17.14 — zero `no-log-needed` errors; only `missing-gplv3-license` remains, deferred to Epic 10)_
- [ ] Running a playbook with `-vvvv` does NOT show any passwords or JWT tokens in output _(pending live validation against CipherTrust Manager)_
- [x] The `verify` parameter from `localNode` is respected for TLS certificate validation
- [x] All 5 sanity ignore files have the 33 `no-log-needed` lines removed

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
