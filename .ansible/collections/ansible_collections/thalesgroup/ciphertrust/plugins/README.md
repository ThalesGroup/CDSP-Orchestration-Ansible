# Plugins

Ansible content shipped by `thalesgroup.ciphertrust`.

| Directory | Contents |
|-----------|----------|
| `modules/` | The 33 modules users call from a playbook. |
| `module_utils/` | Shared code the modules import: the HTTP client, the idempotency helpers, the error hierarchy, and one module per CipherTrust API area. |
| `doc_fragments/` | Documentation shared by every module — the `localNode` connection options and the check-mode/diff-mode attribute blocks. |

## How a module is put together

A module declares its `argument_spec`, then hands off to shared code:

- `module_utils/modules.py` — `ThalesCipherTrustModule` wraps `AnsibleModule`,
  merges in the shared connection options, and normalises legacy `camelCase`
  parameter names to `snake_case`. `ciphertrust_operation` turns any failure
  into a clean `fail_json`.
- `module_utils/cm_api.py` — `CipherTrustClient` handles authentication, JWT
  caching, TLS verification, URL encoding, retries and error translation.
- `module_utils/idempotent.py` — `idempotent_create` and `idempotent_patch`
  implement the GET-before-write pattern so modules report `changed`
  accurately and honour `--check` and `--diff`.
- `module_utils/<area>.py` — one function per CipherTrust API call, e.g.
  `keys2.py`, `cte.py`, `dpg.py`.

## Conventions

- Validation that the argument spec can express (`choices`, `required_if`,
  `required_by`, types) belongs in the spec, not in Python. Only cross-field
  rules the spec cannot express go in a module's `validate_parameters`.
- Values that reach a URL must be encoded with `quote_segment` or
  `quote_query_value`; never concatenate a user-supplied value into a path or
  query string.
- Modules that can return secret material carry a `notes:` block telling users
  to set `no_log: true`.

See `CONTRIBUTING.md` for testing and the sanity-waiver policy.
