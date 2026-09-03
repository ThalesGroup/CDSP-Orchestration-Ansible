# Security Policy

This collection automates configuration of Thales CipherTrust Manager, and the
tasks it runs handle credentials, key material and certificates. The guidance
below covers both how to report a problem in the collection and how to operate
it safely.

## Supported versions

| Version | Supported                        |
| ------- | -------------------------------- |
| 1.0.x   | :white_check_mark:               |
| < 1.0   | :x:                              |

Security fixes are released as a new patch version of the most recent minor
release. Older minor releases are not backported.

## Reporting a vulnerability

Report suspected vulnerabilities privately to
**security@opensource.thalesgroup.com**. Please do not open a public GitHub
issue for a security problem.

Include, where you can:

- the collection version and the ansible-core version in use;
- the module or `module_utils` involved;
- a minimal playbook or reproduction;
- the impact you believe the issue has.

You will receive an acknowledgement of your report, and an assessment of
whether it is accepted as a vulnerability, along with the intended remediation
if it is. Please allow the maintainers time to release a fix before disclosing
the issue publicly.

## Disclosure policy

Reports are handled privately until a fixed version is published. Once a fix is
released, the issue is described in the changelog for that release. Reporters
are credited unless they ask not to be.

## Operating this collection securely

These are properties of the collection that affect the security of a
deployment. They are the settings a review should check first.

### Verify TLS certificates

`localNode.verify` defaults to `false` for compatibility with lab systems using
self-signed certificates. **Set it to `true` in any environment that matters.**
With `verify: false` the connection to CipherTrust Manager is encrypted but
unauthenticated, so it is open to interception.

The default changes to `true` in version 2.0.0.

### Keep credentials out of playbooks

`localNode.password` is marked `no_log`, so it is redacted from Ansible output.
That does not protect it at rest: supply it from Ansible Vault or an external
secret store rather than writing it into a playbook or inventory file.

Use a CipherTrust Manager account scoped to the work the playbook performs
rather than a full administrator, and prefer an authentication domain
(`localNode.auth_domain_path`) over the root domain where the deployment
supports it.

### Protect sensitive module output

Some operations return secret material in the module result — exporting or
cloning a key with its material, creating a CSR with its private key, and
creating a registration token. Ansible cannot redact part of a return value, so
**set `no_log: true` on those tasks**. The affected modules carry a note saying
so in their documentation. Registering such a result also keeps the secret in
memory for the remainder of the play.

### Treat resource names as untrusted input

Resource names and identifiers are percent-encoded before they are placed in a
request URL, so a name containing a path or query separator cannot alter which
resource a request addresses.

## Security update policy

Security fixes are announced in the collection changelog and published to
Ansible Galaxy as a new patch release. Watch the repository, or subscribe to
the Galaxy release feed, to be notified.

## Automated checks

Every push and pull request runs `ansible-test sanity` (the full default test
set, across the supported ansible-core versions), `ansible-lint`, the unit
suite with coverage gates, and CodeQL with the `security-extended` query set.

GitHub secret scanning and push protection are repository settings rather than
workflows; both should be enabled for this repository.

## Design notes

- Only `GET` requests are retried after a transient failure. A `POST`, `PATCH`
  or `DELETE` that may already have been applied is never replayed, because
  duplicating a write against CipherTrust Manager is worse than failing the
  task.
- An expired session is renewed once transparently on a `401`, then the
  request is retried.
- The JWT obtained during a run is cached in memory for the lifetime of that
  module process. It is never written to disk or included in module output.

## Known gaps

- `localNode.verify` still defaults to `false`. See above; this changes in
  2.0.0.
- Integration tests exercise a live CipherTrust Manager and therefore only run
  where credentials are configured.
