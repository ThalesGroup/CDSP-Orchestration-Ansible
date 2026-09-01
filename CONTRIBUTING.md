# Contributing

The code is licensed under the MIT (see LICENSE for details).

First of all, thanks for contributing!

This document provides some basic guidelines for contributing to this repository. To propose improvements, feel free to submit a PR.

## Submitting issues

* If you think you've found an issue, search the issue list to see if there's an existing issue.
* Then, if you find nothing, open a GitHub issue.

## Pull Requests

If your change concern the collection in itself we're more than happy to review your contribution in this repository!

In order to ease/speed up our review, here are some items you can check/improve when submitting your PR:

  * Have a proper commit history (we advise you to rebase if needed).
  * Write tests for the code you wrote.
  * Preferably, make sure that all unit tests pass locally and some relevant kitchen tests.
  * Summarize your PR with an explanatory title and a message describing your changes, cross-referencing any related bugs/PRs.
  * Open your PR against the `master` branch.

### Changelog fragments

This collection uses `antsibull-changelog` and expects changelog fragments for user-facing changes.

For pull requests that modify modules, module utils, or behavior visible to users:

* Add a fragment file under `changelogs/fragments/` named with your issue/PR and a short topic, for example: `123-module-params.yaml`.
* Use one or more supported sections: `major_changes`, `minor_changes`, `breaking_changes`, `deprecated_features`, `removed_features`, `security_fixes`, `bugfixes`, or `known_issues`.
* Keep fragment entries concise and action-oriented.

Example fragment:

```yaml
minor_changes:
  - Added snake_case aliases for selected module parameters.
```

You can validate changelog configuration locally with:

```bash
antsibull-changelog lint
```

### Keep it small, focused

Avoid changing too many things at once. For instance, if you're fixing a role and at the same time adding some code refactor, it makes reviewing harder and the _time-to-release_ longer.

### Commit messages

Please take a moment to write meaningful commit messages.

The commit message should describe the reason for the change and give extra details that will allow someone later on to understand in 5 seconds the thing you've been working on for a day.

If your commit is only shipping documentation changes or example files, and is a complete no-op for the test suite, add **[skip ci]** in the commit message body to skip the build and give that slot to someone else who does need it.

### Squash your commits

Rebase your changes on `master` and squash your commits whenever possible. This keeps history cleaner and easier to revert things. It also makes developers happier!

### Code of Conduct

This collection follows the Ansible project's [Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html). Please read and familiarize yourself with this document.

### More details

Take a look a the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for more details about how to contribute to Ansible.

## Development

To contribute, follow the contributing guidelines above.

### Sanity test waivers

`tests/sanity/ignore-<version>.txt` carries one waiver per line, and
`ansible-test` rejects blank lines and comments in those files, so the reasons
are recorded here instead:

- `validate-modules:missing-gplv3-license` — this collection is MIT licensed
  (see `LICENSE`), while `validate-modules` expects a GPLv3-compatible module
  header by default.
A waiver may only name a file that ships in the build artifact. `build_ignore`
excludes documentation and the unit suite, and `ansible-test` fails the
`ignores` test when a waiver points at a file it cannot find -- so a waiver for
an excluded file passes in the repository and fails at certification time.

Add a matching bullet here whenever you add a waiver, and remove the waiver as
soon as the underlying issue is fixed — `ansible-test` fails the `ignores` test
for waivers that are no longer needed.

## Author Information

oss@thalesgroup.com
