# Contributing

Changes land through pull requests against `develop`; `main` holds what the scheduled run uses. Keep a change to one
of: a new or corrected check (one function per registry check ID, with a unit test against a fake response), a
`repos.yaml` entry or attestation (with a link to the evidence), a `registry.ref` bump (with the fixtures refreshed and
the baseline re-recorded), or a baseline update after a repository's state changed.

Before opening a PR run `python3 -m pytest -q` and, with `GH_TOKEN` set, `python3 check.py --registry <checkout>`
for the repositories your change touches. Do not add a check the registry does not define; propose it in repo-registry
instead. Keep tokens out of the repository: the workflow reads `secrets.GOVERNANCE_TOKEN` only.
