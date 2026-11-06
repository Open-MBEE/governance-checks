# governance-checks

Measures Open-MBEE repositories against the policies in [repo-registry](https://github.com/Open-MBEE/repo-registry)
and reports, per repository and per check, what passes, what fails, and what the token could not read.

The registry defines the policies and will eventually sense and report compliance itself (its WP6). Until then this
repository is the stopgap: every check in `data/policies/*.yaml` becomes a SysML v2 requirement with the same ID,
its facts read from the GitHub endpoint the policy's `reads:` line names, and OpenSysML decides whether each
repository satisfies it. Nothing is decided here that the registry does not define; when the registry grows its own
engine, this repository retires.

## How it works

The model is the source and OpenSysML decides:

1. [`model/governance.sysml`](model/governance.sysml) is hand-written: the kinds (`Type`, `Stage`, and `Tier`
   derived by the `TierOf` calc, the registry's kinds table), a `Repository` with one attribute per fact the policies
   read, and one `requirement def` per registry check in a package per policy (`Policies::ChangeReview::ReviewRequired`
   for `change-review`/`review-required`), whose assumption is the policy's `applies_if` and whose required constraint
   is how the check is decided. A policy change means editing this file; the unit tests fail when it disagrees with
   the pinned registry (a check without a requirement or the reverse, an assumption that is not the policy's
   `applies_if`, a tier that is not the kinds table's, a license list that differs).
2. [`model.py`](model.py) derives [`model/repositories.sysml`](model/repositories.sysml) from `repos.yaml`: one part
   per entry bound to its type, stage and attestations, and one `satisfy` assertion per check in effect; CI fails when
   the committed file is stale (`model.py --check`). It also reads the model back through `sysml -convert api-json`,
   so the facts a sensor may produce are the attributes the model declares.
3. [`sense.py`](sense.py) observes the facts, one sensor per check, through `gh api` — a count, a flag, a string,
   never a verdict — into `build/measurements.json`; a fact the token cannot read is left out.
4. `sysml … -import build/measurements.json` binds the facts into the model and `sysml -satisfy -json` evaluates
   every assertion; [`check.py`](check.py) maps `holds` / `fails` / `unresolved` to the table, adds the sensors'
   detail and compares with `baseline.json`.

OpenSysML treats an assumption as a trusted precondition rather than a vacuity condition, so an assertion is only
generated for a check in effect at the entry's kind; the assumption documents the rule the generator applied.
The OpenSysML release is pinned in `repos.yaml` (`opensysml:`) and installed by the workflow from its GitHub
release with the checksum verified.

## What a run produces

- A Markdown table per repository in the Actions job summary (and `summary.md` in the run's artifact).
- `results.json` with every check's status and detail.
- An exit code of 1 only when a check that passed in [`baseline.json`](baseline.json) no longer does (including one
  that became `unreadable`, which means the run lost that coverage). Known open items stay visible in the table
  without turning every run red; a newly disabled ruleset or removed file does.

Statuses: `pass`, `fail`, `exception` (fails the predicate but the registry's `data/deviations.yaml` records an
accepted exception for that repository and policy), `unreadable` (the token lacks the permission the policy names),
`attested` / `unattested` (the policy's attested checks, recorded under `attest:` in `repos.yaml` with a link to the
evidence), `n/a` (the policy is not in effect at that type/stage), `unimplemented` (org-level checks that need the
registry's own scripts). Below each table the `openmbee-<type>` topic (the registry's `type_topics`) is reported as
declared or not; it is how operators declare a type, not a policy check, and never affects the exit code.

## Configuration

[`repos.yaml`](repos.yaml) lists the repositories and the `type`/`stage` each one is measured at. The registry's
snapshot decides a repository's real kind; the entry here can hold a repository to a higher bar than its current
kind so the gaps are visible before the registry moves it. The tier, and which policies are in effect, come from the
registry's `data/taxonomy/kinds.yaml` and each policy's `applies_if`.

`registry.ref` pins the repo-registry commit the policies are read from. Bump it deliberately: a policy change in
the registry changes what is measured here.

## Running it

```sh
pip install -r requirements.txt
git clone https://github.com/Open-MBEE/repo-registry.git /tmp/registry
git -C /tmp/registry checkout "$(python3 -c 'import yaml;print(yaml.safe_load(open("repos.yaml"))["registry"]["ref"])')"
python3 check.py --registry /tmp/registry                      # table on stdout
python3 check.py --registry /tmp/registry --only Open-MBEE/flexo-change-adapter --json out.json
python3 check.py --registry /tmp/registry --update-baseline    # accept the current state as the baseline
python3 -m pytest -q
```

`gh` must be authenticated (`GH_TOKEN`) and `sysml` must be on `PATH` (or `OPENSYSML_SYSML` / `--sysml` must name it; `curl -fsSL https://opensysml.org/install.sh | sh -s -- --version <pin>` installs it). The checks marked `Administration: read` in the policies (push protection,
Dependabot alerts on, default workflow token, CodeQL default setup) report `unreadable` with a token that lacks it.

## The scheduled workflow

[`.github/workflows/check.yml`](.github/workflows/check.yml) runs the unit tests and then the measurement every
Monday, on manual dispatch, and on pull requests. Scheduled, push and dispatch runs read with
`secrets.GOVERNANCE_TOKEN` when set, otherwise the job's own token (which can read only public data, so the admin-only
checks come back `unreadable`). Pull-request runs execute the branch's own `check.py`, so they never see the secret
and skip the baseline comparison (`--baseline ""`); they prove the script runs, not the repositories' state.

To set the token: create a fine-grained personal access token (or a GitHub App installation token) with
**Administration: read**, **Code scanning alerts: read**, **Dependabot alerts: read**, **Metadata: read** and
**Contents: read** on the measured repositories, and store it as the repository secret `GOVERNANCE_TOKEN`. Org-level
checks (`orgs:` in `repos.yaml`) additionally need **Members: read** on the organization.

## Refreshing the test fixtures

The unit tests read a copy of the registry's policy, kinds and maintainers files from
`tests/fixtures/registry/`. After bumping `registry.ref`:

```sh
cp /tmp/registry/data/policies/*.yaml tests/fixtures/registry/data/policies/
cp /tmp/registry/data/taxonomy/kinds.yaml tests/fixtures/registry/data/taxonomy/
cp /tmp/registry/data/maintainers.yaml tests/fixtures/registry/data/
```
