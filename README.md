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
   is how the check is decided, deadlines and windows included (14 and 60 days for alerts, 365 for off-pattern
   release tags and code-owner verification). A policy change means editing this file; the unit tests fail when it disagrees with
   the pinned registry (a check without a requirement or the reverse, an assumption that is not the policy's
   `applies_if` or that OpenSysML evaluates differently at any type and stage, a tier that is not the kinds table's,
   a license list that differs).
2. [`model.py`](model.py) derives [`model/repositories.sysml`](model/repositories.sysml) from `repos.yaml`: one part
   per entry bound to its type, stage and attestations, and one `satisfy` assertion per registry check, whatever
   the entry's kind; CI fails when the committed file is stale (`model.py --check`). It then asks OpenSysML, through
   the `opensysml` client, what the model says: which assertions are in effect (each one's `inEffect` assumption,
   evaluated for its repository), each repository's tier, and the declared facts (the API's JSON element form), so
   the facts a sensor may produce are the attributes the model declares.
3. [`sense.py`](sense.py) observes the facts of the checks in effect, one sensor per check, through `gh api` — a
   count, a flag, a string, an age in days, never a verdict or a deadline — into `build/measurements.json`; a fact
   the token cannot read is left out.
4. [`check.py`](check.py) hands the model and the facts to OpenSysML through its Python client
   ([`opensysml`](https://pypi.org/project/opensysml/)): `import_data` binds the facts into the model
   (`build/bound.sysml`) and `verify_satisfaction` evaluates every assertion; the verdicts (`holds` / `violated` /
   `undecided`) map to the table, with the sensors' detail added, and are compared with `baseline.json`.

An assertion whose assumption is false holds whatever the facts are, so the table reports it as `n/a` from the
assumption's own value rather than as a pass, and its facts are not sensed. No Python evaluates the registry's
`applies_if` at run time; the unit tests do, to check the model against it.
The OpenSysML release is pinned in `repos.yaml` (`opensysml:`): `requirements.txt` installs the `opensysml` client
of that version, `check.py` refuses any other, and the client starts a private `sysml-grpc` of that release, which
it downloads and checks against the digests it ships (or takes from `$OPENSYSML_BINARY` if that build reports the
pinned version).

## What a run produces

- A Markdown table per repository in the Actions job summary (and `summary.md` in the run's artifact).
- `results.json` with every check's status and detail.
- An exit code of 1 only when a check that passed in [`baseline.json`](baseline.json) no longer does (including one
  that became `unreadable`, which means the run lost that coverage). Known open items stay visible in the table
  without turning every run red; a newly disabled ruleset or removed file does.

Statuses: `pass`, `fail`, `exception` (fails the predicate but the registry's `data/deviations.yaml` records an
accepted exception for that repository and policy), `unreadable` (the token lacks the permission the policy names),
`attested` / `unattested` (the policy's attested checks, recorded under `attest:` in `repos.yaml` with a link to the
evidence), `n/a` (the requirement's assumption is false at that type/stage), `unimplemented` (org-level checks that need the
registry's own scripts). Below each table the `openmbee-<type>` topic (the registry's `type_topics`) is reported as
declared or not; it is how operators declare a type, not a policy check, and never affects the exit code.

## Configuration

[`repos.yaml`](repos.yaml) lists the repositories and the `type`/`stage` each one is measured at. The registry's
snapshot decides a repository's real kind; the entry here can hold a repository to a higher bar than its current
kind so the gaps are visible before the registry moves it. The tier, and which policies are in effect, come from the
model (the `TierOf` calc and each requirement's assumption), which the unit tests hold to the registry's
`data/taxonomy/kinds.yaml` and each policy's `applies_if`.

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

`gh` must be authenticated (`GH_TOKEN`); `pip install -r requirements.txt` brings the `opensysml` client, which
fetches the pinned `sysml-grpc` into `~/.opensysml/bin` on first use. The checks marked `Administration: read` in the policies (push protection,
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
