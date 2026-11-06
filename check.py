#!/usr/bin/env python3
"""Measure Open-MBEE repositories against the repo-registry policies.

Each automated check in a repo-registry policy (data/policies/*.yaml, `checks.automated[].id`) is one function
here, named after the check and reading what the policy's `reads:` line says it reads, through `gh api`. Each
attested check is reported from the `attest:` block of the repository's entry in repos.yaml. Nothing else is
decided here: which policies apply to a repository comes from the policy's `applies_if` evaluated against the
type and stage the entry asks to be measured at (tier from the registry's kinds table).

Statuses: pass, fail, unreadable (the token lacks the permission the check names), attested, unattested,
n/a (the policy does not apply at that type/stage), unimplemented (an org-level check that needs the registry's
own scripts). Compliance failures are reported, never raised; the exit code is non-zero only for a regression
against baseline.json or a construction error (bad configuration, gh missing).
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import pathlib
import re
import subprocess
import sys

import yaml

SEMVER = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
SBOM_GLOBS = ("*.spdx.json", "*.spdx", "*.cdx.json", "*bom*.json")
ORDER = ["fail", "unreadable", "unattested", "unimplemented", "pass", "attested", "n/a"]


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


class GitHub:
    """Thin wrapper over `gh api`: returns (http_status, parsed_json_or_None)."""

    def __init__(self, env: dict | None = None):
        self.env = {**os.environ, **(env or {})}
        self.cache: dict[tuple, tuple[int, object]] = {}

    def api(self, path: str, *, paginate: bool = False, method: str | None = None):
        key = (path, paginate, method)
        if key in self.cache:
            return self.cache[key]
        cmd = ["gh", "api", path]
        if paginate:
            cmd += ["--paginate", "--slurp"]
        if method:
            cmd += ["--method", method]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        if proc.returncode == 0:
            body = proc.stdout.strip()
            data = json.loads(body) if body else None
            if paginate and isinstance(data, list) and data and isinstance(data[0], list):
                data = [item for page in data for item in page]
            status = 204 if body == "" else 200
            result = (status, data)
        else:
            m = re.search(r"\(HTTP (\d{3})\)", proc.stderr)
            status = int(m.group(1)) if m else 0
            data = None
            try:
                data = json.loads(proc.stdout) if proc.stdout.strip() else None
            except json.JSONDecodeError:
                pass
            result = (status, data if data is not None else {"message": proc.stderr.strip()})
        self.cache[key] = result
        return result

    def graphql(self, query: str, **variables):
        cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
        for k, v in variables.items():
            cmd += ["-f", f"{k}={v}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        if proc.returncode != 0:
            return (0, {"message": proc.stderr.strip()})
        return (200, json.loads(proc.stdout))


class Registry:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.policies = []
        for f in sorted((root / "data/policies").glob("*.yaml")):
            d = yaml.safe_load(f.read_text())
            if isinstance(d, dict) and d.get("id") and d.get("checks") is not None:
                self.policies.append(d)
        kinds = yaml.safe_load((root / "data/taxonomy/kinds.yaml").read_text())
        self.kinds = kinds["kinds"]
        self.type_topics = {v: k for k, v in kinds.get("type_topics", {}).items()}
        m = yaml.safe_load((root / "data/maintainers.yaml").read_text())
        self.maintainers = m.get("maintainers") or {}
        lic = next(p for p in self.policies if p["id"] == "license-by-type")
        self.allowed_licenses = lic["allowed_licenses"]

    def tier(self, type_: str, stage: str) -> str:
        try:
            return self.kinds[type_][stage]["tier"]
        except KeyError as e:
            raise SystemExit(f"construction error: no kind {type_}/{stage} in kinds.yaml") from e


def applies(rule, attrs: dict) -> bool:
    if rule is None:
        return True
    if "all" in rule:
        return all(applies(r, attrs) for r in rule["all"])
    if "any" in rule:
        return any(applies(r, attrs) for r in rule["any"])
    if "not" in rule:
        return not applies(rule["not"], attrs)
    value = attrs.get(rule["attr"])
    if "eq" in rule:
        return value == rule["eq"]
    if "in" in rule:
        return value in rule["in"]
    raise SystemExit(f"construction error: unsupported applies_if clause {rule}")


# ----------------------------------------------------------------------------------------------- repository checks

class Repo:
    def __init__(self, gh: GitHub, registry: Registry, entry: dict):
        self.gh = gh
        self.registry = registry
        self.entry = entry
        self.full = entry["name"]
        self.owner, self.name = self.full.split("/", 1)
        self.type = entry["type"]
        self.stage = entry["stage"]
        self.tier = registry.tier(self.type, self.stage)
        status, data = gh.api(f"repos/{self.full}")
        if status != 200:
            raise SystemExit(f"construction error: cannot read {self.full} (HTTP {status}): {data}")
        self.data = data
        self.default_branch = data["default_branch"]

    def attrs(self):
        return {"type": self.type, "stage": self.stage, "tier": self.tier}

    # helpers
    def rules(self):
        return self.gh.api(f"repos/{self.full}/rules/branches/{self.default_branch}")

    def protection(self):
        return self.gh.api(f"repos/{self.full}/branches/{self.default_branch}/protection")

    def rule_of(self, type_):
        status, rules = self.rules()
        if status != 200:
            return None
        return next((r for r in rules if r.get("type") == type_), None)

    def codeowners_text(self):
        for path in CODEOWNERS_PATHS:
            status, data = self.gh.api(f"repos/{self.full}/contents/{path}")
            if status == 200:
                import base64
                return path, base64.b64decode(data["content"]).decode()
        return None, None

    def latest_release(self):
        return self.gh.api(f"repos/{self.full}/releases/latest")

    # --- archive-notice
    def check_archived(self):
        return ("pass", "archived") if self.data.get("archived") else ("fail", "not archived")

    # --- change-review
    def check_review_required(self):
        rule = self.rule_of("pull_request")
        if rule is not None:
            p = rule.get("parameters") or {}
            n, co = p.get("required_approving_review_count", 0), p.get("require_code_owner_review", False)
            ok = n >= 1 and co
            return ("pass" if ok else "fail", f"ruleset: approvals={n}, code_owner_review={co}")
        status, prot = self.protection()
        if status == 200:
            r = prot.get("required_pull_request_reviews") or {}
            n, co = r.get("required_approving_review_count", 0), r.get("require_code_owner_reviews", False)
            return ("pass" if n >= 1 and co else "fail", f"classic: approvals={n}, code_owner_review={co}")
        if status in (403, 404):
            s, rules = self.rules()
            if s == 200:
                return ("fail", "no pull_request rule on the default branch; classic protection unreadable")
            return ("unreadable", f"rules HTTP {s}, protection HTTP {status}")
        return ("unreadable", f"protection HTTP {status}")

    def check_checks_required(self):
        rule = self.rule_of("required_status_checks")
        if rule is not None:
            ctx = [c["context"] for c in (rule.get("parameters") or {}).get("required_status_checks", [])]
            return ("pass" if ctx else "fail", "required: " + ", ".join(ctx))
        status, prot = self.protection()
        if status == 200:
            ok = bool(prot.get("required_status_checks"))
            return ("pass" if ok else "fail", "classic protection")
        s, _ = self.rules()
        if s == 200:
            return ("fail", "no required_status_checks rule on the default branch")
        return ("unreadable", f"rules HTTP {s}, protection HTTP {status}")

    # --- codeowners
    def check_codeowners_present(self):
        path, _ = self.codeowners_text()
        return ("pass", path) if path else ("fail", "no CODEOWNERS at .github/, root or docs/")

    def check_codeowners_valid(self):
        status, data = self.gh.api(f"repos/{self.full}/codeowners/errors")
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        errors = data.get("errors") or []
        return ("pass" if not errors else "fail", f"{len(errors)} error(s)")

    # --- contributing / project-files
    def _profile_file(self, key):
        status, data = self.gh.api(f"repos/{self.full}/community/profile")
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        present = (data.get("files") or {}).get(key) is not None
        return ("pass" if present else "fail", f"community profile files.{key}")

    def check_contributing_present(self):
        return self._profile_file("contributing")

    def check_readme_present(self):
        return self._profile_file("readme")

    # --- dependency-management
    def check_dependabot_alerts_on(self):
        status, _ = self.gh.api(f"repos/{self.full}/vulnerability-alerts")
        if status == 204:
            return ("pass", "enabled")
        if status == 404:
            return ("fail", "disabled (token has admin read)") if self.data.get("permissions", {}).get("admin") \
                else ("unreadable", "404 without admin read")
        return ("unreadable", f"HTTP {status}")

    # --- history-protection
    def _rule_or_classic(self, rule_type, classic_key, label):
        if self.rule_of(rule_type) is not None:
            return ("pass", f"ruleset: {rule_type}")
        status, prot = self.protection()
        if status == 200:
            off = not (prot.get(classic_key) or {}).get("enabled", False)
            return ("pass" if off else "fail", f"classic: {classic_key}.enabled={not off}")
        s, _ = self.rules()
        if s == 200:
            return ("fail", f"no {rule_type} rule on the default branch; classic protection HTTP {status}")
        return ("unreadable", f"rules HTTP {s}, protection HTTP {status}")

    def check_no_force_push(self):
        return self._rule_or_classic("non_fast_forward", "allow_force_pushes", "force push")

    def check_no_deletion(self):
        return self._rule_or_classic("deletion", "allow_deletions", "deletion")

    # --- license-by-type
    def check_license_allowed(self):
        spdx = (self.data.get("license") or {}).get("spdx_id")
        allowed = self.registry.allowed_licenses.get(self.type, [])
        if spdx in allowed:
            return ("pass", spdx)
        return ("fail", f"{spdx or 'missing'}; allowed for {self.type}: {', '.join(allowed)}")

    # --- release-integrity
    def check_sbom_attached(self):
        status, rel = self.latest_release()
        if status == 404:
            return ("fail", "no non-prerelease release")
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        names = [a["name"] for a in rel.get("assets", [])]
        hits = [n for n in names if any(fnmatch.fnmatch(n.lower(), g) for g in SBOM_GLOBS)]
        return ("pass" if hits else "fail", f"{rel['tag_name']}: " + (", ".join(hits) or f"{len(names)} asset(s), no SBOM"))

    def check_release_immutable(self):
        status, rel = self.latest_release()
        if status == 404:
            return ("fail", "no non-prerelease release")
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        return ("pass" if rel.get("immutable") else "fail", f"{rel['tag_name']}: immutable={rel.get('immutable')}")

    # --- secret-protection
    def check_push_protection_on(self):
        sa = self.data.get("security_and_analysis")
        if not sa:
            return ("unreadable", "security_and_analysis absent (needs admin read)")
        st = (sa.get("secret_scanning_push_protection") or {}).get("status")
        return ("pass" if st == "enabled" else "fail", f"secret_scanning_push_protection={st}")

    # --- security-policy
    def check_security_policy_present(self):
        status, data = self.gh.graphql(
            "query($owner:String!,$name:String!){repository(owner:$owner,name:$name){isSecurityPolicyEnabled}}",
            owner=self.owner, name=self.name)
        if status != 200:
            return ("unreadable", str(data)[:80])
        ok = data["data"]["repository"]["isSecurityPolicyEnabled"]
        return ("pass" if ok else "fail", f"isSecurityPolicyEnabled={ok}")

    def check_private_reporting_on(self):
        status, data = self.gh.api(f"repos/{self.full}/private-vulnerability-reporting")
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        return ("pass" if data.get("enabled") else "fail", f"enabled={data.get('enabled')}")

    # --- semantic-versioning
    def check_semver_tags(self):
        status, rels = self.gh.api(f"repos/{self.full}/releases?per_page=100", paginate=True)
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        cutoff = now() - dt.timedelta(days=365)
        recent = [r for r in rels if not r.get("draft") and r.get("published_at") and parse_time(r["published_at"]) >= cutoff]
        bad = [r["tag_name"] for r in recent if not SEMVER.match(r["tag_name"])]
        if not recent:
            return ("pass", "no release in the last 12 months")
        return ("pass" if not bad else "fail", f"{len(recent)} release(s); off-pattern: {', '.join(bad[:5]) or 'none'}")

    # --- static-analysis
    def check_code_scanning_configured(self):
        status, data = self.gh.api(f"repos/{self.full}/code-scanning/default-setup")
        if status == 200 and data.get("state") == "configured":
            return ("pass", "default setup")
        s2, analyses = self.gh.api(f"repos/{self.full}/code-scanning/analyses?per_page=1")
        if s2 == 200:
            return ("pass" if analyses else "fail", f"{'analyses present' if analyses else 'no analyses'}; default-setup HTTP {status}")
        if s2 == 404:
            return ("fail", "code scanning not enabled")
        return ("unreadable", f"default-setup HTTP {status}, analyses HTTP {s2}")

    def _code_scanning_open(self):
        return self.gh.api(f"repos/{self.full}/code-scanning/alerts?state=open&per_page=100", paginate=True)

    def check_no_open_critical(self):
        status, alerts = self._code_scanning_open()
        if status == 404:
            return ("fail", "code scanning not enabled")
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        cutoff = now() - dt.timedelta(days=14)
        old = [a for a in alerts if (a.get("rule") or {}).get("security_severity_level") == "critical"
               and parse_time(a["created_at"]) < cutoff]
        return ("pass" if not old else "fail", f"{len(old)} critical alert(s) older than 14 days")

    # --- vulnerability-remediation
    def check_dependency_alerts_on_time(self):
        status, alerts = self.gh.api(f"repos/{self.full}/dependabot/alerts?state=open&per_page=100", paginate=True)
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        late = []
        for a in alerts:
            sev = (a.get("security_advisory") or {}).get("severity")
            age = (now() - parse_time(a["created_at"])).days
            if (sev == "critical" and age > 14) or (sev in ("high", "medium") and age > 60):
                late.append(f"{a['dependency']['package']['name']}({sev},{age}d)")
        return ("pass" if not late else "fail", f"{len(alerts)} open; late: {', '.join(late[:5]) or 'none'}")

    def check_scanning_clean(self):
        status, alerts = self._code_scanning_open()
        if status == 404:
            return ("fail", "code scanning not enabled")
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        cutoff = now() - dt.timedelta(days=60)
        old = [a for a in alerts if (a.get("rule") or {}).get("security_severity_level") in ("medium", "high", "critical")
               and parse_time(a["created_at"]) < cutoff]
        return ("pass" if not old else "fail", f"{len(old)} medium+ alert(s) older than 60 days")

    # --- verified-code-owners
    def check_verified_owners(self):
        path, text = self.codeowners_text()
        if not text:
            return ("fail", "no CODEOWNERS")
        handles = sorted({h for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
                          for h in re.findall(r"@([A-Za-z0-9-]+)(?![/\w])", line)})
        by_login = {m.get("login"): m for m in self.registry.maintainers.values()}
        cutoff = now() - dt.timedelta(days=365)
        problems = []
        for h in handles:
            m = by_login.get(h)
            if not m:
                problems.append(f"{h}: not in maintainers.yaml")
                continue
            v = m.get("verified") or m.get("verified_on") or (m.get("verification") or {}).get("date")
            if not v or parse_time(str(v) + ("T00:00:00+00:00" if len(str(v)) == 10 else "")) < cutoff:
                problems.append(f"{h}: no verification within 12 months")
        return ("pass" if not problems else "fail", "; ".join(problems) or f"{len(handles)} owner(s) verified")

    # --- workflow-least-privilege
    def check_default_token_read(self):
        status, data = self.gh.api(f"repos/{self.full}/actions/permissions/workflow")
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        v = data.get("default_workflow_permissions")
        return ("pass" if v == "read" else "fail", f"default_workflow_permissions={v}")

    # --- type topic (kinds.yaml type_topics; operators declare type with it)
    def check_type_topic(self):
        topic = self.registry.type_topics.get(self.type)
        topics = self.data.get("topics") or []
        return ("pass" if topic in topics else "fail", f"topics={','.join(topics) or 'none'}; expected {topic}")


# ------------------------------------------------------------------------------------------------------ org checks

class Org:
    def __init__(self, gh: GitHub, registry: Registry, entry: dict):
        self.gh, self.registry, self.entry = gh, registry, entry
        self.full = entry["name"]
        self.type, self.stage = entry["type"], entry["stage"]
        self.tier = registry.tier(self.type, self.stage)

    def attrs(self):
        return {"type": self.type, "stage": self.stage, "tier": self.tier}

    def _org(self):
        return self.gh.api(f"orgs/{self.full}")

    def check_owner_count(self):
        status, admins = self.gh.api(f"orgs/{self.full}/members?role=admin&per_page=100", paginate=True)
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        return ("pass" if 2 <= len(admins) <= 3 else "fail", f"{len(admins)} owner(s)")

    def check_two_factor_required(self):
        status, org = self._org()
        v = org.get("two_factor_requirement_enabled") if status == 200 else None
        if v is None:
            return ("unreadable", "returned only to owners")
        return ("pass" if v else "fail", f"two_factor_requirement_enabled={v}")

    def check_base_permission_read(self):
        status, org = self._org()
        v = org.get("default_repository_permission") if status == 200 else None
        if v is None:
            return ("unreadable", "returned only to owners")
        return ("pass" if v in ("read", "none") else "fail", f"default_repository_permission={v}")

    def check_owners_public(self):
        s1, admins = self.gh.api(f"orgs/{self.full}/members?role=admin&per_page=100", paginate=True)
        s2, public = self.gh.api(f"orgs/{self.full}/public_members?per_page=100", paginate=True)
        if s1 != 200 or s2 != 200:
            return ("unreadable", f"HTTP {s1}/{s2}")
        hidden = {a["login"] for a in admins} - {p["login"] for p in public}
        return ("pass" if not hidden else "fail", f"{len(hidden)} owner(s) with concealed membership")

    def check_maintainers_public(self):
        status, public = self.gh.api(f"orgs/{self.full}/public_members?per_page=100", paginate=True)
        if status != 200:
            return ("unreadable", f"HTTP {status}")
        logins = {p["login"] for p in public}
        missing = [m["login"] for m in self.registry.maintainers.values() if m.get("login") not in logins]
        return ("pass" if not missing else "fail", "not public: " + (", ".join(missing) or "none"))

    def check_match(self):
        return ("unimplemented", "needs repo-registry scripts/org.py")


# ----------------------------------------------------------------------------------------------------------- driver

def run_entry(gh, registry, entry):
    subject = Org(gh, registry, entry) if entry.get("scope") == "org" else Repo(gh, registry, entry)
    attest = entry.get("attest") or {}
    rows = []
    for policy in registry.policies:
        scope = policy.get("scope", "repository")
        if (scope == "org") != isinstance(subject, Org):
            continue
        in_effect = applies(policy.get("applies_if"), subject.attrs())
        for check in policy["checks"].get("automated") or []:
            fn = getattr(subject, "check_" + check["id"].replace("-", "_"), None)
            if not in_effect:
                status, detail = "n/a", ""
            elif fn is None:
                status, detail = "unimplemented", ""
            else:
                status, detail = fn()
            rows.append({"policy": policy["id"], "check": check["id"], "kind": "automated", "status": status, "detail": detail})
        for check in policy["checks"].get("attested") or []:
            if not in_effect:
                status, detail = "n/a", ""
            elif check["id"] in attest:
                status, detail = "attested", str(attest[check["id"]])
            else:
                status, detail = "unattested", "no entry under attest: in repos.yaml"
            rows.append({"policy": policy["id"], "check": check["id"], "kind": "attested", "status": status, "detail": detail})
    if isinstance(subject, Repo):
        status, detail = subject.check_type_topic()
        rows.append({"policy": "type-topic", "check": "type-topic", "kind": "automated", "status": status, "detail": detail})
    return {"name": subject.full, "type": subject.type, "stage": subject.stage, "tier": subject.tier, "checks": rows}


def summarize(results):
    out = []
    for r in results:
        counts = {}
        for c in r["checks"]:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        head = ", ".join(f"{k} {counts[k]}" for k in ORDER if counts.get(k))
        out.append(f"### {r['name']} — {r['type']}/{r['stage']} ({r['tier']} tier): {head}\n")
        out.append("| policy | check | status | detail |\n|---|---|---|---|")
        for c in sorted(r["checks"], key=lambda c: (ORDER.index(c["status"]), c["policy"])):
            if c["status"] == "n/a":
                continue
            out.append(f"| {c['policy']} | {c['check']} | {c['status']} | {c['detail'].replace('|', '/')} |")
        na = sorted({c["policy"] for c in r["checks"] if c["status"] == "n/a"})
        if na:
            out.append(f"\nNot in effect at {r['type']}/{r['stage']}: {', '.join(na)}")
        out.append("")
    return "\n".join(out)


def regressions(results, baseline):
    """A check that passed (or was attested) in the baseline and no longer does."""
    good = {"pass", "attested", "n/a"}
    out = []
    for r in results:
        base = {(c["check"]): c["status"] for c in (baseline.get(r["name"]) or {}).get("checks", [])}
        for c in r["checks"]:
            before = base.get(c["check"])
            if before in good and c["status"] not in good and c["status"] != "unreadable":
                out.append(f"{r['name']}: {c['policy']}/{c['check']} {before} -> {c['status']} ({c['detail']})")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="repos.yaml")
    ap.add_argument("--registry", required=True, help="path to a checkout of Open-MBEE/repo-registry at the pinned ref")
    ap.add_argument("--only", action="append", help="repository (owner/name) to measure; repeatable")
    ap.add_argument("--json", dest="json_out", help="write the results here")
    ap.add_argument("--summary", help="write the Markdown summary here (default: stdout)")
    ap.add_argument("--baseline", default="baseline.json")
    ap.add_argument("--update-baseline", action="store_true")
    args = ap.parse_args(argv)

    config = yaml.safe_load(pathlib.Path(args.config).read_text())
    registry = Registry(pathlib.Path(args.registry))
    gh = GitHub()
    entries = config["repos"] + [{**o, "scope": "org"} for o in config.get("orgs") or []]
    if args.only:
        entries = [e for e in entries if e["name"] in args.only]
    results = [run_entry(gh, registry, e) for e in entries]

    text = summarize(results)
    if args.summary:
        pathlib.Path(args.summary).write_text(text)
    else:
        print(text)
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(results, indent=2) + "\n")

    base_path = pathlib.Path(args.baseline)
    snapshot = {r["name"]: {"checks": [{"check": c["check"], "status": c["status"]} for c in r["checks"]]} for r in results}
    if args.update_baseline:
        existing = json.loads(base_path.read_text()) if base_path.exists() else {}
        existing.update(snapshot)
        base_path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")
        return 0
    if base_path.exists():
        regs = regressions(results, json.loads(base_path.read_text()))
        if regs:
            print("\nREGRESSIONS against baseline.json:\n- " + "\n- ".join(regs), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
