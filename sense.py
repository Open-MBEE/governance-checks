#!/usr/bin/env python3
"""Sense the facts the repo-registry policies read, one sensor per automated check, through `gh api`.

A sensor returns raw observations (a count, a flag, a string), never a verdict: the verdicts come from evaluating
the generated SysML model (model.py) over these facts with OpenSysML. A fact the token cannot read is left out,
which the model reports as unresolved and the table as `unreadable`.
"""
from __future__ import annotations

import base64
import datetime as dt
import fnmatch
import re

from common import CODEOWNERS_PATHS, SBOM_GLOBS, SEMVER, GitHub, Registry, now, parse_time


class Sensed:
    """What one sensor observed: the facts it could read, a one-line detail, and why it could not read."""

    def __init__(self, facts: dict | None = None, detail: str = "", unreadable: str | None = None):
        self.facts, self.detail, self.unreadable = facts or {}, detail, unreadable


def facts(**kw):
    detail = kw.pop("detail", "")
    return Sensed(kw, detail)


def unreadable(reason):
    return Sensed(None, reason, reason)


class Repository:
    def __init__(self, gh: GitHub, registry: Registry, entry: dict):
        self.gh, self.registry, self.entry = gh, registry, entry
        self.full = entry["name"]
        self.owner, self.name = self.full.split("/", 1)
        self.type, self.stage = entry["type"], entry["stage"]
        self.tier = registry.tier(self.type, self.stage)
        status, data = gh.api(f"repos/{self.full}")
        if status != 200:
            raise SystemExit(f"construction error: cannot read {self.full} (HTTP {status}): {data}")
        self.data = data
        self.default_branch = data["default_branch"]

    def attrs(self):
        return {"type": self.type, "stage": self.stage, "tier": self.tier}

    def sensor(self, check_id: str):
        return getattr(self, "sense_" + check_id.replace("-", "_"), None)

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
        """(path, text, None) when found, (None, None, None) when absent, (None, None, status) when unreadable."""
        denied = None
        for path in CODEOWNERS_PATHS:
            status, data = self.gh.api(f"repos/{self.full}/contents/{path}")
            if status == 200:
                return path, base64.b64decode(data["content"]).decode(), None
            if status != 404:
                denied = status
        return None, None, denied

    def latest_release(self):
        return self.gh.api(f"repos/{self.full}/releases/latest")

    # --- archive-notice
    def sense_archived(self):
        a = bool(self.data.get("archived"))
        return facts(archived=a, detail="archived" if a else "not archived")

    # --- change-review
    def sense_review_required(self):
        rule = self.rule_of("pull_request")
        if rule is not None:
            p = rule.get("parameters") or {}
            n, co = p.get("required_approving_review_count", 0), bool(p.get("require_code_owner_review", False))
            return facts(approvalsRequired=n, codeOwnerReviewRequired=co, detail=f"ruleset: approvals={n}, code_owner_review={co}")
        status, prot = self.protection()
        if status == 200:
            r = prot.get("required_pull_request_reviews") or {}
            n, co = r.get("required_approving_review_count", 0), bool(r.get("require_code_owner_reviews", False))
            return facts(approvalsRequired=n, codeOwnerReviewRequired=co, detail=f"classic: approvals={n}, code_owner_review={co}")
        if status in (403, 404):
            s, _ = self.rules()
            if s == 200:
                return facts(approvalsRequired=0, codeOwnerReviewRequired=False,
                             detail="no pull_request rule on the default branch; classic protection unreadable")
            return unreadable(f"rules HTTP {s}, protection HTTP {status}")
        return unreadable(f"protection HTTP {status}")

    def sense_checks_required(self):
        rule = self.rule_of("required_status_checks")
        if rule is not None:
            ctx = [c["context"] for c in (rule.get("parameters") or {}).get("required_status_checks", [])]
            return facts(requiredStatusChecks=len(ctx), detail="required: " + (", ".join(ctx) or "none"))
        status, prot = self.protection()
        if status == 200:
            rsc = prot.get("required_status_checks") or {}
            ctx = sorted({*(rsc.get("contexts") or []), *(c["context"] for c in rsc.get("checks") or [])})
            return facts(requiredStatusChecks=len(ctx), detail="classic protection: " + (", ".join(ctx) or "none"))
        s, _ = self.rules()
        if s == 200:
            return facts(requiredStatusChecks=0, detail="no required_status_checks rule on the default branch")
        return unreadable(f"rules HTTP {s}, protection HTTP {status}")

    # --- codeowners
    def sense_codeowners_present(self):
        path, _, denied = self.codeowners_text()
        if denied:
            return unreadable(f"contents HTTP {denied}")
        return facts(codeownersPresent=bool(path), detail=path or "no CODEOWNERS at .github/, root or docs/")

    def sense_codeowners_valid(self):
        status, data = self.gh.api(f"repos/{self.full}/codeowners/errors")
        if status != 200:
            return unreadable(f"HTTP {status}")
        errors = data.get("errors") or []
        return facts(codeownersErrors=len(errors), detail=f"{len(errors)} error(s)")

    # --- contributing / project-files
    def _profile_file(self, key, fact):
        status, data = self.gh.api(f"repos/{self.full}/community/profile")
        if status != 200:
            return unreadable(f"HTTP {status}")
        present = (data.get("files") or {}).get(key) is not None
        return facts(**{fact: present}, detail=f"community profile files.{key}={'present' if present else 'absent'}")

    def sense_contributing_present(self):
        return self._profile_file("contributing", "contributingPresent")

    def sense_readme_present(self):
        return self._profile_file("readme", "readmePresent")

    # --- dependency-management
    def sense_dependabot_alerts_on(self):
        # GraphQL answers for any reader; the REST endpoint returns 404 both for "disabled" and "no admin read".
        status, data = self.gh.graphql(
            "query($owner:String!,$name:String!){repository(owner:$owner,name:$name){hasVulnerabilityAlertsEnabled}}",
            owner=self.owner, name=self.name)
        on = ((data.get("data") or {}).get("repository") or {}).get("hasVulnerabilityAlertsEnabled") if status == 200 else None
        if on is not None:
            return facts(dependabotAlertsOn=bool(on), detail=f"hasVulnerabilityAlertsEnabled={on}")
        status, _ = self.gh.api(f"repos/{self.full}/vulnerability-alerts")
        if status == 204:
            return facts(dependabotAlertsOn=True, detail="enabled")
        return unreadable(f"HTTP {status}: disabled or no Administration read")

    # --- history-protection
    def _rule_or_classic(self, rule_type, classic_key, fact):
        s, rules = self.rules()
        if s == 200 and any(r.get("type") == rule_type for r in rules):
            return facts(**{fact: True}, detail=f"ruleset: {rule_type}")
        status, prot = self.protection()
        if status == 200:
            blocked = not (prot.get(classic_key) or {}).get("enabled", False)
            return facts(**{fact: blocked}, detail=f"classic: {classic_key}.enabled={not blocked}")
        if s == 200:
            return facts(**{fact: False}, detail=f"no {rule_type} rule on the default branch; classic protection HTTP {status}")
        return unreadable(f"rules HTTP {s}, protection HTTP {status}")

    def sense_no_force_push(self):
        return self._rule_or_classic("non_fast_forward", "allow_force_pushes", "forcePushBlocked")

    def sense_no_deletion(self):
        return self._rule_or_classic("deletion", "allow_deletions", "deletionBlocked")

    # --- license-by-type
    def sense_license_allowed(self):
        spdx = (self.data.get("license") or {}).get("spdx_id") or "none"
        return facts(license=spdx, detail=spdx)

    # --- release-integrity
    def _stable_release(self):
        status, rel = self.latest_release()
        if status == 404:
            return None, "no non-prerelease release"
        if status != 200:
            return None, f"HTTP {status}"
        return rel, ""

    def sense_sbom_attached(self):
        rel, why = self._stable_release()
        if rel is None:
            return facts(stableRelease=False, sbomAttached=False, detail=why) if why.startswith("no ") else unreadable(why)
        names = [a["name"] for a in rel.get("assets", [])]
        sbom = [n for n in names if any(fnmatch.fnmatch(n.lower(), g) for g in SBOM_GLOBS)]
        return facts(stableRelease=True, sbomAttached=bool(sbom), detail=f"{rel.get('tag_name')}: {', '.join(sbom) or 'no SBOM among ' + str(len(names)) + ' asset(s)'}")

    def sense_release_immutable(self):
        rel, why = self._stable_release()
        if rel is None:
            return facts(stableRelease=False, releaseImmutable=False, detail=why) if why.startswith("no ") else unreadable(why)
        imm = bool(rel.get("immutable"))
        return facts(stableRelease=True, releaseImmutable=imm, detail=f"{rel.get('tag_name')}: immutable={imm}")

    # --- secret-protection
    def sense_push_protection_on(self):
        sa = self.data.get("security_and_analysis")
        if not sa:
            return unreadable("security_and_analysis absent (needs Administration read)")
        st = (sa.get("secret_scanning_push_protection") or {}).get("status")
        return facts(pushProtectionOn=st == "enabled", detail=f"secret_scanning_push_protection={st}")

    # --- security-policy
    def sense_security_policy_present(self):
        status, data = self.gh.graphql(
            "query($owner:String!,$name:String!){repository(owner:$owner,name:$name){isSecurityPolicyEnabled}}",
            owner=self.owner, name=self.name)
        if status != 200:
            return unreadable(str(data)[:80])
        ok = bool(data["data"]["repository"]["isSecurityPolicyEnabled"])
        return facts(securityPolicyPresent=ok, detail=f"isSecurityPolicyEnabled={ok}")

    def sense_private_reporting_on(self):
        status, data = self.gh.api(f"repos/{self.full}/private-vulnerability-reporting")
        if status != 200:
            return unreadable(f"HTTP {status}")
        return facts(privateReportingOn=bool(data.get("enabled")), detail=f"enabled={data.get('enabled')}")

    # --- semantic-versioning
    def sense_semver_tags(self):
        status, rels = self.gh.api(f"repos/{self.full}/releases?per_page=100", paginate=True)
        if status != 200:
            return unreadable(f"HTTP {status}")
        cutoff = now() - dt.timedelta(days=365)
        recent = [r for r in rels if not r.get("draft") and r.get("published_at") and parse_time(r["published_at"]) >= cutoff]
        bad = [r["tag_name"] for r in recent if not SEMVER.match(r["tag_name"])]
        if not recent:
            return facts(offPatternReleaseTags=0, detail="no release in the last 12 months")
        return facts(offPatternReleaseTags=len(bad), detail=f"{len(recent)} release(s); off-pattern: {', '.join(bad[:5]) or 'none'}")

    # --- static-analysis
    def sense_code_scanning_configured(self):
        status, data = self.gh.api(f"repos/{self.full}/code-scanning/default-setup")
        if status == 200 and data.get("state") == "configured":
            return facts(codeScanningConfigured=True, detail="default setup configured")
        s2, analyses = self.gh.api(f"repos/{self.full}/code-scanning/analyses?per_page=1")
        if s2 == 200:
            return facts(codeScanningConfigured=bool(analyses), detail=f"{len(analyses)} recent analysis(es)" if analyses else "no analyses")
        if s2 == 404:
            return facts(codeScanningConfigured=False, detail="code scanning not enabled")
        return unreadable(f"default-setup HTTP {status}, analyses HTTP {s2}")

    def _code_scanning_overdue(self, fact, levels, days):
        status, alerts = self.gh.api(f"repos/{self.full}/code-scanning/alerts?state=open&per_page=100", paginate=True)
        if status == 404:
            return facts(codeScanningEnabled=False, **{fact: 0}, detail="code scanning not enabled")
        if status != 200:
            return unreadable(f"HTTP {status}")
        cutoff = now() - dt.timedelta(days=days)
        old = [a for a in alerts if (a.get("rule") or {}).get("security_severity_level") in levels and parse_time(a["created_at"]) < cutoff]
        return facts(codeScanningEnabled=True, **{fact: len(old)}, detail=f"{len(old)} {'/'.join(levels)} alert(s) older than {days} days")

    def sense_no_open_critical(self):
        return self._code_scanning_overdue("criticalAlertsOverdue", ("critical",), 14)

    def sense_scanning_clean(self):
        return self._code_scanning_overdue("mediumPlusAlertsOverdue", ("medium", "high", "critical"), 60)

    # --- vulnerability-remediation
    def sense_dependency_alerts_on_time(self):
        status, alerts = self.gh.api(f"repos/{self.full}/dependabot/alerts?state=open&per_page=100", paginate=True)
        if status != 200:
            return unreadable(f"HTTP {status}")
        late = []
        for a in alerts:
            sev = (a.get("security_advisory") or {}).get("severity")
            age = now() - parse_time(a["created_at"])
            if (sev == "critical" and age > dt.timedelta(days=14)) or (sev in ("high", "medium") and age > dt.timedelta(days=60)):
                late.append(f"{a['dependency']['package']['name']}({sev},{age.days}d)")
        return facts(dependabotAlertsOverdue=len(late), detail=f"{len(alerts)} open; late: {', '.join(late[:5]) or 'none'}")

    # --- verified-code-owners
    def sense_verified_owners(self):
        path, text, denied = self.codeowners_text()
        if denied:
            return unreadable(f"contents HTTP {denied}")
        if path is None:
            return facts(codeownersPresent=False, codeOwners=0, unverifiedCodeOwners=0, detail="no CODEOWNERS")
        lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        handles = {h for line in lines for h in re.findall(r"@([A-Za-z0-9-]+)(?![/\w])", line)}
        problems, blocked = [], []
        for org, slug in sorted({t for line in lines for t in re.findall(r"@([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)", line)}):
            status, members = self.gh.api(f"orgs/{org}/teams/{slug}/members?per_page=100", paginate=True)
            if status != 200:
                blocked.append(f"@{org}/{slug}: team members HTTP {status}")
                continue
            handles.update(m["login"] for m in members)
        by_login = {m.get("login"): m for m in self.registry.maintainers.values()}
        cutoff = now() - dt.timedelta(days=365)
        for h in sorted(handles):
            m = by_login.get(h)
            if not m:
                problems.append(f"{h}: not in maintainers.yaml")
                continue
            v = m.get("verified") or m.get("verified_on") or (m.get("verification") or {}).get("date")
            if not v or parse_time(str(v) + ("T00:00:00+00:00" if len(str(v)) == 10 else "")) < cutoff:
                problems.append(f"{h}: no verification within 12 months")
        if blocked and not problems:
            return unreadable("; ".join(blocked))
        return facts(codeownersPresent=True, codeOwners=len(handles), unverifiedCodeOwners=len(problems),
                     detail="; ".join(problems + blocked) or (f"{len(handles)} owner(s) verified" if handles else f"{path} names no owner"))

    # --- workflow-least-privilege
    def sense_default_token_read(self):
        status, data = self.gh.api(f"repos/{self.full}/actions/permissions/workflow")
        if status != 200:
            return unreadable(f"HTTP {status}")
        v = data.get("default_workflow_permissions")
        return facts(defaultTokenRead=v == "read", detail=f"default_workflow_permissions={v}")

    def type_topic(self):
        """The `openmbee-<type>` topic (kinds.yaml type_topics) operators declare their type with; informational."""
        topic = self.registry.type_topics.get(self.type)
        return {"expected": topic, "declared": topic in (self.data.get("topics") or [])}
