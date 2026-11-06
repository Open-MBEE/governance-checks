#!/usr/bin/env python3
"""Generate the SysML v2 governance model from the pinned repo-registry data.

`model/governance.sysml` holds the kinds (type, stage, tier), a `Repository` with one attribute per fact the
policies read, and one `requirement def` per automated or attested check, grouped in a package per policy: the
policy's `applies_if` is the requirement's assumption, the check's predicate its required constraint.
`model/repositories.sysml` holds one part per entry in repos.yaml, bound to its kind and attestations, and one
`satisfy` assertion per check in effect for it. OpenSysML evaluates the assertions over the sensed facts
(sense.py); nothing here decides a verdict.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import yaml

from common import CHECK_APPLIES, Registry, applies

# The facts the sensors observe (sense.py), as attributes of Repository: name, type, where the registry reads it.
FACTS = [
    ("archived", "Boolean", "GET /repos/{owner}/{repo} .archived"),
    ("approvalsRequired", "Integer", "default-branch pull_request rule: required_approving_review_count"),
    ("codeOwnerReviewRequired", "Boolean", "default-branch pull_request rule: require_code_owner_review"),
    ("requiredStatusChecks", "Integer", "default-branch required_status_checks rule: number of contexts"),
    ("codeownersPresent", "Boolean", "CODEOWNERS at .github/, the root or docs/"),
    ("codeownersErrors", "Integer", "GET /repos/{owner}/{repo}/codeowners/errors: number of errors"),
    ("contributingPresent", "Boolean", "GET /repos/{owner}/{repo}/community/profile files.contributing"),
    ("readmePresent", "Boolean", "GET /repos/{owner}/{repo}/community/profile files.readme"),
    ("dependabotAlertsOn", "Boolean", "GraphQL repository.hasVulnerabilityAlertsEnabled"),
    ("forcePushBlocked", "Boolean", "default-branch non_fast_forward rule, or classic allow_force_pushes off"),
    ("deletionBlocked", "Boolean", "default-branch deletion rule, or classic allow_deletions off"),
    ("license", "String", "GET /repos/{owner}/{repo} .license.spdx_id"),
    ("stableRelease", "Boolean", "GET /repos/{owner}/{repo}/releases/latest exists (a non-prerelease release)"),
    ("sbomAttached", "Boolean", "latest release has an SPDX or CycloneDX asset"),
    ("releaseImmutable", "Boolean", "latest release .immutable"),
    ("pushProtectionOn", "Boolean", "GET /repos/{owner}/{repo} security_and_analysis.secret_scanning_push_protection"),
    ("securityPolicyPresent", "Boolean", "GraphQL repository.isSecurityPolicyEnabled"),
    ("privateReportingOn", "Boolean", "GET /repos/{owner}/{repo}/private-vulnerability-reporting .enabled"),
    ("offPatternReleaseTags", "Integer", "releases of the last 12 months whose tag is not vMAJOR.MINOR.PATCH"),
    ("codeScanningConfigured", "Boolean", "code-scanning default setup configured, or analyses exist"),
    ("criticalAlertsOverdue", "Integer", "open critical code-scanning alerts older than 14 days"),
    ("mediumPlusAlertsOverdue", "Integer", "open medium-or-higher code-scanning alerts older than 60 days"),
    ("dependabotAlertsOverdue", "Integer", "open Dependabot alerts past 14 (critical) or 60 (high, medium) days"),
    ("unverifiedCodeOwners", "Integer", "code owners not in maintainers.yaml or not verified within 12 months"),
    ("defaultTokenRead", "Boolean", "GET /repos/{owner}/{repo}/actions/permissions/workflow .default_workflow_permissions == read"),
]

# Each automated check's predicate over the facts; license-allowed is generated from the policy's allowed list.
PREDICATES = {
    "archived": "repo.archived",
    "review-required": "repo.approvalsRequired >= 1 and repo.codeOwnerReviewRequired",
    "checks-required": "repo.requiredStatusChecks >= 1",
    "codeowners-present": "repo.codeownersPresent",
    "codeowners-valid": "repo.codeownersErrors == 0",
    "contributing-present": "repo.contributingPresent",
    "readme-present": "repo.readmePresent",
    "dependabot-alerts-on": "repo.dependabotAlertsOn",
    "no-force-push": "repo.forcePushBlocked",
    "no-deletion": "repo.deletionBlocked",
    "sbom-attached": "repo.stableRelease and repo.sbomAttached",
    "release-immutable": "repo.stableRelease and repo.releaseImmutable",
    "push-protection-on": "repo.pushProtectionOn",
    "security-policy-present": "repo.securityPolicyPresent",
    "private-reporting-on": "repo.privateReportingOn",
    "semver-tags": "repo.offPatternReleaseTags == 0",
    "code-scanning-configured": "repo.codeScanningConfigured",
    "no-open-critical": "repo.codeScanningConfigured and repo.criticalAlertsOverdue == 0",
    "scanning-clean": "repo.codeScanningConfigured and repo.mediumPlusAlertsOverdue == 0",
    "dependency-alerts-on-time": "repo.dependabotAlertsOverdue == 0",
    "verified-owners": "repo.codeownersPresent and repo.unverifiedCodeOwners == 0",
    "default-token-read": "repo.defaultTokenRead",
}


def pascal(s: str) -> str:
    return "".join(p[:1].upper() + p[1:] for p in s.replace("_", "-").split("-"))


def camel(s: str) -> str:
    p = pascal(s)
    return p[:1].lower() + p[1:]


def attested_fact(check_id: str) -> str:
    return "attested" + pascal(check_id)


def kind_ref(attr: str, value: str) -> str:
    return f"{attr.capitalize()}::{value}"


def applies_expr(rule) -> str:
    if rule is None:
        return "true"
    if "all" in rule:
        return " and ".join(f"({applies_expr(r)})" for r in rule["all"])
    if "any" in rule:
        return " or ".join(f"({applies_expr(r)})" for r in rule["any"])
    if "not" in rule:
        return f"not ({applies_expr(rule['not'])})"
    attr = rule["attr"]
    if "eq" in rule:
        return f"repo.{attr} == {kind_ref(attr, rule['eq'])}"
    if "in" in rule:
        return " or ".join(f"repo.{attr} == {kind_ref(attr, v)}" for v in rule["in"])
    raise SystemExit(f"construction error: unsupported applies_if clause {rule}")


def license_expr(allowed: dict) -> str:
    alts = []
    for type_, licenses in allowed.items():
        lic = " or ".join(f'repo.license == "{l}"' for l in licenses) or "false"
        alts.append(f"(repo.type == Type::{type_} and ({lic}))")
    return " or ".join(alts)


def doc(text: str, indent: str) -> str:
    text = " ".join(str(text).split()).replace("*/", "* /")
    return f"{indent}doc /* {text} */\n"


def repo_policies(registry: Registry):
    return [p for p in registry.policies if p.get("scope", "repository") == "repository"]


def attested_checks(registry: Registry):
    return [c for p in repo_policies(registry) for c in p["checks"].get("attested") or []]


def governance_sysml(registry: Registry, ref: str) -> str:
    types = list(registry.kinds)
    stages = sorted({s for t in types for s in registry.kinds[t]}, key=lambda s: ["sandbox", "incubating", "graduated", "archived"].index(s) if s in ("sandbox", "incubating", "graduated", "archived") else 9)
    tiers = sorted({registry.kinds[t][s]["tier"] for t in types for s in registry.kinds[t]}, key=lambda x: ["low", "medium", "high", "none"].index(x) if x in ("low", "medium", "high", "none") else 9)
    out = [f"package Governance {{\n", doc(f"Generated by model.py from Open-MBEE/repo-registry at {ref}; edit the registry or the generator, not this file.", "    ")]
    out.append("    private import ScalarValues::*;\n\n")
    out.append("    enum def Type { " + " ".join(f"{t};" for t in types) + " }\n")
    out.append("    enum def Stage { " + " ".join(f"{s};" for s in stages) + " }\n")
    out.append("    enum def Tier { " + " ".join(f"{t};" for t in tiers) + " }\n\n")
    out.append("    part def Repository {\n")
    out.append(doc("A repository measured at a type and stage (repos.yaml); the tier follows from the registry's kinds table.", "        "))
    out.append("        attribute type : Type;\n        attribute stage : Stage;\n        attribute tier : Tier;\n\n")
    for name, type_, reads in FACTS:
        out.append(doc(reads, "        "))
        out.append(f"        attribute {name} : {type_};\n")
    out.append("\n")
    for c in attested_checks(registry):
        out.append(doc(f"Attested in repos.yaml: {c['statement']}", "        "))
        out.append(f"        attribute {attested_fact(c['id'])} : Boolean;\n")
    out.append("    }\n\n    package Policies {\n")
    for p in repo_policies(registry):
        out.append(f"        package {pascal(p['id'])} {{\n")
        out.append(doc(f"{p['id']}: {p.get('meaning', p.get('name', ''))}", "            "))
        for c in p["checks"].get("automated") or []:
            pred = license_expr(p["allowed_licenses"]) if c["id"] == "license-allowed" else PREDICATES.get(c["id"])
            if pred is None:
                raise SystemExit(f"construction error: no predicate for automated check {p['id']}/{c['id']}")
            out.append(f"            requirement def {pascal(c['id'])} {{\n")
            out.append(doc(f"{c['id']} reads: {c.get('reads', '')}", "                "))
            out.append("                subject repo : Repository;\n")
            out.append(f"                assume constraint inEffect {{ {applies_expr(p.get('applies_if'))} }}\n")
            out.append(f"                require constraint {camel(c['id'])} {{ {pred} }}\n")
            out.append("            }\n")
        for c in p["checks"].get("attested") or []:
            out.append(f"            requirement def {pascal(c['id'])} {{\n")
            out.append(doc(f"{c['id']} (attested): {c['statement']}", "                "))
            out.append("                subject repo : Repository;\n")
            rule = {"all": [r for r in (p.get("applies_if"), CHECK_APPLIES.get(c["id"])) if r]} or None
            out.append(f"                assume constraint inEffect {{ {applies_expr(rule if rule['all'] else None)} }}\n")
            out.append(f"                require constraint {camel(c['id'])} {{ repo.{attested_fact(c['id'])} }}\n")
            out.append("            }\n")
        out.append("        }\n")
    out.append("    }\n}\n")
    return "".join(out)


def in_effect(registry: Registry, entry: dict):
    """(policy, check, kind) for every check in effect at the entry's type/stage."""
    attrs = {"type": entry["type"], "stage": entry["stage"], "tier": registry.tier(entry["type"], entry["stage"])}
    rows = []
    for p in repo_policies(registry):
        if not applies(p.get("applies_if"), attrs):
            continue
        rows += [(p, c, "automated") for c in p["checks"].get("automated") or []]
        rows += [(p, c, "attested") for c in p["checks"].get("attested") or [] if applies(CHECK_APPLIES.get(c["id"]), attrs)]
    return rows


def element(name: str) -> str:
    return f"Repositories::'{name}'"


def assertion(name: str, check_id: str) -> str:
    return f"'{name}: {check_id}'"


def repositories_sysml(registry: Registry, entries: list[dict]) -> str:
    out = ["package Repositories {\n", doc("Generated by model.py from repos.yaml; the facts are imported at run time (sense.py).", "    "),
           "    private import Governance::*;\n\n"]
    for e in entries:
        tier = registry.tier(e["type"], e["stage"])
        out.append(f"    part '{e['name']}' : Repository {{\n")
        out.append(f"        attribute :>> type = Type::{e['type']};\n        attribute :>> stage = Stage::{e['stage']};\n        attribute :>> tier = Tier::{tier};\n")
        attest = e.get("attest") or {}
        for p, c, kind in in_effect(registry, e):
            if kind == "attested":
                out.append(f"        attribute :>> {attested_fact(c['id'])} = {'true' if c['id'] in attest else 'false'};\n")
        out.append("    }\n")
        for p, c, kind in in_effect(registry, e):
            out.append(f"    satisfy requirement {assertion(e['name'], c['id'])} : Policies::{pascal(p['id'])}::{pascal(c['id'])} by '{e['name']}';\n")
        out.append("\n")
    out.append("}\n")
    return "".join(out)


def generate(registry: Registry, config: dict, out_dir: pathlib.Path) -> dict[str, str]:
    files = {"governance.sysml": governance_sysml(registry, config["registry"]["ref"]),
             "repositories.sysml": repositories_sysml(registry, config["repos"])}
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out_dir / name).write_text(text)
    return files


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="repos.yaml")
    ap.add_argument("--registry", required=True, help="path to a checkout of Open-MBEE/repo-registry at the pinned ref")
    ap.add_argument("--out", default="model")
    ap.add_argument("--check", action="store_true", help="fail if the files under --out are not what would be generated")
    args = ap.parse_args(argv)
    config = yaml.safe_load(pathlib.Path(args.config).read_text())
    registry = Registry(pathlib.Path(args.registry))
    out = pathlib.Path(args.out)
    if args.check:
        stale = [n for n, t in {"governance.sysml": governance_sysml(registry, config["registry"]["ref"]),
                                "repositories.sysml": repositories_sysml(registry, config["repos"])}.items()
                 if not (out / n).exists() or (out / n).read_text() != t]
        if stale:
            print("stale: " + ", ".join(stale) + " (run model.py to regenerate)", file=sys.stderr)
            return 1
        print("model up to date")
        return 0
    for name in generate(registry, config, out):
        print(f"wrote {out / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
