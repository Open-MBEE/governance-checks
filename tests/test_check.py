"""Unit tests with a fake GitHub: each sensor's facts, the generated model, the verdict mapping, the regression rule."""
import base64
import datetime as dt
import json
import re
import pathlib
import sys

import pytest
import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check  # noqa: E402
import common  # noqa: E402
import model  # noqa: E402
import sense  # noqa: E402

REGISTRY = pathlib.Path(__file__).parent / "fixtures" / "registry"
PIN = yaml.safe_load((pathlib.Path(__file__).resolve().parents[1] / "repos.yaml").read_text())["opensysml"]


@pytest.fixture(scope="module")
def conn():
    with check.connect(PIN) as c:
        yield c


class FakeGitHub:
    def __init__(self, responses):
        self.responses = responses

    def api(self, path, paginate=False, method=None):
        for k, result in self.responses.items():
            if k == "graphql":
                continue
            if path == k or (k.endswith("?") and path.startswith(k)) or path.startswith(k + "?"):
                return result
        return (404, {"message": "Not Found"})

    def graphql(self, query, **variables):
        return self.responses.get("graphql", (0, {}))


def registry():
    return common.Registry(REGISTRY)


def repo(responses, **entry):
    base = {"repos/o/r": (200, {"id": 7, "default_branch": "develop", "archived": False, "license": {"spdx_id": "Apache-2.0"},
                                "topics": ["openmbee-tool"], "permissions": {"admin": False}})}
    base.update(responses)
    e = {"name": "o/r", "type": "tool", "stage": "graduated"}
    e.update(entry)
    return sense.Repository(FakeGitHub(base), registry(), e)


def iso(days_ago, hours=0):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago, hours=hours)).isoformat()


def test_applies_if_clauses():
    attrs = {"type": "tool", "stage": "graduated", "tier": "high"}
    assert common.applies({"attr": "tier", "eq": "high"}, attrs)
    assert common.applies({"all": [{"attr": "type", "in": ["tool"]}, {"attr": "stage", "in": ["incubating", "graduated"]}]}, attrs)
    assert not common.applies({"not": {"attr": "stage", "eq": "graduated"}}, attrs)
    assert registry().tier("tool", "sandbox") == "low" and registry().tier("tool", "graduated") == "high"


# ---------------------------------------------------------------------------------------------------------- sensors

def test_review_required_from_ruleset():
    rules = (200, [{"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True}}])
    s = repo({"repos/o/r/rules/branches/develop": rules}).sense_review_required()
    assert s.facts == {"approvalsRequired": 1, "codeOwnerReviewRequired": True} and not s.unreadable
    s = repo({"repos/o/r/rules/branches/develop": (200, [])}).sense_review_required()
    assert s.facts == {"approvalsRequired": 0, "codeOwnerReviewRequired": False}
    assert repo({"repos/o/r/rules/branches/develop": (403, {})}).sense_review_required().unreadable


def test_checks_and_history_rules():
    rules = (200, [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "test"}, {"context": "CodeQL"}]}},
                   {"type": "non_fast_forward"}])
    r = repo({"repos/o/r/rules/branches/develop": rules})
    assert r.sense_checks_required().facts == {"requiredStatusChecks": 2}
    classic = {"repos/o/r/rules/branches/develop": (200, []), "repos/o/r/branches/develop/protection":
               (200, {"required_status_checks": {"contexts": [], "checks": [{"context": "ci/build", "app_id": 1}]}})}
    assert repo(classic).sense_checks_required().facts == {"requiredStatusChecks": 1}
    assert r.sense_no_force_push().facts == {"forcePushBlocked": True}
    assert r.sense_no_deletion().facts == {"deletionBlocked": False}


def test_codeowners():
    content = {"repos/o/r/contents/.github/CODEOWNERS": (200, {"content": base64.b64encode(b"* @HuiJun @someone\n").decode()}),
               "repos/o/r/codeowners/errors": (200, {"errors": []})}
    r = repo(content)
    assert r.sense_codeowners_present().facts == {"codeownersPresent": True}
    assert r.sense_codeowners_valid().facts == {"codeownersErrors": 0}
    s = r.sense_verified_owners()
    assert s.facts == {"codeownersPresent": True, "codeOwners": 2, "unverifiedCodeOwners": 2} and "someone: not in maintainers.yaml" in s.detail
    assert repo({}).sense_codeowners_present().facts == {"codeownersPresent": False}
    assert repo({}).sense_verified_owners().facts == {"codeownersPresent": False, "codeOwners": 0, "unverifiedCodeOwners": 0}
    empty = {"repos/o/r/contents/CODEOWNERS": (200, {"content": ""})}
    assert repo(empty).sense_codeowners_present().facts == {"codeownersPresent": True}
    assert repo(empty).sense_verified_owners().facts == {"codeownersPresent": True, "codeOwners": 0, "unverifiedCodeOwners": 0}
    denied = {f"repos/o/r/contents/{p}": (403, {}) for p in common.CODEOWNERS_PATHS}
    assert repo(denied).sense_codeowners_present().unreadable and repo(denied).sense_verified_owners().unreadable
    team = {"repos/o/r/contents/.github/CODEOWNERS": (200, {"content": base64.b64encode(b"* @o/core\n").decode()})}
    assert repo(team).sense_verified_owners().unreadable == "@o/core: team members HTTP 404"
    team["orgs/o/teams/core/members"] = (200, [{"login": "someone"}])
    assert repo(team).sense_verified_owners().facts["unverifiedCodeOwners"] == 1


def test_dependabot_alerts_on():
    gql = lambda on: {"graphql": (200, {"data": {"repository": {"hasVulnerabilityAlertsEnabled": on}}})}
    assert repo(gql(True)).sense_dependabot_alerts_on().facts == {"dependabotAlertsOn": True}
    assert repo(gql(False)).sense_dependabot_alerts_on().facts == {"dependabotAlertsOn": False}
    assert repo({"repos/o/r/vulnerability-alerts": (204, None)}).sense_dependabot_alerts_on().facts == {"dependabotAlertsOn": True}
    assert repo({"repos/o/r/vulnerability-alerts": (404, {})}).sense_dependabot_alerts_on().unreadable


def test_release_integrity_and_semver():
    rel = (200, {"tag_name": "v1.2.0", "immutable": True, "assets": [{"name": "x.spdx.json"}]})
    r = repo({"repos/o/r/releases/latest": rel})
    assert r.sense_sbom_attached().facts == {"stableRelease": True, "sbomAttached": True}
    assert r.sense_release_immutable().facts == {"stableRelease": True, "releaseImmutable": True}
    assert repo({}).sense_sbom_attached().facts == {"stableRelease": False, "sbomAttached": False}
    rels = (200, [{"tag_name": "v1.2.0", "published_at": iso(10)}, {"tag_name": "nightly-1", "published_at": iso(5)},
                  {"tag_name": "v0.9.0-alpha.1", "published_at": iso(400)}])
    s = repo({"repos/o/r/releases": rels}).sense_semver_tags()
    assert s.facts == {"offPatternReleaseTags": 1} and "nightly-1" in s.detail


def test_security_and_settings():
    r = repo({"repos/o/r": (200, {"default_branch": "main", "security_and_analysis": {"secret_scanning_push_protection": {"status": "enabled"}}}),
              "graphql": (200, {"data": {"repository": {"isSecurityPolicyEnabled": True}}}),
              "repos/o/r/private-vulnerability-reporting": (200, {"enabled": False}),
              "repos/o/r/actions/permissions/workflow": (200, {"default_workflow_permissions": "write"})})
    assert r.sense_push_protection_on().facts == {"pushProtectionOn": True}
    assert r.sense_security_policy_present().facts == {"securityPolicyPresent": True}
    assert r.sense_private_reporting_on().facts == {"privateReportingOn": False}
    assert r.sense_default_token_read().facts == {"defaultTokenRead": False}
    assert repo({}).sense_push_protection_on().unreadable and repo({}).sense_default_token_read().unreadable
    assert repo({}).sense_license_allowed().facts == {"license": "Apache-2.0"}
    assert repo({}).type_topic() == {"expected": "openmbee-tool", "declared": True}


def test_code_scanning_and_alert_ages():
    alerts = (200, [{"rule": {"security_severity_level": "critical"}, "created_at": iso(20)},
                    {"rule": {"security_severity_level": "medium"}, "created_at": iso(61)}])
    r = repo({"repos/o/r/code-scanning/alerts": alerts, "repos/o/r/code-scanning/analyses": (200, [{"id": 1}])})
    assert r.sense_code_scanning_configured().facts == {"codeScanningConfigured": True}
    assert r.sense_no_open_critical().facts == {"codeScanningEnabled": True, "criticalAlertsOverdue": 1}
    assert r.sense_scanning_clean().facts == {"codeScanningEnabled": True, "mediumPlusAlertsOverdue": 1}
    clean = repo({"repos/o/r/code-scanning/alerts": (200, []), "repos/o/r/code-scanning/analyses": (200, [])})
    assert clean.sense_code_scanning_configured().facts == {"codeScanningConfigured": False}
    assert clean.sense_no_open_critical().facts == {"codeScanningEnabled": True, "criticalAlertsOverdue": 0}
    off = repo({"repos/o/r/code-scanning/alerts": (404, {}), "repos/o/r/code-scanning/analyses": (404, {})})
    assert off.sense_code_scanning_configured().facts == {"codeScanningConfigured": False}
    assert off.sense_no_open_critical().facts == {"codeScanningEnabled": False, "criticalAlertsOverdue": 0}
    dep = (200, [{"security_advisory": {"severity": "critical"}, "dependency": {"package": {"name": "c"}}, "created_at": iso(14, 12)},
                 {"security_advisory": {"severity": "high"}, "dependency": {"package": {"name": "h"}}, "created_at": iso(30)}])
    assert repo({"repos/o/r/dependabot/alerts": dep}).sense_dependency_alerts_on_time().facts == {"dependabotAlertsOverdue": 1}


# ---------------------------------------------------------------------------------- the model against the registry

MODEL_TEXT = model.MODEL.read_text()


def requirement_block(policy_id, check_id):
    m = re.search(rf"package {model.pascal(policy_id)} \{{.*?requirement def {model.pascal(check_id)} \{{(.*?)\n            \}}", MODEL_TEXT, re.S)
    return m.group(1) if m else None


def test_every_registry_check_is_a_requirement_with_the_policy_s_assumption():
    reg = registry()
    r = repo({})
    expected = set()
    for p in model.repo_policies(reg):
        for kind in ("automated", "attested"):
            for c in p["checks"].get(kind) or []:
                expected.add(model.requirement_name(p["id"], c["id"]))
                block = requirement_block(p["id"], c["id"])
                assert block, f"no requirement def for {p['id']}/{c['id']}"
                assume = re.search(r"assume constraint inEffect \{ (.*?) \}", block).group(1)
                assert " ".join(assume.split()) == model.applies_expr(model.check_rule(p, c)), f"{c['id']} assumption"
                if kind == "automated":
                    assert r.sensor(c["id"]) is not None, c["id"]
                else:
                    assert f"repo.{model.attested_fact(c['id'])}" in block
    declared = set(re.findall(r"^\s*requirement def (\w+)", MODEL_TEXT, re.M))
    assert declared == {n.rsplit("::", 1)[1] for n in expected}, "requirement defs without a registry check"
    lic = requirement_block("license-by-type", "license-allowed")
    stated = {t: set(re.findall(r'repo\.license == "([^"]+)"', body))
              for t, body in re.findall(r"\(repo\.type == Type::(\w+) and \((.*?)\)\)", lic)}
    assert stated == {t: set(ls) for t, ls in reg.allowed_licenses.items()}, "license lists differ from the registry"


def test_repositories_follow_repos_yaml():
    reg = registry()
    entries = [{"name": "o/r", "type": "tool", "stage": "sandbox"},
               {"name": "o/g", "type": "tool", "stage": "graduated", "attest": {"design-current": "docs/x.md"}}]
    reps = model.repositories_sysml(reg, entries)
    assert "satisfy requirement 'o/r: codeowners-present' : Policies::Codeowners::CodeownersPresent by 'o/r';" in reps
    assert "'o/r: review-required'" not in reps and "attribute :>> tier" not in reps
    assert "attribute :>> attestedDesignCurrent = true;" in reps and "attribute :>> attestedStableReleasePolicy = false;" in reps
    mid = {c["id"] for _, c, _ in model.in_effect(reg, {"name": "o/m", "type": "tool", "stage": "incubating"})}
    assert "semver-tags" in mid and "stable-release-policy" not in mid


def test_model_declares_the_facts_the_sensors_produce_and_the_registry_s_requirements(conn):
    reg = registry()
    m = model.Model(conn)
    assert m.requirements == sorted(model.requirement_name(p["id"], c["id"]) for p in model.repo_policies(reg)
                                    for kind in ("automated", "attested") for c in p["checks"].get(kind) or [])
    names = set(m.facts)
    for p in model.repo_policies(reg):
        for c in p["checks"].get("attested") or []:
            assert model.attested_fact(c["id"]) in names
    produced = {"archived", "approvalsRequired", "codeOwnerReviewRequired", "requiredStatusChecks", "codeownersPresent", "codeownersErrors",
                "contributingPresent", "readmePresent", "dependabotAlertsOn", "forcePushBlocked", "deletionBlocked", "license", "stableRelease",
                "sbomAttached", "releaseImmutable", "pushProtectionOn", "securityPolicyPresent", "privateReportingOn", "offPatternReleaseTags",
                "codeScanningConfigured", "codeScanningEnabled", "criticalAlertsOverdue", "mediumPlusAlertsOverdue", "dependabotAlertsOverdue",
                "codeOwners", "unverifiedCodeOwners", "defaultTokenRead"}
    assert produced <= names, produced - names


def test_tier_calc_matches_the_kinds_table(conn):
    reg = registry()
    m = conn.parse_sources([(str(model.MODEL), model.MODEL.read_text())], strict=True)
    for type_, stages in reg.kinds.items():
        for stage, kind in stages.items():
            [tier] = m.eval(f"Governance::TierOf(Governance::Type::{type_}, Governance::Stage::{stage})")
            assert tier.literal_id == f"Governance::Tier::{kind['tier']}", f"{type_}/{stage}"


def test_opensysml_decides_the_verdicts(conn, tmp_path):
    reg = registry()
    entries = [{"name": "o/r", "type": "tool", "stage": "graduated", "attest": {"design-current": "x"}}]
    (tmp_path / "m").mkdir()
    model.generate(reg, {"repos": entries}, tmp_path / "m")
    records = [{"element": model.element("o/r"), "approvalsRequired": 1, "codeOwnerReviewRequired": True, "readmePresent": False,
                "license": "GPL-3.0"}]
    verdicts = check.evaluate(conn, tmp_path / "m", tmp_path / "b", records)
    status = {k[1]: v["status"] for k, v in verdicts.items()}
    assert status["review-required"] == "holds" and status["readme-present"] == "violated" and status["license-allowed"] == "violated"
    assert status["design-current"] == "holds" and status["signed-with-provenance"] == "violated"
    assert status["checks-required"] == "undecided"
    assert verdicts[("o/r", "readme-present")]["condition"] == "repo.readmePresent"
    assert "no value for feature repo.requiredStatusChecks" in verdicts[("o/r", "checks-required")]["error"]


# ----------------------------------------------------------------------------------------------------------- driver

def test_run_all_maps_verdicts_and_unreadable_facts():
    reg = registry()
    e = {"name": "o/r", "type": "tool", "stage": "graduated", "attest": {"design-current": "docs/x.md"}}
    said = {c["id"]: sense.Sensed({}, "ok") for _, c, kind in model.in_effect(reg, e) if kind == "automated"}
    said["push-protection-on"] = sense.unreadable("HTTP 403")
    verdicts = {("o/r", c["id"]): {"status": "holds", "condition": ""} for _, c, _ in model.in_effect(reg, e)}
    verdicts[("o/r", "sbom-attached")] = {"status": "violated", "condition": "repo.stableRelease and repo.sbomAttached"}
    verdicts[("o/r", "push-protection-on")] = {"status": "violated", "condition": "repo.pushProtectionOn"}
    verdicts[("o/r", "signed-with-provenance")] = {"status": "violated", "condition": "repo.attestedSignedWithProvenance"}
    notes = {"o/r": {"said": said, "topic": {"expected": "openmbee-tool", "declared": False}, "id": 7}}
    by = {c["check"]: c for c in check.run_all(reg, [e], verdicts, notes)[0]["checks"]}
    assert by["review-required"]["status"] == "pass"
    assert by["sbom-attached"]["status"] == "fail" and by["sbom-attached"]["detail"].endswith("; evaluated to false: repo.stableRelease and repo.sbomAttached")
    assert by["push-protection-on"] == {**by["push-protection-on"], "status": "unreadable", "detail": "HTTP 403"}
    assert by["design-current"]["status"] == "attested" and by["signed-with-provenance"]["status"] == "unattested"
    assert by["archived"]["status"] == "n/a"
    reg.deviations[("7", "release-integrity")] = {"reason": "source-only"}
    by = {c["check"]: c for c in check.run_all(reg, [e], verdicts, notes)[0]["checks"]}
    assert by["sbom-attached"]["status"] == "exception"


def test_regressions_on_good_to_bad_or_unreadable():
    results = [{"name": "o/r", "checks": [
        {"policy": "p", "check": "a", "status": "fail", "detail": ""},
        {"policy": "p", "check": "b", "status": "unreadable", "detail": ""},
        {"policy": "p", "check": "c", "status": "fail", "detail": ""}]}]
    baseline = {"o/r": {"checks": [{"check": "a", "status": "pass"}, {"check": "b", "status": "pass"}, {"check": "c", "status": "fail"}]}}
    regs = check.regressions(results, baseline)
    assert [r.split(" (")[0] for r in regs] == ["o/r: p/a pass -> fail", "o/r: p/b pass -> unreadable"]
