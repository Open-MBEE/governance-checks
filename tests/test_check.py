"""Unit tests with a fake GitHub: each sensor's facts, the generated model, the verdict mapping, the regression rule."""
import base64
import datetime as dt
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check  # noqa: E402
import common  # noqa: E402
import model  # noqa: E402
import sense  # noqa: E402

REGISTRY = pathlib.Path(__file__).parent / "fixtures" / "registry"
SYSML = os.environ.get("OPENSYSML_SYSML") or shutil.which("sysml")


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


# ------------------------------------------------------------------------------------------------------------ model

def test_every_automated_check_has_a_sensor_and_a_predicate():
    reg = registry()
    r = repo({})
    for p in model.repo_policies(reg):
        for c in p["checks"].get("automated") or []:
            assert r.sensor(c["id"]) is not None, c["id"]
            assert c["id"] == "license-allowed" or c["id"] in model.PREDICATES, c["id"]
    names = {f[0] for f in model.FACTS}
    for pred in model.PREDICATES.values():
        for fact in {w[5:] for w in pred.replace("(", " ").split() if w.startswith("repo.")}:
            assert fact in names, fact


def test_applies_and_license_expressions():
    assert model.applies_expr({"attr": "tier", "eq": "high"}) == "repo.tier == Tier::high"
    assert model.applies_expr({"all": [{"attr": "type", "eq": "tool"}, {"attr": "stage", "in": ["incubating", "graduated"]}]}) == \
        "(repo.type == Type::tool) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated)"
    assert model.applies_expr(None) == "true"
    assert model.license_expr({"tool": ["Apache-2.0", "MIT"]}) == '(repo.type == Type::tool and (repo.license == "Apache-2.0" or repo.license == "MIT"))'


def test_generated_model_shape():
    reg = registry()
    gov = model.governance_sysml(reg, "abc")
    assert "requirement def ReviewRequired" in gov and "assume constraint inEffect { repo.tier == Tier::high }" in gov
    assert "require constraint reviewRequired { repo.approvalsRequired >= 1 and repo.codeOwnerReviewRequired }" in gov
    assert "attribute attestedDesignCurrent : Boolean;" in gov
    entries = [{"name": "o/r", "type": "tool", "stage": "sandbox"},
               {"name": "o/g", "type": "tool", "stage": "graduated", "attest": {"design-current": "docs/x.md"}}]
    reps = model.repositories_sysml(reg, entries)
    assert "satisfy requirement 'o/r: codeowners-present'" in reps and "'o/r: review-required'" not in reps
    assert "attribute :>> attestedDesignCurrent = true;" in reps and "attribute :>> attestedStableReleasePolicy = false;" in reps
    mid = {c["id"] for _, c, _ in model.in_effect(reg, {"name": "o/m", "type": "tool", "stage": "incubating"})}
    assert "semver-tags" in mid and "stable-release-policy" not in mid


@pytest.mark.skipif(not SYSML, reason="no sysml binary (set OPENSYSML_SYSML)")
def test_opensysml_decides_the_verdicts(tmp_path):
    reg = registry()
    entries = [{"name": "o/r", "type": "tool", "stage": "graduated", "attest": {"design-current": "x"}}]
    (tmp_path / "m").mkdir()
    model.generate(reg, {"registry": {"ref": "t"}, "repos": entries}, tmp_path / "m")
    records = [{"element": model.element("o/r"), "approvalsRequired": 1, "codeOwnerReviewRequired": True, "readmePresent": False,
                "license": "GPL-3.0"}]
    verdicts = check.evaluate(SYSML, tmp_path / "m", tmp_path / "b", records)
    status = {k[1]: v["status"] for k, v in verdicts.items()}
    assert status["review-required"] == "holds" and status["readme-present"] == "fails" and status["license-allowed"] == "fails"
    assert status["design-current"] == "holds" and status["signed-with-provenance"] == "fails"
    assert status["checks-required"] == "unresolved"


# ----------------------------------------------------------------------------------------------------------- driver

def test_run_all_maps_verdicts_and_unreadable_facts():
    reg = registry()
    e = {"name": "o/r", "type": "tool", "stage": "graduated", "attest": {"design-current": "docs/x.md"}}
    said = {c["id"]: sense.Sensed({}, "ok") for _, c, kind in model.in_effect(reg, e) if kind == "automated"}
    said["push-protection-on"] = sense.unreadable("HTTP 403")
    verdicts = {("o/r", c["id"]): {"status": "holds", "lines": []} for _, c, _ in model.in_effect(reg, e)}
    verdicts[("o/r", "sbom-attached")] = {"status": "fails", "lines": ["  Required condition evaluated to false: repo.stableRelease and repo.sbomAttached"]}
    verdicts[("o/r", "push-protection-on")] = {"status": "fails", "lines": []}
    verdicts[("o/r", "signed-with-provenance")] = {"status": "fails", "lines": []}
    notes = {"o/r": {"said": said, "topic": {"expected": "openmbee-tool", "declared": False}, "id": 7}}
    by = {c["check"]: c for c in check.run_all(reg, [e], verdicts, notes)[0]["checks"]}
    assert by["review-required"]["status"] == "pass"
    assert by["sbom-attached"]["status"] == "fail" and "evaluated to false" in by["sbom-attached"]["detail"]
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
