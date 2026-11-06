"""Unit tests with a fake GitHub: each check's predicate, applicability, and the regression rule."""
import base64
import datetime as dt
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check  # noqa: E402

REGISTRY = pathlib.Path(__file__).parent / "fixtures" / "registry"


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
    return check.Registry(REGISTRY)


def repo(responses, **entry):
    base = {"repos/o/r": (200, {"default_branch": "develop", "archived": False, "license": {"spdx_id": "Apache-2.0"},
                                "topics": ["openmbee-tool"], "permissions": {"admin": False}})}
    base.update(responses)
    e = {"name": "o/r", "type": "tool", "stage": "graduated"}
    e.update(entry)
    return check.Repo(FakeGitHub(base), registry(), e)


def iso(days_ago):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago)).isoformat()


def test_applies_if_clauses():
    attrs = {"type": "tool", "stage": "graduated", "tier": "high"}
    assert check.applies({"attr": "tier", "eq": "high"}, attrs)
    assert check.applies({"all": [{"attr": "type", "in": ["tool"]}, {"attr": "stage", "in": ["incubating", "graduated"]}]}, attrs)
    assert not check.applies({"not": {"attr": "stage", "eq": "graduated"}}, attrs)
    assert check.applies({"any": [{"attr": "type", "eq": "media"}, {"attr": "tier", "eq": "high"}]}, attrs)


def test_tier_comes_from_kinds():
    assert registry().tier("tool", "sandbox") == "low"
    assert registry().tier("tool", "graduated") == "high"


def test_review_required_from_ruleset():
    r = repo({"repos/o/r/rules/branches/develop": (200, [
        {"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True}}])})
    assert r.check_review_required()[0] == "pass"
    r = repo({"repos/o/r/rules/branches/develop": (200, [
        {"type": "pull_request", "parameters": {"required_approving_review_count": 0, "require_code_owner_review": False}}])})
    assert r.check_review_required()[0] == "fail"


def test_review_required_no_rule_and_no_classic_read_is_fail():
    r = repo({"repos/o/r/rules/branches/develop": (200, []), "repos/o/r/branches/develop/protection": (403, {})})
    assert r.check_review_required()[0] == "fail"


def test_history_protection_rules():
    r = repo({"repos/o/r/rules/branches/develop": (200, [{"type": "deletion"}, {"type": "non_fast_forward"}])})
    assert r.check_no_force_push()[0] == "pass" and r.check_no_deletion()[0] == "pass"
    r = repo({"repos/o/r/rules/branches/develop": (200, [{"type": "deletion"}]), "repos/o/r/branches/develop/protection": (403, {})})
    assert r.check_no_force_push()[0] == "fail"


def test_checks_required():
    r = repo({"repos/o/r/rules/branches/develop": (200, [
        {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "test"}]}}])})
    assert r.check_checks_required() == ("pass", "required: test")


def test_codeowners():
    import base64
    body = base64.b64encode(b"* @HuiJun @someone\n").decode()
    r = repo({"repos/o/r/contents/.github/CODEOWNERS": (200, {"content": body}),
              "repos/o/r/codeowners/errors": (200, {"errors": []})})
    assert r.check_codeowners_present() == ("pass", ".github/CODEOWNERS")
    assert r.check_codeowners_valid()[0] == "pass"
    status, detail = r.check_verified_owners()
    assert status == "fail" and "someone: not in maintainers.yaml" in detail and "HuiJun: no verification" in detail
    assert repo({}).check_codeowners_present()[0] == "fail"


def test_dependabot_alerts_on():
    gql = lambda on: {"graphql": (200, {"data": {"repository": {"hasVulnerabilityAlertsEnabled": on}}})}
    assert repo(gql(True)).check_dependabot_alerts_on()[0] == "pass"
    assert repo(gql(False)).check_dependabot_alerts_on()[0] == "fail"
    assert repo({"repos/o/r/vulnerability-alerts": (204, None)}).check_dependabot_alerts_on()[0] == "pass"
    assert repo({"repos/o/r/vulnerability-alerts": (404, {})}).check_dependabot_alerts_on()[0] == "unreadable"


def test_codeowners_unreadable_and_teams():
    denied = {f"repos/o/r/contents/{p}": (403, {}) for p in check.CODEOWNERS_PATHS}
    assert repo(denied).check_codeowners_present()[0] == "unreadable"
    assert repo(denied).check_verified_owners()[0] == "unreadable"
    team = {"repos/o/r/contents/.github/CODEOWNERS": (200, {"content": base64.b64encode(b"* @o/core\n").decode()})}
    assert repo(team).check_verified_owners() == ("unreadable", "@o/core: team members HTTP 404")
    team["orgs/o/teams/core/members"] = (200, [{"login": "someone"}])
    status, detail = repo(team).check_verified_owners()
    assert status == "fail" and "someone: not in maintainers.yaml" in detail


def test_license_exception():
    r = repo({"repos/o/r": (200, {"id": 7, "default_branch": "main", "license": {"spdx_id": "GPL-3.0"}})})
    assert r.check_license_allowed()[0] == "fail"
    r.registry.deviations[("7", "license-by-type")] = {"reason": "depends on GPL code", "approved_by": "x"}
    status, detail = r.check_license_allowed()
    assert status == "exception" and "GPL-3.0; accepted exception" in detail


def test_license_by_type():
    assert repo({}).check_license_allowed()[0] == "pass"
    assert repo({}, type="media").check_license_allowed()[0] == "pass"
    r = repo({"repos/o/r": (200, {"default_branch": "main", "license": {"spdx_id": "GPL-3.0"}, "topics": []})})
    assert r.check_license_allowed()[0] == "fail"


def test_release_integrity():
    rel = (200, {"tag_name": "v1.2.0", "immutable": True, "assets": [{"name": "sbom.spdx.json"}, {"name": "x.tgz"}]})
    r = repo({"repos/o/r/releases/latest": rel})
    assert r.check_sbom_attached() == ("pass", "v1.2.0: sbom.spdx.json")
    assert r.check_release_immutable()[0] == "pass"
    r = repo({"repos/o/r/releases/latest": (404, {})})
    assert r.check_sbom_attached() == ("fail", "no non-prerelease release")


def test_push_protection():
    r = repo({"repos/o/r": (200, {"default_branch": "main", "license": None, "topics": [],
                                  "security_and_analysis": {"secret_scanning_push_protection": {"status": "enabled"}}})})
    assert r.check_push_protection_on()[0] == "pass"
    assert repo({}).check_push_protection_on()[0] == "unreadable"


def test_security_policy_and_pvr():
    r = repo({"graphql": (200, {"data": {"repository": {"isSecurityPolicyEnabled": True}}}),
              "repos/o/r/private-vulnerability-reporting": (200, {"enabled": False})})
    assert r.check_security_policy_present()[0] == "pass"
    assert r.check_private_reporting_on()[0] == "fail"


def test_semver_tags():
    rels = (200, [{"tag_name": "v1.0.0", "draft": False, "published_at": iso(10)},
                  {"tag_name": "v0.1.0-alpha.1", "draft": False, "published_at": iso(20)},
                  {"tag_name": "nightly", "draft": False, "published_at": iso(400)}])
    status, detail = repo({"repos/o/r/releases?": rels}).check_semver_tags()
    assert status == "fail" and detail.endswith("off-pattern: v0.1.0-alpha.1")


def test_code_scanning():
    r = repo({"repos/o/r/code-scanning/default-setup": (403, {}),
              "repos/o/r/code-scanning/analyses": (200, [{"id": 1}]),
              "repos/o/r/code-scanning/alerts": (200, [
                  {"rule": {"security_severity_level": "critical"}, "created_at": iso(20)},
                  {"rule": {"security_severity_level": "medium"}, "created_at": iso(20)}])})
    assert r.check_code_scanning_configured()[0] == "pass"
    assert r.check_no_open_critical() == ("fail", "1 critical alert(s) older than 14 days")
    assert r.check_scanning_clean()[0] == "pass"


def test_dependency_alerts_on_time():
    alerts = (200, [{"security_advisory": {"severity": "high"}, "created_at": iso(61), "dependency": {"package": {"name": "n3"}}},
                    {"security_advisory": {"severity": "critical"}, "created_at": iso(3), "dependency": {"package": {"name": "x"}}}])
    status, detail = repo({"repos/o/r/dependabot/alerts": alerts}).check_dependency_alerts_on_time()
    assert status == "fail" and "n3(high,61d)" in detail
    half_day_over = (200, [{"security_advisory": {"severity": "critical"}, "dependency": {"package": {"name": "c"}},
                            "created_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=14, hours=12)).isoformat()}])
    assert repo({"repos/o/r/dependabot/alerts": half_day_over}).check_dependency_alerts_on_time()[0] == "fail"


def test_default_token_and_topic():
    r = repo({"repos/o/r/actions/permissions/workflow": (200, {"default_workflow_permissions": "write"})})
    assert r.check_default_token_read()[0] == "fail"
    assert repo({}).check_default_token_read()[0] == "unreadable"
    assert repo({}).type_topic() == {"expected": "openmbee-tool", "declared": True}
    assert repo({}, type="media").type_topic()["declared"] is False


def test_run_entry_applicability_and_attestations():
    reg = registry()
    gh = FakeGitHub({"repos/o/r": (200, {"default_branch": "main", "archived": False, "license": {"spdx_id": "MIT"}, "topics": []})})
    low = check.run_entry(gh, reg, {"name": "o/r", "type": "tool", "stage": "sandbox"})
    by = {c["check"]: c["status"] for c in low["checks"]}
    assert by["sbom-attached"] == "n/a" and by["review-required"] == "n/a" and by["license-allowed"] == "pass"
    high = check.run_entry(gh, reg, {"name": "o/r", "type": "tool", "stage": "graduated",
                                     "attest": {"design-current": "docs/security-design.md"}})
    by = {c["check"]: c["status"] for c in high["checks"]}
    assert by["design-current"] == "attested" and by["signed-with-provenance"] == "unattested"
    assert by["sbom-attached"] == "fail"
    assert "type-topic" not in by and high["topic"]["declared"] is False
    mid = check.run_entry(gh, reg, {"name": "o/r", "type": "tool", "stage": "incubating"})
    by = {c["check"]: c["status"] for c in mid["checks"]}
    assert by["semver-tags"] != "n/a" and by["stable-release-policy"] == "n/a"
    assert {c["check"]: c["status"] for c in high["checks"]}["stable-release-policy"] == "unattested"


def test_regressions_on_good_to_bad_or_unreadable():
    results = [{"name": "o/r", "checks": [
        {"policy": "p", "check": "a", "status": "fail", "detail": ""},
        {"policy": "p", "check": "b", "status": "unreadable", "detail": ""},
        {"policy": "p", "check": "c", "status": "fail", "detail": ""}]}]
    baseline = {"o/r": {"checks": [{"check": "a", "status": "pass"}, {"check": "b", "status": "pass"}, {"check": "c", "status": "fail"}]}}
    regs = check.regressions(results, baseline)
    assert [r.split(" (")[0] for r in regs] == ["o/r: p/a pass -> fail", "o/r: p/b pass -> unreadable"]
