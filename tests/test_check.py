"""Unit tests with a fake GitHub: each sensor's facts, the generated model, the verdict mapping, the regression rule."""
import base64
import datetime as dt
import functools
import json
import re
import pathlib
import sys
import types

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


@functools.cache
def the_model():
    with check.connect(PIN) as c:
        return model.Model(c)


def repo(responses, patterns=None, **entry):
    base = {"repos/o/r": (200, {"id": 7, "default_branch": "develop", "archived": False, "license": {"spdx_id": "Apache-2.0"},
                                "topics": ["openmbee-tool"], "permissions": {"admin": False}})}
    base.update(responses)
    e = {"name": "o/r", "type": "tool", "stage": "graduated"}
    e.update(entry)
    return sense.Repository(FakeGitHub(base), registry(), e, patterns or the_model())


def iso(days_ago, hours=0):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago, hours=hours)).isoformat()


def applies(rule, attrs):
    """The registry's applies_if, evaluated here only to check what the model decides."""
    if rule is None:
        return True
    if "all" in rule:
        return all(applies(r, attrs) for r in rule["all"])
    if "any" in rule:
        return any(applies(r, attrs) for r in rule["any"])
    if "not" in rule:
        return not applies(rule["not"], attrs)
    return attrs[rule["attr"]] == rule["eq"] if "eq" in rule else attrs[rule["attr"]] in rule["in"]


class Decided:
    """An Applicability with the answers given, for the tests that do not ask OpenSysML."""

    def __init__(self, reg, entries, tier="high"):
        self.effective = {(e["name"], c["id"]): applies(model.check_rule(p, c), {**e, "tier": tier})
                          for e in entries for p, c, _ in model.checks(reg)}
        self.tiers = {e["name"]: tier for e in entries}

    in_effect, tier = model.Applicability.in_effect, model.Applicability.tier


def close(facts, **expected):
    return facts == pytest.approx(expected, abs=0.01)


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
    assert s.facts == {"codeownersPresent": True, "codeOwners": 2, "codeOwnersNotMaintainers": 1, "codeOwnersNeverVerified": 1,
                       "oldestCodeOwnerVerificationDays": 0.0}
    assert "someone: not in maintainers.yaml" in s.detail and "HuiJun: no verification date" in s.detail
    none = {"codeOwners": 0, "codeOwnersNotMaintainers": 0, "codeOwnersNeverVerified": 0, "oldestCodeOwnerVerificationDays": 0.0}
    assert repo({}).sense_codeowners_present().facts == {"codeownersPresent": False}
    assert repo({}).sense_verified_owners().facts == {"codeownersPresent": False, **none}
    r.registry.maintainers = {1: {"login": "HuiJun", "verified": iso(400)[:10]}, 2: {"login": "someone", "verified": iso(30)}}
    s = r.sense_verified_owners()
    assert s.facts["codeOwnersNotMaintainers"] == 0 and s.facts["codeOwnersNeverVerified"] == 0
    assert 400 <= s.facts["oldestCodeOwnerVerificationDays"] < 401.01
    empty = {"repos/o/r/contents/CODEOWNERS": (200, {"content": ""})}
    assert repo(empty).sense_codeowners_present().facts == {"codeownersPresent": True}
    assert repo(empty).sense_verified_owners().facts == {"codeownersPresent": True, **none}
    denied = {f"repos/o/r/contents/{p}": (403, {}) for p in common.CODEOWNERS_PATHS}
    assert repo(denied).sense_codeowners_present().unreadable and repo(denied).sense_verified_owners().unreadable
    team = {"repos/o/r/contents/.github/CODEOWNERS": (200, {"content": base64.b64encode(b"* @o/core\n").decode()})}
    assert repo(team).sense_verified_owners().unreadable == "@o/core: team members HTTP 404"
    team["orgs/o/teams/core/members"] = (200, [{"login": "someone"}])
    assert repo(team).sense_verified_owners().facts["codeOwnersNotMaintainers"] == 1


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
    assert close(s.facts, offPatternReleases=2, newestOffPatternReleaseDays=5) and "nightly-1" in s.detail
    assert repo({"repos/o/r/releases": (200, rels[1][:1])}).sense_semver_tags().facts == {"offPatternReleases": 0, "newestOffPatternReleaseDays": 0.0}


def test_the_patterns_are_the_model_s():
    m = the_model()
    for tag, ok in {"v1.2.3": True, "v0.0.0": True, "v10.20.30": True, "1.2.3": False, "v1.2": False, "v01.2.3": False,
                    "v1.2.3-rc.1": False, "v1.2.3.4": False, "v1x2x3": False}.items():
        assert bool(m.semver.match(tag)) == ok, tag
    assert m.sbom_globs == ["*.spdx.json", "*.spdx", "*.cdx.json", "*bom*.json"]
    assert not hasattr(common, "SEMVER") and not hasattr(common, "SBOM_GLOBS")
    # a sensor matches with whatever the model states
    other = types.SimpleNamespace(semver=re.compile("^nightly-"), sbom_globs=["*.txt"])
    rel = (200, {"tag_name": "v1.2.0", "assets": [{"name": "x.spdx.json"}]})
    assert repo({"repos/o/r/releases/latest": rel}, patterns=other).sense_sbom_attached().facts["sbomAttached"] is False
    rels = (200, [{"tag_name": "v1.2.0", "published_at": iso(10)}, {"tag_name": "nightly-1", "published_at": iso(5)}])
    assert close(repo({"repos/o/r/releases": rels}, patterns=other).sense_semver_tags().facts, offPatternReleases=1, newestOffPatternReleaseDays=10)


def test_evidence_resolves_only_for_a_file_or_directory_that_exists():
    link = "https://github.com/o/e/blob/develop/docs/design.md"
    attest = {"design-current": link + "#controls", "workflows-hardened": "https://github.com/o/e/tree/develop/.github/workflows/",
              "service-pins": "package.json pins every dependency", "dependency-policy": "https://example.org/policy",
              "disclosure-followed": "https://github.com/o/e/blob/develop/GONE.md", "coordinated-releases": "https://github.com/o/e/blob/develop/DENIED.md"}
    r = repo({"repos/o/e/contents/docs/design.md?ref=develop": (200, {"name": "design.md"}),
              "repos/o/e/contents/.github/workflows?ref=develop": (200, [{"name": "ci.yml"}]),
              "repos/o/e/contents/DENIED.md?ref=develop": (403, {})}, attest=attest)
    sensed = {c: r.sense_evidence("f", c) for c in [*attest, "no-built-executables"]}
    assert sensed["design-current"].facts == {"f": True} and sensed["design-current"].detail == link + "#controls"
    assert sensed["workflows-hardened"].facts == {"f": True}
    for c, why in {"service-pins": "not a link", "dependency-policy": "not a link", "disclosure-followed": "evidence not found",
                   "no-built-executables": "no entry under attest"}.items():
        assert sensed[c].facts == {"f": False} and why in sensed[c].detail, c
    assert sensed["coordinated-releases"].unreadable.startswith("evidence HTTP 403")


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
    assert close(r.sense_no_open_critical().facts, codeScanningEnabled=True, oldestCriticalScanningAlertDays=20)
    assert close(r.sense_scanning_clean().facts, codeScanningEnabled=True, oldestMediumPlusScanningAlertDays=61)
    clean = repo({"repos/o/r/code-scanning/alerts": (200, []), "repos/o/r/code-scanning/analyses": (200, [])})
    assert clean.sense_code_scanning_configured().facts == {"codeScanningConfigured": False}
    assert clean.sense_no_open_critical().facts == {"codeScanningEnabled": True, "oldestCriticalScanningAlertDays": 0.0}
    off = repo({"repos/o/r/code-scanning/alerts": (404, {}), "repos/o/r/code-scanning/analyses": (404, {})})
    assert off.sense_code_scanning_configured().facts == {"codeScanningConfigured": False}
    assert off.sense_no_open_critical().facts == {"codeScanningEnabled": False, "oldestCriticalScanningAlertDays": 0.0}
    dep = (200, [{"security_advisory": {"severity": "critical"}, "dependency": {"package": {"name": "c"}}, "created_at": iso(14, 12)},
                 {"security_advisory": {"severity": "high"}, "dependency": {"package": {"name": "h"}}, "created_at": iso(30)}])
    s = repo({"repos/o/r/dependabot/alerts": dep}).sense_dependency_alerts_on_time()
    assert close(s.facts, oldestCriticalDependabotAlertDays=14.5, oldestHighOrMediumDependabotAlertDays=30) and "h(high,30d)" in s.detail
    assert repo({"repos/o/r/dependabot/alerts": (200, [])}).sense_dependency_alerts_on_time().facts == {
        "oldestCriticalDependabotAlertDays": 0.0, "oldestHighOrMediumDependabotAlertDays": 0.0}


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
                    assert f"{{ repo.{model.attested_fact(c['id'])} and repo.{model.evidence_fact(c['id'])} }}" in block
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
    assert "attribute :>> tier" not in reps
    assert "attribute :>> attestedDesignCurrent = true;" in reps and "attribute :>> attestedStableReleasePolicy = false;" in reps
    # every registry check is asserted of every repository: which are in effect is the model's to decide
    assert reps.count("satisfy requirement") == len(entries) * len(model.checks(reg))


def test_the_model_decides_what_is_in_effect_as_the_registry_s_applies_if_does(conn, tmp_path):
    reg = registry()
    entries = [{"name": f"o/{t}-{s}", "type": t, "stage": s} for t, stages in reg.kinds.items() for s in stages]
    model.generate(reg, {"repos": entries}, tmp_path)
    decided = model.Applicability(conn, tmp_path, reg, entries)
    for e in entries:
        tier = reg.kinds[e["type"]][e["stage"]]["tier"]
        assert decided.tier(e) == tier, e["name"]
        expected = {c["id"] for p, c, _ in model.checks(reg) if applies(model.check_rule(p, c), {**e, "tier": tier})}
        assert {c["id"] for _, c, _ in decided.in_effect(reg, e)} == expected, e["name"]
    mid = {c["id"] for _, c, _ in decided.in_effect(reg, {"name": "o/tool-incubating"})}
    assert "semver-tags" in mid and "stable-release-policy" not in mid and "review-required" not in mid


def test_model_declares_the_facts_the_sensors_produce_and_the_registry_s_requirements(conn):
    reg = registry()
    m = model.Model(conn)
    assert m.requirements == sorted(model.requirement_name(p["id"], c["id"]) for p in model.repo_policies(reg)
                                    for kind in ("automated", "attested") for c in p["checks"].get(kind) or [])
    names = set(m.facts)
    for p in model.repo_policies(reg):
        for c in p["checks"].get("attested") or []:
            assert model.attested_fact(c["id"]) in names and model.evidence_fact(c["id"]) in names
    produced = {"archived", "approvalsRequired", "codeOwnerReviewRequired", "requiredStatusChecks", "codeownersPresent", "codeownersErrors",
                "contributingPresent", "readmePresent", "dependabotAlertsOn", "forcePushBlocked", "deletionBlocked", "license", "stableRelease",
                "sbomAttached", "releaseImmutable", "pushProtectionOn", "securityPolicyPresent", "privateReportingOn", "offPatternReleases",
                "newestOffPatternReleaseDays", "codeScanningConfigured", "codeScanningEnabled", "oldestCriticalScanningAlertDays",
                "oldestMediumPlusScanningAlertDays", "oldestCriticalDependabotAlertDays", "oldestHighOrMediumDependabotAlertDays",
                "codeOwners", "codeOwnersNotMaintainers", "codeOwnersNeverVerified", "oldestCodeOwnerVerificationDays", "defaultTokenRead"}
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
    entries = [{"name": "o/r", "type": "tool", "stage": "graduated",
                "attest": {"design-current": "x", "dependency-policy": "y", "service-pins": "z"}}]
    (tmp_path / "m").mkdir()
    model.generate(reg, {"repos": entries}, tmp_path / "m")
    records = [{"element": model.element("o/r"), "approvalsRequired": 1, "codeOwnerReviewRequired": True, "readmePresent": False,
                "license": "GPL-3.0", "evidenceDesignCurrentResolves": True, "evidenceDependencyPolicyResolves": False,
                "evidenceSignedWithProvenanceResolves": True}]
    verdicts = check.evaluate(conn, tmp_path / "m", tmp_path / "b", records)
    status = {k[1]: v["status"] for k, v in verdicts.items()}
    assert status["review-required"] == "holds" and status["readme-present"] == "violated" and status["license-allowed"] == "violated"
    # attested needs both: an entry in repos.yaml and evidence that resolves
    assert status["design-current"] == "holds" and status["signed-with-provenance"] == "violated"
    assert status["dependency-policy"] == "violated" and status["service-pins"] == "undecided"
    assert status["checks-required"] == "undecided"
    assert verdicts[("o/r", "readme-present")]["condition"] == "repo.readmePresent"
    assert "no value for feature repo.requiredStatusChecks" in verdicts[("o/r", "checks-required")]["error"]
    assert status["archived"] == "holds"  # not in effect for a live repository: nothing is required of it


def test_the_model_states_the_deadlines(conn, tmp_path):
    reg = registry()
    names = ["o/on-time", "o/late", "o/edge"]
    model.generate(reg, {"repos": [{"name": n, "type": "tool", "stage": "graduated"} for n in names]}, tmp_path / "m")
    owners = {"codeownersPresent": True, "codeOwners": 2, "codeOwnersNotMaintainers": 0, "codeOwnersNeverVerified": 0}
    records = [
        {"element": model.element("o/on-time"), "codeScanningEnabled": True, "oldestCriticalScanningAlertDays": 14.0,
         "oldestMediumPlusScanningAlertDays": 60.0, "oldestCriticalDependabotAlertDays": 0.0, "oldestHighOrMediumDependabotAlertDays": 59.9,
         "offPatternReleases": 0, "newestOffPatternReleaseDays": 0.0, **owners, "oldestCodeOwnerVerificationDays": 365.0},
        {"element": model.element("o/late"), "codeScanningEnabled": True, "oldestCriticalScanningAlertDays": 14.01,
         "oldestMediumPlusScanningAlertDays": 60.01, "oldestCriticalDependabotAlertDays": 14.5, "oldestHighOrMediumDependabotAlertDays": 30.0,
         "offPatternReleases": 1, "newestOffPatternReleaseDays": 5.0, **owners, "oldestCodeOwnerVerificationDays": 365.01},
        {"element": model.element("o/edge"), "codeScanningEnabled": False, "oldestCriticalScanningAlertDays": 0.0,
         "oldestMediumPlusScanningAlertDays": 0.0, "oldestCriticalDependabotAlertDays": 14.0, "oldestHighOrMediumDependabotAlertDays": 60.01,
         "offPatternReleases": 3, "newestOffPatternReleaseDays": 365.01, **owners, "codeOwnersNeverVerified": 1,
         "oldestCodeOwnerVerificationDays": 10.0}]
    verdicts = check.evaluate(conn, tmp_path / "m", tmp_path / "b", records)
    deadlines = ("no-open-critical", "scanning-clean", "dependency-alerts-on-time", "semver-tags", "verified-owners")
    status = {n: {c: verdicts[(n, c)]["status"] for c in deadlines} for n in names}
    assert set(status["o/on-time"].values()) == {"holds"}, status["o/on-time"]
    assert set(status["o/late"].values()) == {"violated"}, status["o/late"]
    assert status["o/edge"] == {"no-open-critical": "violated", "scanning-clean": "violated", "dependency-alerts-on-time": "violated",
                                "semver-tags": "holds", "verified-owners": "violated"}
    assert "repo.oldestCriticalScanningAlertDays <= 14" in verdicts[("o/late", "no-open-critical")]["condition"]


# ----------------------------------------------------------------------------------------------------------- driver

def test_run_all_maps_verdicts_and_unreadable_facts():
    reg = registry()
    e = {"name": "o/r", "type": "tool", "stage": "graduated", "attest": {"design-current": "docs/x.md"}}
    decided = Decided(reg, [e])
    said = {c["id"]: sense.Sensed({}, "ok") for _, c, kind in decided.in_effect(reg, e)}
    said["push-protection-on"] = sense.unreadable("HTTP 403")
    said["design-current"] = sense.Sensed({}, "https://github.com/o/r/blob/develop/docs/x.md")
    said["signed-with-provenance"] = sense.Sensed({}, "no entry under attest: in repos.yaml")
    said["disclosure-followed"] = sense.unreadable("evidence HTTP 403: x")
    verdicts = {("o/r", c["id"]): {"status": "holds", "condition": ""} for _, c, _ in model.checks(reg)}
    verdicts[("o/r", "sbom-attached")] = {"status": "violated", "condition": "repo.stableRelease and repo.sbomAttached"}
    verdicts[("o/r", "push-protection-on")] = {"status": "violated", "condition": "repo.pushProtectionOn"}
    verdicts[("o/r", "signed-with-provenance")] = {"status": "violated", "condition": "repo.attestedSignedWithProvenance"}
    notes = {"o/r": {"said": said, "topic": {"expected": "openmbee-tool", "declared": False}, "id": 7}}
    by = {c["check"]: c for c in check.run_all(reg, [e], verdicts, notes, decided)[0]["checks"]}
    assert by["review-required"]["status"] == "pass"
    assert by["sbom-attached"]["status"] == "fail" and by["sbom-attached"]["detail"].endswith("; evaluated to false: repo.stableRelease and repo.sbomAttached")
    assert by["push-protection-on"] == {**by["push-protection-on"], "status": "unreadable", "detail": "HTTP 403"}
    assert by["design-current"]["status"] == "attested" and by["design-current"]["detail"].endswith("docs/x.md")
    assert by["signed-with-provenance"]["status"] == "unattested" and by["signed-with-provenance"]["detail"].startswith("no entry")
    assert by["disclosure-followed"]["status"] == "unreadable"
    assert by["archived"]["status"] == "n/a"
    reg.deviations[("7", "release-integrity")] = {"reason": "source-only"}
    by = {c["check"]: c for c in check.run_all(reg, [e], verdicts, notes, decided)[0]["checks"]}
    assert by["sbom-attached"]["status"] == "exception"


def test_regressions_on_good_to_bad_or_unreadable():
    results = [{"name": "o/r", "checks": [
        {"policy": "p", "check": "a", "status": "fail", "detail": ""},
        {"policy": "p", "check": "b", "status": "unreadable", "detail": ""},
        {"policy": "p", "check": "c", "status": "fail", "detail": ""}]}]
    baseline = {"o/r": {"checks": [{"check": "a", "status": "pass"}, {"check": "b", "status": "pass"}, {"check": "c", "status": "fail"}]}}
    regs = check.regressions(results, baseline)
    assert [r.split(" (")[0] for r in regs] == ["o/r: p/a pass -> fail", "o/r: p/b pass -> unreadable"]


def test_a_kind_the_registry_does_not_define_is_a_construction_error():
    reg = registry()
    type_, stage = next((t, s) for t in reg.kinds for s in ("sandbox", "incubating", "graduated", "archived") if s not in reg.kinds[t])
    with pytest.raises(SystemExit, match="no kind"):
        model.repositories_sysml(reg, [{"name": "o/a", "type": type_, "stage": stage}])
