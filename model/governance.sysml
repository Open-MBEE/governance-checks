package Governance {
    doc /* The Open-MBEE governance policies as SysML v2, hand-written against Open-MBEE/repo-registry (the pin
           in repos.yaml): one requirement def per registry check, in a package per policy, named after their IDs in
           PascalCase. tests/test_check.py checks this model against the registry's data; OpenSysML decides which
           requirements are in effect for each repository (model/repositories.sysml, generated from repos.yaml:
           the `inEffect` assumption) and whether the repository satisfies them. Deadlines and windows are stated
           here, in the required constraints; the sensors report ages in days. An attested check holds when
           repos.yaml records evidence for it and that evidence resolves. */
    private import ScalarValues::*;

    enum def Type { tool; media; research; governance; }
    enum def Stage { sandbox; incubating; graduated; archived; }
    enum def Tier { low; medium; high; none; }

    calc def TierOf {
        doc /* The registry's kinds table (data/taxonomy/kinds.yaml): type and stage give the tier. */
        in type : Type;
        in stage : Stage;
        return : Tier =
            if stage == Stage::archived ? Tier::none
            else if stage == Stage::sandbox or type == Type::research ? Tier::low
            else if stage == Stage::graduated and (type == Type::tool or type == Type::governance) ? Tier::high
            else Tier::medium;
    }

    package Patterns {
        doc /* The patterns the sensors match names against. OpenSysML has no pattern matching, so the sensors read
               these from the model and apply them; they carry none of their own. */
        doc /* semantic-versioning: a release tag is vMAJOR.MINOR.PATCH (semver.org), as a regular expression */
        attribute semverTag : String = "^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$";
        doc /* release-integrity: a release asset is an SPDX or CycloneDX SBOM when its lower-cased name matches one of these globs */
        attribute sbomAsset : String[4] = ("*.spdx.json", "*.spdx", "*.cdx.json", "*bom*.json");
    }

    part def Repository {
        doc /* A repository measured at a type and stage (repos.yaml); the tier follows from the registry's kinds table. */
        attribute type : Type;
        attribute stage : Stage;
        attribute tier : Tier = TierOf(type, stage);

        doc /* GET /repos/{owner}/{repo} .archived */
        attribute archived : Boolean;
        doc /* default-branch pull_request rule: required_approving_review_count */
        attribute approvalsRequired : Integer;
        doc /* default-branch pull_request rule: require_code_owner_review */
        attribute codeOwnerReviewRequired : Boolean;
        doc /* default-branch required_status_checks rule: number of contexts */
        attribute requiredStatusChecks : Integer;
        doc /* CODEOWNERS at .github/, the root or docs/ */
        attribute codeownersPresent : Boolean;
        doc /* GET /repos/{owner}/{repo}/codeowners/errors: number of errors */
        attribute codeownersErrors : Integer;
        doc /* GET /repos/{owner}/{repo}/community/profile files.contributing */
        attribute contributingPresent : Boolean;
        doc /* GET /repos/{owner}/{repo}/community/profile files.readme */
        attribute readmePresent : Boolean;
        doc /* GraphQL repository.hasVulnerabilityAlertsEnabled */
        attribute dependabotAlertsOn : Boolean;
        doc /* default-branch non_fast_forward rule, or classic allow_force_pushes off */
        attribute forcePushBlocked : Boolean;
        doc /* default-branch deletion rule, or classic allow_deletions off */
        attribute deletionBlocked : Boolean;
        doc /* GET /repos/{owner}/{repo} .license.spdx_id */
        attribute license : String;
        doc /* GET /repos/{owner}/{repo}/releases/latest exists (a non-prerelease release) */
        attribute stableRelease : Boolean;
        doc /* latest release has an SPDX or CycloneDX asset */
        attribute sbomAttached : Boolean;
        doc /* latest release .immutable */
        attribute releaseImmutable : Boolean;
        doc /* GET /repos/{owner}/{repo} security_and_analysis.secret_scanning_push_protection */
        attribute pushProtectionOn : Boolean;
        doc /* GraphQL repository.isSecurityPolicyEnabled */
        attribute securityPolicyPresent : Boolean;
        doc /* GET /repos/{owner}/{repo}/private-vulnerability-reporting .enabled */
        attribute privateReportingOn : Boolean;
        doc /* published non-draft releases whose tag is not vMAJOR.MINOR.PATCH */
        attribute offPatternReleases : Integer;
        doc /* days since the newest of them was published (0 when there is none) */
        attribute newestOffPatternReleaseDays : Real;
        doc /* code-scanning default setup configured, or analyses exist */
        attribute codeScanningConfigured : Boolean;
        doc /* GET /repos/{owner}/{repo}/code-scanning/alerts answers (404 when code scanning is not enabled) */
        attribute codeScanningEnabled : Boolean;
        doc /* age in days of the oldest open critical code-scanning alert (0 when there is none) */
        attribute oldestCriticalScanningAlertDays : Real;
        doc /* age in days of the oldest open medium-or-higher code-scanning alert (0 when there is none) */
        attribute oldestMediumPlusScanningAlertDays : Real;
        doc /* age in days of the oldest open critical Dependabot alert (0 when there is none) */
        attribute oldestCriticalDependabotAlertDays : Real;
        doc /* age in days of the oldest open high or medium Dependabot alert (0 when there is none) */
        attribute oldestHighOrMediumDependabotAlertDays : Real;
        doc /* distinct users CODEOWNERS names, teams expanded */
        attribute codeOwners : Integer;
        doc /* code owners not in maintainers.yaml */
        attribute codeOwnersNotMaintainers : Integer;
        doc /* code owners in maintainers.yaml with no verification date */
        attribute codeOwnersNeverVerified : Integer;
        doc /* days since the oldest verification date among the code owners (0 when none has one) */
        attribute oldestCodeOwnerVerificationDays : Real;
        doc /* GET /repos/{owner}/{repo}/actions/permissions/workflow .default_workflow_permissions == read */
        attribute defaultTokenRead : Boolean;

        doc /* Attested in repos.yaml: The README says that support has ended, and names any known active forks. (Repositories archived before this policy existed are exempt.) */
        attribute attestedEndOfSupportNote : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceEndOfSupportNoteResolves : Boolean;
        doc /* Attested in repos.yaml: The contribution guide keeps requirements on contributors minimal, says which kinds of contribution are accepted, says how contributions are reviewed and tested before they are merged, and (for code) asks for tests with each change. */
        attribute attestedContributingContent : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceContributingContentResolves : Boolean;
        doc /* Attested in repos.yaml: A dependency policy is published (in CONTRIBUTING or its own file) and followed. */
        attribute attestedDependencyPolicy : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceDependencyPolicyResolves : Boolean;
        doc /* Attested in repos.yaml: If the project provides an internet or infrastructure service, its direct dependencies are pinned: each one names an exact version (for example 2.4.1, not 2.x). */
        attribute attestedServicePins : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceServicePinsResolves : Boolean;
        doc /* Attested in repos.yaml: Release artifacts are signed, and a build record (provenance) is published with them that meets SLSA Build Level 3: built by GitHub Actions on GitHub-hosted runners through a reusable workflow, with GitHub artifact attestations. */
        attribute attestedSignedWithProvenance : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceSignedWithProvenanceResolves : Boolean;
        doc /* Attested in repos.yaml: The source repository holds no built executables, except test fixtures that are documented as such. */
        attribute attestedNoBuiltExecutables : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceNoBuiltExecutablesResolves : Boolean;
        doc /* Attested in repos.yaml: A design document describes the security controls (the measures that protect the software and its users, such as who can sign in, how data is protected, and how input is checked) and is updated when they change. */
        attribute attestedDesignCurrent : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceDesignCurrentResolves : Boolean;
        doc /* Attested in repos.yaml: Reports are answered following the published process, which also says what to expect for automated or AI-assisted reports. */
        attribute attestedDisclosureFollowed : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceDisclosureFollowedResolves : Boolean;
        doc /* Attested in repos.yaml: For graduated tools: a published policy says which releases are supported, and how fixes are backported (copied into those older supported releases). */
        attribute attestedStableReleasePolicy : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceStableReleasePolicyResolves : Boolean;
        doc /* Attested in repos.yaml: Fixes for known vulnerabilities are released in coordination with the project's users, following the security policy. */
        attribute attestedCoordinatedReleases : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceCoordinatedReleasesResolves : Boolean;
        doc /* Attested in repos.yaml: Workflows follow GitHub's security hardening guide for Actions: text that outside contributors control (such as pull request titles) is never run as a command, code from outside contributors' pull requests is never run with write access or secrets, and each job asks only for the permissions it needs. */
        attribute attestedWorkflowsHardened : Boolean;
        doc /* the evidence repos.yaml gives for it is a file or directory on github.com that exists */
        attribute evidenceWorkflowsHardenedResolves : Boolean;
    }

    package Policies {
        package ArchiveNotice {
            doc /* archive-notice: Before a repository is archived, its README says that support has ended and points to any known active forks. Repositories archived before this policy existed count as compliant as they are. */
            requirement def Archived {
                doc /* archived reads: GET /repos/{owner}/{repo} -> archived == true */
                subject repo : Repository;
                assume constraint inEffect { repo.stage == Stage::archived }
                require constraint archived { repo.archived }
            }
            requirement def EndOfSupportNote {
                doc /* end-of-support-note (attested): The README says that support has ended, and names any known active forks. (Repositories archived before this policy existed are exempt.) */
                subject repo : Repository;
                assume constraint inEffect { repo.stage == Stage::archived }
                require constraint endOfSupportNote { repo.attestedEndOfSupportNote and repo.evidenceEndOfSupportNoteResolves }
            }
        }
        package ChangeReview {
            doc /* change-review: High-tier repositories (graduated tools, and the registry) need at least one approving review from a code owner, and passing checks, before a change is merged to the default branch. */
            requirement def ReviewRequired {
                doc /* review-required reads: GET /repos/{owner}/{repo}/branches/{default_branch}/protection -> required_pull_request_reviews.required_approving_review_count >= 1 and .require_code_owner_reviews, or the same in a pull_request rule of GET .../rules/branches/{default_branch} */
                subject repo : Repository;
                assume constraint inEffect { repo.tier == Tier::high }
                require constraint reviewRequired { repo.approvalsRequired >= 1 and repo.codeOwnerReviewRequired }
            }
            requirement def ChecksRequired {
                doc /* checks-required reads: GET /repos/{owner}/{repo}/branches/{default_branch}/protection -> required_status_checks is set, or GET .../rules/branches/{default_branch} has a required_status_checks rule */
                subject repo : Repository;
                assume constraint inEffect { repo.tier == Tier::high }
                require constraint checksRequired { repo.requiredStatusChecks >= 1 }
            }
        }
        package Codeowners {
            doc /* codeowners: Every live repository names the people who look after it, in a CODEOWNERS file. That file is the authoritative list of the repository's operators. */
            requirement def CodeownersPresent {
                doc /* codeowners-present reads: GET /repos/{owner}/{repo}/contents/{.github/CODEOWNERS|CODEOWNERS|docs/CODEOWNERS} -> first of these returns 200 */
                subject repo : Repository;
                assume constraint inEffect { not (repo.stage == Stage::archived) }
                require constraint codeownersPresent { repo.codeownersPresent }
            }
            requirement def CodeownersValid {
                doc /* codeowners-valid reads: GET /repos/{owner}/{repo}/codeowners/errors -> errors is empty */
                subject repo : Repository;
                assume constraint inEffect { not (repo.stage == Stage::archived) }
                require constraint codeownersValid { repo.codeownersErrors == 0 }
            }
        }
        package Contributing {
            doc /* contributing: Tools from version 1.0, media in use, and the registry itself publish a contribution guide that keeps demands on contributors small, says what kinds of contribution are welcome, says how contributions are reviewed and tested before they are merged, and asks for tests with code. */
            requirement def ContributingPresent {
                doc /* contributing-present reads: GET /repos/{owner}/{repo}/community/profile -> files.contributing is not null */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::media or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint contributingPresent { repo.contributingPresent }
            }
            requirement def ContributingContent {
                doc /* contributing-content (attested): The contribution guide keeps requirements on contributors minimal, says which kinds of contribution are accepted, says how contributions are reviewed and tested before they are merged, and (for code) asks for tests with each change. */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::media or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint contributingContent { repo.attestedContributingContent and repo.evidenceContributingContentResolves }
            }
        }
        package DependencyManagement {
            doc /* dependency-management: Tools from version 1.0, and the registry, turn on Dependabot alerts and publish a short dependency policy: how new dependencies are chosen and how they are kept up to date. Services the project provides pin their direct dependencies. */
            requirement def DependabotAlertsOn {
                doc /* dependabot-alerts-on reads: GET /repos/{owner}/{repo}/vulnerability-alerts -> 204 (404 means off only when the caller has admin read; otherwise yellow) */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint dependabotAlertsOn { repo.dependabotAlertsOn }
            }
            requirement def DependencyPolicy {
                doc /* dependency-policy (attested): A dependency policy is published (in CONTRIBUTING or its own file) and followed. */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint dependencyPolicy { repo.attestedDependencyPolicy and repo.evidenceDependencyPolicyResolves }
            }
            requirement def ServicePins {
                doc /* service-pins (attested): If the project provides an internet or infrastructure service, its direct dependencies are pinned: each one names an exact version (for example 2.4.1, not 2.x). */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint servicePins { repo.attestedServicePins and repo.evidenceServicePinsResolves }
            }
        }
        package HistoryProtection {
            doc /* history-protection: Tools from version 1.0, and the registry, protect the default branch from force pushes and deletion, so that its history stays complete for review and audit. */
            requirement def NoForcePush {
                doc /* no-force-push reads: GET /repos/{owner}/{repo}/branches/{default_branch}/protection -> allow_force_pushes.enabled == false, or GET .../rules/branches/{default_branch} includes non_fast_forward */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint noForcePush { repo.forcePushBlocked }
            }
            requirement def NoDeletion {
                doc /* no-deletion reads: GET /repos/{owner}/{repo}/branches/{default_branch}/protection -> allow_deletions.enabled == false, or GET .../rules/branches/{default_branch} includes deletion */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint noDeletion { repo.deletionBlocked }
            }
        }
        package LicenseByType {
            doc /* license-by-type: Every live repository has a license that OpenMBEE accepts for its type of content: Apache-2.0 or MIT for tools; CC-BY-4.0, Apache-2.0 or MIT for media; Apache-2.0, MIT, CC-BY-4.0 or a CDLA license for research; Apache-2.0 for governance. Any other license needs a recorded exception. */
            requirement def LicenseAllowed {
                doc /* license-allowed reads: GET /repos/{owner}/{repo} -> license.spdx_id is in allowed_licenses for the repository's type (missing or NOASSERTION is red; an accepted exception in data/deviations.yaml is green, marked as an exception) */
                subject repo : Repository;
                assume constraint inEffect { not (repo.stage == Stage::archived) }
                require constraint licenseAllowed { (repo.type == Type::tool and (repo.license == "Apache-2.0" or repo.license == "MIT")) or (repo.type == Type::media and (repo.license == "CC-BY-4.0" or repo.license == "Apache-2.0" or repo.license == "MIT")) or (repo.type == Type::research and (repo.license == "Apache-2.0" or repo.license == "MIT" or repo.license == "CC-BY-4.0" or repo.license == "CDLA-Permissive-2.0" or repo.license == "CDLA-Sharing-1.0")) or (repo.type == Type::governance and (repo.license == "Apache-2.0")) }
            }
        }
        package ProjectFiles {
            doc /* project-files: Every live repository has a README that says what it is and how to use it. (Its license is covered by license-by-type.) */
            requirement def ReadmePresent {
                doc /* readme-present reads: GET /repos/{owner}/{repo}/community/profile -> files.readme is not null */
                subject repo : Repository;
                assume constraint inEffect { not (repo.stage == Stage::archived) }
                require constraint readmePresent { repo.readmePresent }
            }
        }
        package ReleaseIntegrity {
            doc /* release-integrity: Graduated tools publish each release with a software bill of materials (SBOM), sign it, publish build provenance, and keep built executables out of the source repository. */
            requirement def SbomAttached {
                doc /* sbom-attached reads: GET /repos/{owner}/{repo}/releases/latest -> assets include a file named like *.spdx.json, *.spdx, *.cdx.json or *bom*.json */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool) and (repo.stage == Stage::graduated) }
                require constraint sbomAttached { repo.stableRelease and repo.sbomAttached }
            }
            requirement def ReleaseImmutable {
                doc /* release-immutable reads: GET /repos/{owner}/{repo}/releases/latest -> immutable == true */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool) and (repo.stage == Stage::graduated) }
                require constraint releaseImmutable { repo.stableRelease and repo.releaseImmutable }
            }
            requirement def SignedWithProvenance {
                doc /* signed-with-provenance (attested): Release artifacts are signed, and a build record (provenance) is published with them that meets SLSA Build Level 3: built by GitHub Actions on GitHub-hosted runners through a reusable workflow, with GitHub artifact attestations. */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool) and (repo.stage == Stage::graduated) }
                require constraint signedWithProvenance { repo.attestedSignedWithProvenance and repo.evidenceSignedWithProvenanceResolves }
            }
            requirement def NoBuiltExecutables {
                doc /* no-built-executables (attested): The source repository holds no built executables, except test fixtures that are documented as such. */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool) and (repo.stage == Stage::graduated) }
                require constraint noBuiltExecutables { repo.attestedNoBuiltExecutables and repo.evidenceNoBuiltExecutablesResolves }
            }
        }
        package SecretProtection {
            doc /* secret-protection: Tools from version 1.0, and the registry, turn on push protection, so that GitHub blocks a push that contains a password, key or token. */
            requirement def PushProtectionOn {
                doc /* push-protection-on reads: GET /repos/{owner}/{repo} -> security_and_analysis.secret_scanning_push_protection.status == enabled (the block is absent without admin read: yellow, not off) */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint pushProtectionOn { repo.pushProtectionOn }
            }
        }
        package SecurityDesign {
            doc /* security-design: High-tier repositories keep a short design document that describes the security controls of what they build, and keep it current. */
            requirement def DesignCurrent {
                doc /* design-current (attested): A design document describes the security controls (the measures that protect the software and its users, such as who can sign in, how data is protected, and how input is checked) and is updated when they change. */
                subject repo : Repository;
                assume constraint inEffect { repo.tier == Tier::high }
                require constraint designCurrent { repo.attestedDesignCurrent and repo.evidenceDesignCurrentResolves }
            }
        }
        package SecurityPolicy {
            doc /* security-policy: Tools from version 1.0, and the registry, publish a security policy that says how to report a vulnerability and who responds, and turn on GitHub's private vulnerability reporting. */
            requirement def SecurityPolicyPresent {
                doc /* security-policy-present reads: GraphQL repository { isSecurityPolicyEnabled } == true */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint securityPolicyPresent { repo.securityPolicyPresent }
            }
            requirement def PrivateReportingOn {
                doc /* private-reporting-on reads: GET /repos/{owner}/{repo}/private-vulnerability-reporting -> enabled == true */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint privateReportingOn { repo.privateReportingOn }
            }
            requirement def DisclosureFollowed {
                doc /* disclosure-followed (attested): Reports are answered following the published process, which also says what to expect for automated or AI-assisted reports. */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint disclosureFollowed { repo.attestedDisclosureFollowed and repo.evidenceDisclosureFollowedResolves }
            }
        }
        package SemanticVersioning {
            doc /* semantic-versioning: Tools from version 1.0 number their releases with semantic versioning, so that the version says whether an update is a fix, a feature or a breaking change. Graduated tools also say which releases get fixes, and for how long. */
            requirement def SemverTags {
                doc /* semver-tags reads: GET /repos/{owner}/{repo}/releases -> every non-draft release tag in the last 12 months matches vMAJOR.MINOR.PATCH (semver.org) */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint semverTags { repo.offPatternReleases == 0 or repo.newestOffPatternReleaseDays > 365 }
            }
            requirement def StableReleasePolicy {
                doc /* stable-release-policy (attested): For graduated tools: a published policy says which releases are supported, and how fixes are backported (copied into those older supported releases). */
                subject repo : Repository;
                assume constraint inEffect { ((repo.type == Type::tool) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated)) and (repo.stage == Stage::graduated) }
                require constraint stableReleasePolicy { repo.attestedStableReleasePolicy and repo.evidenceStableReleasePolicyResolves }
            }
        }
        package StaticAnalysis {
            doc /* static-analysis: Tools from version 1.0, and the registry, run code scanning on every change and fix critical findings promptly. */
            requirement def CodeScanningConfigured {
                doc /* code-scanning-configured reads: GET /repos/{owner}/{repo}/code-scanning/default-setup -> state == configured, or GET .../code-scanning/analyses is not empty */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint codeScanningConfigured { repo.codeScanningConfigured }
            }
            requirement def NoOpenCritical {
                doc /* no-open-critical reads: GET /repos/{owner}/{repo}/code-scanning/alerts?state=open -> none with security_severity_level == critical older than 14 days */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint noOpenCritical { repo.codeScanningEnabled and repo.oldestCriticalScanningAlertDays <= 14 }
            }
        }
        package VerifiedCodeOwners {
            doc /* verified-code-owners: The code owners of a high-tier repository (graduated tools, and the organization's governance) are named maintainers whom an organization owner has verified, out of band, in the last 12 months. The owner verifies their identity; that they are not a sanctioned party, nor located or ordinarily resident in a comprehensively sanctioned jurisdiction; and that they have no affiliation with an organization of concern. Each verification is recorded in data/maintainers.yaml, with the facts the maintainer consents to publish (legal name, country of residence, affiliation). No verification, or one more than 12 months old, means the person may not be a code owner here. The policy is for code owners, not contributors. It restricts who may approve and merge changes, not who may contribute them, and every contribution passes through a verified code owner's review. */
            requirement def VerifiedOwners {
                doc /* verified-owners reads: GET /repos/{owner}/{repo}/contents/{.github/CODEOWNERS|CODEOWNERS|docs/CODEOWNERS} -> every person named is a maintainer in data/maintainers.yaml whose verification is dated within the last 12 months */
                subject repo : Repository;
                assume constraint inEffect { repo.tier == Tier::high }
                require constraint verifiedOwners { repo.codeownersPresent and repo.codeOwners >= 1 and repo.codeOwnersNotMaintainers == 0 and repo.codeOwnersNeverVerified == 0 and repo.oldestCodeOwnerVerificationDays <= 365 }
            }
        }
        package VulnerabilityRemediation {
            doc /* vulnerability-remediation: High-tier repositories fix known vulnerabilities on a deadline: critical ones within 14 days, medium and high ones within 60 days, and release the fixes in step with the people who use them. */
            requirement def DependencyAlertsOnTime {
                doc /* dependency-alerts-on-time reads: GET /repos/{owner}/{repo}/dependabot/alerts?state=open -> no critical alert older than 14 days, and no high or medium alert older than 60 days */
                subject repo : Repository;
                assume constraint inEffect { repo.tier == Tier::high }
                require constraint dependencyAlertsOnTime { repo.oldestCriticalDependabotAlertDays <= 14 and repo.oldestHighOrMediumDependabotAlertDays <= 60 }
            }
            requirement def ScanningClean {
                doc /* scanning-clean reads: GET /repos/{owner}/{repo}/code-scanning/alerts?state=open -> no alert of medium or higher security severity older than 60 days */
                subject repo : Repository;
                assume constraint inEffect { repo.tier == Tier::high }
                require constraint scanningClean { repo.codeScanningEnabled and repo.oldestMediumPlusScanningAlertDays <= 60 }
            }
            requirement def CoordinatedReleases {
                doc /* coordinated-releases (attested): Fixes for known vulnerabilities are released in coordination with the project's users, following the security policy. */
                subject repo : Repository;
                assume constraint inEffect { repo.tier == Tier::high }
                require constraint coordinatedReleases { repo.attestedCoordinatedReleases and repo.evidenceCoordinatedReleasesResolves }
            }
        }
        package WorkflowLeastPrivilege {
            doc /* workflow-least-privilege: Tools from version 1.0, and the registry, give their GitHub Actions workflows read-only access by default, and set up workflows following GitHub's hardening guidance. */
            requirement def DefaultTokenRead {
                doc /* default-token-read reads: GET /repos/{owner}/{repo}/actions/permissions/workflow -> default_workflow_permissions == read */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint defaultTokenRead { repo.defaultTokenRead }
            }
            requirement def WorkflowsHardened {
                doc /* workflows-hardened (attested): Workflows follow GitHub's security hardening guide for Actions: text that outside contributors control (such as pull request titles) is never run as a command, code from outside contributors' pull requests is never run with write access or secrets, and each job asks only for the permissions it needs. */
                subject repo : Repository;
                assume constraint inEffect { (repo.type == Type::tool or repo.type == Type::governance) and (repo.stage == Stage::incubating or repo.stage == Stage::graduated) }
                require constraint workflowsHardened { repo.attestedWorkflowsHardened and repo.evidenceWorkflowsHardenedResolves }
            }
        }
    }
}
