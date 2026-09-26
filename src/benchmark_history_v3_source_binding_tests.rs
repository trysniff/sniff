use super::*;
use crate::benchmark::{
    HISTORICAL_V3_PROTOCOL_SCHEMA_VERSION, HistoricalV3AllowedMetadataField,
    HistoricalV3CandidateWindow, HistoricalV3ForbiddenMetadataField, HistoricalV3HumanReviewPolicy,
    HistoricalV3IdenticalTestPolicy, HistoricalV3MechanicalRequirement,
    HistoricalV3SourceFrameBinding, HistoricalV3StopRule, HistoricalV3TestEnvironmentBinding,
    HistoricalV3TestRecipePolicy, HistoricalV3TestRecipeSelector,
    SOURCE_FRAME_COLLECTION_MANIFEST_SCHEMA_VERSION, SOURCE_FRAME_COLLECTION_POLICY_SCHEMA_VERSION,
    SourceFramePageCommitment, SourceFrameRawPage, seal_historical_v3_protocol,
};
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::TempDir;

pub(crate) struct FrameFixture {
    pub(crate) root: TempDir,
    pub(crate) manifest: SourceFrameCollectionManifest,
    pub(crate) frame: Vec<u8>,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn json_sha256(value: &impl Serialize) -> String {
    sha256(&serde_json::to_vec(value).unwrap())
}

fn hourly_query(policy: &super::super::SourceFrameCollectionPolicy, hour: usize) -> String {
    let start = format!("{}T{hour:02}:00:00Z", policy.created_day_utc);
    let end = format!("{}T{hour:02}:59:59Z", policy.created_day_utc);
    format!(
        "language:{} created:{start}..{end} fork:false archived:false mirror:false template:false",
        policy.language
    )
}

fn frame_fixture(
    language: HistoricalV3Language,
    github_language: &str,
    index: usize,
    repositories: &[(u64, &str)],
) -> FrameFixture {
    frame_fixture_at(language, github_language, index, repositories, "2026-08-08")
}

fn frame_fixture_at(
    language: HistoricalV3Language,
    github_language: &str,
    index: usize,
    repositories: &[(u64, &str)],
    created_day: &str,
) -> FrameFixture {
    let root = tempfile::tempdir().unwrap();
    let raw_root = root.path().join("raw");
    fs::create_dir(&raw_root).unwrap();
    let policy = super::super::SourceFrameCollectionPolicy {
        schema_version: SOURCE_FRAME_COLLECTION_POLICY_SCHEMA_VERSION,
        frame_id: format!("synthetic-{github_language}-frame"),
        source: "https://api.github.com/search/repositories".to_string(),
        api_version: "2022-11-28".to_string(),
        language: github_language.to_string(),
        created_day_utc: created_day.to_string(),
        derivation_seed: format!("{index:08x}{}", "0".repeat(32)),
        derivation_period_start_utc: created_day.to_string(),
        derivation_period_days: 1,
        derivation_rule: "first_8_hex_u32_mod_period_days".to_string(),
        partition: "utc_hour".to_string(),
        include_forks: false,
        include_archived: false,
        include_mirrors: false,
        include_templates: false,
        ordering: "github_repository_id_ascending".to_string(),
        attestation: format!("Synthetic {language:?} source frame."),
    };
    let mut commitments = Vec::new();
    for hour in 0..24 {
        let query = hourly_query(&policy, hour);
        let items = if hour == 0 {
            repositories
                .iter()
                .map(|(id, repository)| {
                    serde_json::json!({
                        "id": id,
                        "full_name": repository,
                        "created_at": format!("{created_day}T00:01:00Z"),
                        "fork": false,
                        "archived": false,
                        "mirror_url": null,
                        "is_template": false
                    })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let response = serde_json::json!({
            "total_count": items.len(),
            "incomplete_results": false,
            "items": items
        })
        .to_string();
        let raw = SourceFrameRawPage {
            query: query.clone(),
            page: 1,
            per_page: 100,
            response_sha256: sha256(response.as_bytes()),
            response,
        };
        let relative = format!("raw/hour-{hour:02}-page-001.json");
        let bytes = serde_json::to_vec_pretty(&raw).unwrap();
        fs::write(root.path().join(&relative), &bytes).unwrap();
        commitments.push(SourceFramePageCommitment {
            query,
            page: 1,
            artifact_path: relative,
            artifact_sha256: sha256(&bytes),
            response_sha256: raw.response_sha256,
        });
    }
    commitments.sort_by(|left, right| {
        (&left.query, left.page, &left.artifact_path).cmp(&(
            &right.query,
            right.page,
            &right.artifact_path,
        ))
    });
    let mut ordered = repositories.to_vec();
    ordered.sort_by_key(|(id, _)| *id);
    let mut frame = String::from("repo,metadata\n");
    for (id, repository) in ordered {
        frame.push_str(&format!(
            "github.com/{},github_repository_id={id};created_at={created_day}T00:01:00Z\n",
            repository.to_ascii_lowercase(),
        ));
    }
    let frame = frame.into_bytes();
    let mut manifest = SourceFrameCollectionManifest {
        schema_version: SOURCE_FRAME_COLLECTION_MANIFEST_SCHEMA_VERSION,
        policy_sha256: json_sha256(&policy),
        frame_sha256: sha256(&frame),
        repository_count: repositories.len(),
        pages: commitments,
        manifest_sha256: String::new(),
        policy,
    };
    manifest.manifest_sha256 = manifest.computed_manifest_sha256().unwrap();
    validate_source_frame_manifest(&manifest, root.path(), &frame).unwrap();
    FrameFixture {
        root,
        manifest,
        frame,
    }
}

pub(crate) fn prior_identity_seal() -> HistoricalV3PriorBenchmarkIdentitySeal {
    prepare_historical_v3_prior_identity_seal(vec![
        HistoricalV3PriorArtifactBinding {
            artifact_id: "blind-oss-v1".to_string(),
            artifact_sha256: "1".repeat(64),
            repositories: vec!["https://github.com/Zed/Used.git".to_string()],
        },
        HistoricalV3PriorArtifactBinding {
            artifact_id: "historical-v2".to_string(),
            artifact_sha256: "2".repeat(64),
            repositories: vec!["github.com/Other/Prior".to_string()],
        },
    ])
    .unwrap()
}

pub(crate) fn protocol(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
    fixtures: &[FrameFixture],
) -> HistoricalV3Protocol {
    let languages = [
        HistoricalV3Language::Go,
        HistoricalV3Language::JavaScript,
        HistoricalV3Language::Kotlin,
        HistoricalV3Language::Python,
        HistoricalV3Language::Rust,
        HistoricalV3Language::TypeScript,
    ];
    seal_historical_v3_protocol(HistoricalV3Protocol {
        schema_version: HISTORICAL_V3_PROTOCOL_SCHEMA_VERSION,
        protocol_id: "synthetic-historical-v3-source-binding".to_string(),
        protocol_contract: "sniffbench-historical-v3-protocol-v6".to_string(),
        ranking_domain: "sniffbench-historical-v3-candidate-rank-v1".to_string(),
        ranking_seed: "3".repeat(64),
        prior_benchmark_identity_seal_sha256: seal.seal_sha256.clone(),
        repository_created_after_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        languages: languages.to_vec(),
        source_frames: fixtures
            .iter()
            .zip(languages)
            .map(|(fixture, language)| HistoricalV3SourceFrameBinding {
                language,
                frame_id: fixture.manifest.policy.frame_id.clone(),
                policy_sha256: fixture.manifest.policy_sha256.clone(),
                manifest_sha256: fixture.manifest.manifest_sha256.clone(),
                frame_sha256: fixture.manifest.frame_sha256.clone(),
                repository_count: fixture.manifest.repository_count,
            })
            .collect(),
        candidate_window: HistoricalV3CandidateWindow {
            merged_at_or_after_utc: "2025-01-01T00:00:00Z".to_string(),
            merged_before_utc: "2026-01-01T00:00:00Z".to_string(),
            github_api_version: "2022-11-28".to_string(),
            partition: "repository_then_merged_at_utc".to_string(),
            pagination: "github_graphql_cursor_until_exhausted".to_string(),
        },
        allowed_metadata_fields: vec![
            HistoricalV3AllowedMetadataField::RepositoryId,
            HistoricalV3AllowedMetadataField::PullRequestNumber,
            HistoricalV3AllowedMetadataField::CreatedAt,
            HistoricalV3AllowedMetadataField::UpdatedAt,
            HistoricalV3AllowedMetadataField::ClosedAt,
            HistoricalV3AllowedMetadataField::MergedAt,
            HistoricalV3AllowedMetadataField::BaseCommit,
            HistoricalV3AllowedMetadataField::HeadCommit,
            HistoricalV3AllowedMetadataField::MergeCommit,
            HistoricalV3AllowedMetadataField::ParentCommits,
            HistoricalV3AllowedMetadataField::ArtifactIdentity,
        ],
        forbidden_metadata_fields: vec![
            HistoricalV3ForbiddenMetadataField::Title,
            HistoricalV3ForbiddenMetadataField::Body,
            HistoricalV3ForbiddenMetadataField::IssueText,
            HistoricalV3ForbiddenMetadataField::Comments,
            HistoricalV3ForbiddenMetadataField::Reviews,
            HistoricalV3ForbiddenMetadataField::Reactions,
            HistoricalV3ForbiddenMetadataField::Labels,
            HistoricalV3ForbiddenMetadataField::Assignees,
            HistoricalV3ForbiddenMetadataField::Popularity,
            HistoricalV3ForbiddenMetadataField::AuthorIdentity,
            HistoricalV3ForbiddenMetadataField::GeneratedSummary,
        ],
        mechanical_requirements: vec![
            HistoricalV3MechanicalRequirement::ImmutableRevisionsMaterialize,
            HistoricalV3MechanicalRequirement::PatchReproducesMerge,
            HistoricalV3MechanicalRequirement::ChangedProductionMethodResolves,
            HistoricalV3MechanicalRequirement::CompilerSourceAndSemanticCensus,
            HistoricalV3MechanicalRequirement::RepositoryMethodBounds,
            HistoricalV3MechanicalRequirement::NetProductionReductionOrConsolidation,
            HistoricalV3MechanicalRequirement::PublicSurfacePreserved,
            HistoricalV3MechanicalRequirement::IdenticalTestsPass,
            HistoricalV3MechanicalRequirement::NonProductionOnlyChangesExcluded,
        ],
        mechanical_policy: crate::benchmark::HistoricalV3MechanicalPolicy {
            production_method_minimum: 1,
            production_method_maximum: 500,
            generated_path_segments: vec!["generated".to_string()],
            vendored_path_segments: vec!["vendor".to_string()],
            documentation_path_segments: vec!["docs".to_string()],
            fixture_path_segments: vec!["fixtures".to_string()],
            test_path_segments: vec!["tests".to_string()],
            test_file_suffixes: vec![".test.ts".to_string(), "_test.go".to_string()],
        },
        test_recipe_policy: test_recipe_policy(),
        identical_test_policy: identical_test_policy(),
        human_review_policy: human_review_policy(),
        stop_rule: HistoricalV3StopRule {
            accepted_target_per_language: 40,
            distinct_repository_floor_per_language: 20,
            accepted_case_cap_per_repository: 4,
            reviewable_candidate_cap_per_repository: 8,
            adjudication_cap_per_language: 400,
        },
        no_fallbacks: true,
        model_access_forbidden: true,
        sniff_output_access_forbidden: true,
        protocol_sha256: String::new(),
    })
    .unwrap()
}

pub(crate) fn human_review_policy() -> HistoricalV3HumanReviewPolicy {
    HistoricalV3HumanReviewPolicy {
        source_only_review: true,
        independent_reviewers: 2,
        distinct_dispute_resolver: true,
        reviewers_must_not_see_sniff_output: true,
        reviewers_must_not_see_repository_identity: true,
        reviewers_must_not_see_change_metadata: true,
        reviewers_must_not_see_each_other_labels: true,
        human_only_review: true,
        complete_source_context_required: true,
        behavior_evidence_required: true,
        exact_before_mechanism_required: true,
        exact_after_removal_required: true,
        relocation_check_required: true,
        simpler_counterfactual_required: true,
    }
}

pub(crate) fn identical_test_policy() -> HistoricalV3IdenticalTestPolicy {
    HistoricalV3IdenticalTestPolicy {
        execution_contract: "sniffbench-historical-v3-identical-test-policy-v1".to_string(),
        cpu_limit_millis: 4_000,
        memory_limit_bytes: 8 * 1024 * 1024 * 1024,
        process_limit: 1_024,
        temporary_filesystem_bytes: 2 * 1024 * 1024 * 1024,
        preparation_command_timeout_seconds: 30 * 60,
        test_command_timeout_seconds: 60 * 60,
        retained_output_bytes: 64 * 1024,
        network_disabled_during_all_commands: true,
        ephemeral_container_filesystem: true,
        host_source_mounts_forbidden: true,
        all_capabilities_dropped: true,
        no_new_privileges: true,
    }
}

pub(crate) fn test_recipe_policy() -> HistoricalV3TestRecipePolicy {
    HistoricalV3TestRecipePolicy {
        selector_contract: "sniffbench-historical-v3-test-recipe-selectors-v1".to_string(),
        selectors: vec![
            HistoricalV3TestRecipeSelector::NodePackage,
            HistoricalV3TestRecipeSelector::Cargo,
            HistoricalV3TestRecipeSelector::GoModule,
            HistoricalV3TestRecipeSelector::PythonUv,
            HistoricalV3TestRecipeSelector::PythonPoetry,
            HistoricalV3TestRecipeSelector::PythonPdm,
            HistoricalV3TestRecipeSelector::PythonHashedRequirements,
            HistoricalV3TestRecipeSelector::GradleWrapper,
        ],
        maximum_input_file_bytes: 4 * 1024 * 1024,
        maximum_total_input_bytes: 16 * 1024 * 1024,
        execution_platform: "linux/amd64".to_string(),
        network_disabled_during_tests: true,
        environments: [
            HistoricalV3Language::Go,
            HistoricalV3Language::JavaScript,
            HistoricalV3Language::Kotlin,
            HistoricalV3Language::Python,
            HistoricalV3Language::Rust,
            HistoricalV3Language::TypeScript,
        ]
        .into_iter()
        .map(|language| HistoricalV3TestEnvironmentBinding {
            language,
            image_digest: format!("sha256:{}", "a".repeat(64)),
            toolchain_manifest_sha256: "b".repeat(64),
            dependency_store_sha256: "c".repeat(64),
        })
        .collect(),
    }
}

pub(crate) fn fixtures() -> Vec<FrameFixture> {
    [
        (HistoricalV3Language::Go, "Go"),
        (HistoricalV3Language::JavaScript, "JavaScript"),
        (HistoricalV3Language::Kotlin, "Kotlin"),
        (HistoricalV3Language::Python, "Python"),
        (HistoricalV3Language::Rust, "Rust"),
        (HistoricalV3Language::TypeScript, "TypeScript"),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (language, name))| {
        if index == 0 {
            frame_fixture(language, name, index, &[(1, "Zed/Used"), (2, "Alpha/Go")])
        } else {
            frame_fixture(
                language,
                name,
                index,
                &[(index as u64 + 10, &format!("Fresh/{name}"))],
            )
        }
    })
    .collect()
}

pub(crate) fn operator_fixtures(fresh_repositories_per_language: usize) -> Vec<FrameFixture> {
    [
        (HistoricalV3Language::Go, "Go"),
        (HistoricalV3Language::JavaScript, "JavaScript"),
        (HistoricalV3Language::Kotlin, "Kotlin"),
        (HistoricalV3Language::Python, "Python"),
        (HistoricalV3Language::Rust, "Rust"),
        (HistoricalV3Language::TypeScript, "TypeScript"),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (language, name))| {
        let names = (0..fresh_repositories_per_language)
            .map(|slot| format!("Fresh/{name}{slot:02}"))
            .collect::<Vec<_>>();
        let mut repositories = names
            .iter()
            .enumerate()
            .map(|(slot, repository)| (index as u64 * 100 + slot as u64 + 10, repository.as_str()))
            .collect::<Vec<_>>();
        if index == 0 {
            repositories.push((1, "Zed/Used"));
        }
        frame_fixture(language, name, index, &repositories)
    })
    .collect()
}

pub(crate) fn artifacts(fixtures: &[FrameFixture]) -> Vec<HistoricalV3SourceFrameArtifact<'_>> {
    fixtures
        .iter()
        .map(|fixture| HistoricalV3SourceFrameArtifact {
            manifest: &fixture.manifest,
            artifact_root: fixture.root.path(),
            frame: &fixture.frame,
        })
        .collect()
}

#[test]
fn prior_identity_seal_canonicalizes_and_rejects_tampering() {
    let seal = prior_identity_seal();
    assert_eq!(
        seal.repositories,
        vec!["other/prior".to_string(), "zed/used".to_string()]
    );
    validate_historical_v3_prior_identity_seal(&seal).unwrap();

    let mut changed = seal;
    changed.repositories[0] = "different/repository".to_string();
    assert!(
        validate_historical_v3_prior_identity_seal(&changed)
            .unwrap_err()
            .contains("commitment changed")
    );
}

#[test]
fn replay_binds_every_frame_and_excludes_prior_repositories() {
    let fixtures = fixtures();
    let seal = prior_identity_seal();
    let protocol = protocol(&seal, &fixtures);
    let audit = bind_historical_v3_source_frames(&protocol, &seal, &artifacts(&fixtures)).unwrap();

    assert_eq!(audit.frames.len(), 6);
    assert_eq!(audit.frames[0].repository_count, 2);
    assert_eq!(audit.frames[0].eligible_repository_count, 1);
    assert_eq!(audit.frames[0].excluded_prior_repository_count, 1);
    assert!(
        audit
            .frames
            .iter()
            .skip(1)
            .all(|frame| frame.eligible_repository_count == 1)
    );
    validate_historical_v3_source_binding_audit(&protocol, &seal, &artifacts(&fixtures), &audit)
        .unwrap();

    let mut recommitted = audit;
    recommitted.frames[0].eligible_repository_count += 1;
    recommitted.frames[0].excluded_prior_repository_count -= 1;
    recommitted.audit_sha256 = compute_source_binding_audit_sha256(&recommitted).unwrap();
    assert!(
        validate_historical_v3_source_binding_audit(
            &protocol,
            &seal,
            &artifacts(&fixtures),
            &recommitted,
        )
        .unwrap_err()
        .contains("does not replay")
    );
}

#[test]
fn binding_rejects_protocol_seal_drift_and_raw_frame_tampering() {
    let fixtures = fixtures();
    let seal = prior_identity_seal();
    let mut wrong_seal_protocol = protocol(&seal, &fixtures);
    wrong_seal_protocol.prior_benchmark_identity_seal_sha256 = "9".repeat(64);
    wrong_seal_protocol = seal_historical_v3_protocol(wrong_seal_protocol).unwrap();
    assert!(
        bind_historical_v3_source_frames(&wrong_seal_protocol, &seal, &artifacts(&fixtures),)
            .unwrap_err()
            .contains("another prior identity seal")
    );

    let protocol = protocol(&seal, &fixtures);
    let first_page = fixtures[0].root.path().join("raw/hour-00-page-001.json");
    fs::write(first_page, b"tampered").unwrap();
    assert!(
        bind_historical_v3_source_frames(&protocol, &seal, &artifacts(&fixtures))
            .unwrap_err()
            .contains("commitment changed")
    );
}

#[test]
fn binding_rejects_pre_cutoff_repository_frames() {
    let mut fixtures = fixtures();
    fixtures[0] = frame_fixture_at(
        HistoricalV3Language::Go,
        "Go",
        0,
        &[(1, "Zed/Used"), (2, "Alpha/Go")],
        "2026-08-07",
    );
    let seal = prior_identity_seal();
    let protocol = protocol(&seal, &fixtures);
    assert!(
        bind_historical_v3_source_frames(&protocol, &seal, &artifacts(&fixtures))
            .unwrap_err()
            .contains("predates the committed repository creation cutoff")
    );
}

#[test]
fn source_frame_parser_requires_creation_timestamp() {
    let frame = b"repo,metadata\ngithub.com/example/repo,github_repository_id=1\n";
    assert!(
        parse_historical_v3_source_frame(frame)
            .unwrap_err()
            .contains("omits repository creation time")
    );
}
