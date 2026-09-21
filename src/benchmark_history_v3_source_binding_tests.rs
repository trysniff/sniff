use super::*;
use crate::benchmark::{
    HISTORICAL_V3_PROTOCOL_SCHEMA_VERSION, HistoricalV3AllowedMetadataField,
    HistoricalV3CandidateWindow, HistoricalV3ForbiddenMetadataField,
    HistoricalV3MechanicalRequirement, HistoricalV3SourceFrameBinding, HistoricalV3StopRule,
    SOURCE_FRAME_COLLECTION_MANIFEST_SCHEMA_VERSION, SOURCE_FRAME_COLLECTION_POLICY_SCHEMA_VERSION,
    SourceFramePageCommitment, SourceFrameRawPage, seal_historical_v3_protocol,
};
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::TempDir;

struct FrameFixture {
    root: TempDir,
    manifest: SourceFrameCollectionManifest,
    frame: Vec<u8>,
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
    let root = tempfile::tempdir().unwrap();
    let raw_root = root.path().join("raw");
    fs::create_dir(&raw_root).unwrap();
    let policy = super::super::SourceFrameCollectionPolicy {
        schema_version: SOURCE_FRAME_COLLECTION_POLICY_SCHEMA_VERSION,
        frame_id: format!("synthetic-{github_language}-frame"),
        source: "https://api.github.com/search/repositories".to_string(),
        api_version: "2022-11-28".to_string(),
        language: github_language.to_string(),
        created_day_utc: "2025-01-01".to_string(),
        derivation_seed: format!("{index:08x}{}", "0".repeat(32)),
        derivation_period_start_utc: "2025-01-01".to_string(),
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
                        "created_at": "2025-01-01T00:01:00Z",
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
            "github.com/{},github_repository_id={id};created_at=2025-01-01T00:01:00Z\n",
            repository.to_ascii_lowercase()
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

fn prior_identity_seal() -> HistoricalV3PriorBenchmarkIdentitySeal {
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

fn protocol(
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
        protocol_contract: "sniffbench-historical-v3-protocol-v1".to_string(),
        ranking_domain: "sniffbench-historical-v3-candidate-rank-v1".to_string(),
        ranking_seed: "3".repeat(64),
        prior_benchmark_identity_seal_sha256: seal.seal_sha256.clone(),
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
            pagination: "github_link_header_until_exhausted".to_string(),
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

fn fixtures() -> Vec<FrameFixture> {
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

fn artifacts(fixtures: &[FrameFixture]) -> Vec<HistoricalV3SourceFrameArtifact<'_>> {
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
