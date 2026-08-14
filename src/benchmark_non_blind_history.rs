use super::source_selection::{eligible_source_frame, normalize_repository};
use super::{BenchmarkSourceSeal, FrameEligibilityAudit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::path::{Component, Path};

pub const NON_BLIND_HISTORY_WORKSHEET_SCHEMA_VERSION: u32 = 1;
pub(super) const HISTORY_RANK_CONTRACT: &str = "sniffbench-non-blind-history-v1";
pub(super) const COMMIT_RANK_CONTRACT: &str = "sniffbench-non-blind-commit-v1";
pub(super) const INTENTIONAL_BOUNDARY_RANK_CONTRACT: &str = "sniffbench-intentional-boundary-v1";
const EXPECTED_SUBJECT_REGEX: &str = "(?i)\\b(simplif(?:y|ied|ication)|cleanup|clean up|refactor|remove(?:d|s|ing)? (?:dead|duplicate|duplicated|redundant|unnecessary)|deduplicat(?:e|ed|ion))\\b";
const REQUIRED_LANGUAGES: [&str; 6] =
    ["go", "javascript", "kotlin", "python", "rust", "typescript"];
const REQUIRED_BOUNDARY_CATEGORIES: [&str; 8] = [
    "adapter",
    "retry_boundary",
    "public_wrapper",
    "compatibility_api",
    "generated_surface",
    "test_seam",
    "entrypoint",
    "framework_callback",
];
const REQUIRED_BOUNDARY_REQUIREMENTS: [&str; 5] = [
    "candidate source is outside the blind OSS seal",
    "the exact public/framework/test contract is captured as a hash-bound behavioral artifact before labeling",
    "selection is based on observable role and contract evidence, not path/name alone and never Sniff output",
    "independent adjudication must confirm Clean and intentional_boundary before the case can satisfy this partition",
    "a failed candidate closes its precommitted slot rather than allowing a hand-picked replacement",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonBlindSelectionPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub prepared_at: String,
    pub precommit_parent_revision: String,
    pub ranking_seed: String,
    pub no_fallbacks: bool,
    pub supported_languages: Vec<String>,
    pub historical_simplification: HistoricalSelectionPolicy,
    pub research_trajectories: ResearchSelectionPolicy,
    pub intentional_boundaries: IntentionalBoundarySelectionPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalSelectionPolicy {
    pub sampling_frame_url: String,
    pub sampling_frame_commit: String,
    pub sampling_frame_blob: String,
    pub sampling_frame_sha256: String,
    pub repository_ranking_contract: String,
    pub assessed_repository_prefix: usize,
    pub repositories_per_language: usize,
    pub commits_per_repository: usize,
    pub excluded_repository_source: String,
    pub commit_ranking_contract: String,
    pub commit_subject_regex: String,
    pub commit_requirements: Vec<String>,
    pub source_method_bounds: MethodBounds,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodBounds {
    pub minimum: usize,
    pub maximum: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchSelectionPolicy {
    pub required_sources: Vec<serde_json::Value>,
    pub selection_rule: String,
    pub failure_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySelectionPolicy {
    pub categories: Vec<String>,
    pub cases_per_category: usize,
    pub candidate_ranking_contract: String,
    pub requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRepositoryCandidate {
    pub rank: usize,
    pub repository: String,
    pub rank_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonBlindHistoryWorksheet {
    pub schema_version: u32,
    pub rank_contract: String,
    pub policy_sha256: String,
    pub frame_sha256: String,
    pub blind_source_seal_sha256: String,
    pub frame_eligibility: FrameEligibilityAudit,
    pub excluded_blind_repositories: Vec<String>,
    pub candidates: Vec<HistoricalRepositoryCandidate>,
    pub task_sha256: String,
}

pub fn prepare_non_blind_history(
    policy_bytes: &[u8],
    frame: &[u8],
    blind_seal_bytes: &[u8],
) -> Result<NonBlindHistoryWorksheet, String> {
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("failed to parse non-blind selection policy: {error}"))?;
    validate_policy(&policy)?;
    let actual_frame_sha256 = sha256(frame);
    if !actual_frame_sha256
        .eq_ignore_ascii_case(&policy.historical_simplification.sampling_frame_sha256)
    {
        return Err(format!(
            "non-blind sampling frame hash mismatch: expected {}, got {actual_frame_sha256}",
            policy.historical_simplification.sampling_frame_sha256
        ));
    }
    let blind_seal: BenchmarkSourceSeal = serde_json::from_slice(blind_seal_bytes)
        .map_err(|error| format!("failed to parse excluded blind source seal: {error}"))?;
    let blind_source_seal_sha256 = sha256(blind_seal_bytes);
    if blind_seal.computed_seal_sha256()? != blind_seal.seal_sha256 {
        return Err("excluded blind source seal commitment mismatch".to_string());
    }
    let excluded_blind_repositories = blind_seal
        .sources
        .iter()
        .map(|source| normalize_repository(&source.repository))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    if excluded_blind_repositories.is_empty() {
        return Err("excluded blind source seal has no repositories".to_string());
    }
    let excluded = excluded_blind_repositories
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let (repositories, frame_eligibility) = eligible_source_frame(frame)?;
    let mut candidates = repositories
        .into_iter()
        .filter(|repository| !excluded.contains(repository.as_str()))
        .map(|repository| HistoricalRepositoryCandidate {
            rank: 0,
            rank_sha256: sha256(
                [
                    HISTORY_RANK_CONTRACT.as_bytes(),
                    b"\0",
                    policy.ranking_seed.as_bytes(),
                    b"\0",
                    repository.as_bytes(),
                ]
                .concat()
                .as_slice(),
            ),
            repository,
        })
        .collect::<Vec<_>>();
    let prefix = policy.historical_simplification.assessed_repository_prefix;
    if candidates.len() < prefix {
        return Err(format!(
            "non-blind sampling frame has {} eligible non-blind repositories but policy requires {prefix}",
            candidates.len()
        ));
    }
    candidates.sort_by(|left, right| {
        (&left.rank_sha256, &left.repository).cmp(&(&right.rank_sha256, &right.repository))
    });
    candidates.truncate(prefix);
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.rank = index + 1;
    }
    let policy_sha256 = sha256(policy_bytes);
    let task_sha256 = json_sha256(&(
        HISTORY_RANK_CONTRACT,
        &policy_sha256,
        &actual_frame_sha256,
        &blind_source_seal_sha256,
        &frame_eligibility,
        &excluded_blind_repositories,
        &candidates,
    ))?;
    Ok(NonBlindHistoryWorksheet {
        schema_version: NON_BLIND_HISTORY_WORKSHEET_SCHEMA_VERSION,
        rank_contract: HISTORY_RANK_CONTRACT.to_string(),
        policy_sha256,
        frame_sha256: actual_frame_sha256,
        blind_source_seal_sha256,
        frame_eligibility,
        excluded_blind_repositories,
        candidates,
        task_sha256,
    })
}

pub fn validate_non_blind_history_worksheet(
    policy_bytes: &[u8],
    frame: &[u8],
    blind_seal_bytes: &[u8],
    worksheet: &NonBlindHistoryWorksheet,
) -> Result<(), String> {
    let expected = prepare_non_blind_history(policy_bytes, frame, blind_seal_bytes)?;
    if worksheet != &expected {
        return Err("non-blind history worksheet changed its immutable task".to_string());
    }
    Ok(())
}

pub(super) fn validate_policy(policy: &NonBlindSelectionPolicy) -> Result<(), String> {
    if policy.schema_version != 1
        || policy.policy_id != "sniffbench-non-blind-v1"
        || !policy.no_fallbacks
    {
        return Err(
            "non-blind selection policy has an unsupported identity or fallback mode".to_string(),
        );
    }
    require_git_revision(
        "precommit_parent_revision",
        &policy.precommit_parent_revision,
    )?;
    require_git_revision("ranking_seed", &policy.ranking_seed)?;
    require_git_revision(
        "sampling_frame_commit",
        &policy.historical_simplification.sampling_frame_commit,
    )?;
    require_git_revision(
        "sampling_frame_blob",
        &policy.historical_simplification.sampling_frame_blob,
    )?;
    require_sha256(
        "sampling_frame_sha256",
        &policy.historical_simplification.sampling_frame_sha256,
    )?;
    if !policy
        .supported_languages
        .iter()
        .map(String::as_str)
        .eq(REQUIRED_LANGUAGES)
    {
        return Err("non-blind selection policy changed the supported languages".to_string());
    }
    let history = &policy.historical_simplification;
    if history.repository_ranking_contract
        != format!(
            "sha256({HISTORY_RANK_CONTRACT}\\0 || ranking_seed || \\0 || canonical_repository_identity), ascending digest then identity"
        )
        || history.commit_ranking_contract
            != format!(
                "sha256({COMMIT_RANK_CONTRACT}\\0 || ranking_seed || \\0 || canonical_repository_identity || \\0 || full_commit_sha), ascending digest then commit SHA"
            )
        || history.commit_subject_regex != EXPECTED_SUBJECT_REGEX
        || history.assessed_repository_prefix == 0
        || history.repositories_per_language == 0
        || history.commits_per_repository != 1
        || history.source_method_bounds.minimum == 0
        || history.source_method_bounds.minimum > history.source_method_bounds.maximum
        || history.commit_requirements.is_empty()
    {
        return Err(
            "non-blind historical selection policy changed its executable contract".to_string(),
        );
    }
    safe_relative(&history.excluded_repository_source)?;
    if !history.sampling_frame_url.starts_with("https://") {
        return Err("non-blind sampling frame URL must use HTTPS".to_string());
    }
    if policy.research_trajectories.required_sources.len() != 2 {
        return Err("non-blind selection policy removed required corpus sources".to_string());
    }
    let source_ids = policy
        .research_trajectories
        .required_sources
        .iter()
        .filter_map(|source| source.get("source_id").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    if source_ids != BTreeSet::from(["slopcodebench", "trim"]) {
        return Err("non-blind selection policy must require SlopCodeBench and TRIM".to_string());
    }
    let boundaries = &policy.intentional_boundaries;
    let expected_ranking = format!(
        "sha256({INTENTIONAL_BOUNDARY_RANK_CONTRACT}\\0 || ranking_seed || \\0 || immutable_repository_revision || \\0 || repository_path || \\0 || exact_symbol_identity), ascending digest then identity"
    );
    if !boundaries
        .categories
        .iter()
        .map(String::as_str)
        .eq(REQUIRED_BOUNDARY_CATEGORIES)
        || boundaries.cases_per_category != 2
        || boundaries.candidate_ranking_contract != expected_ranking
        || !boundaries
            .requirements
            .iter()
            .map(String::as_str)
            .eq(REQUIRED_BOUNDARY_REQUIREMENTS)
    {
        return Err(
            "non-blind intentional-boundary policy changed its executable contract".to_string(),
        );
    }
    Ok(())
}

fn safe_relative(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        Err(format!(
            "non-blind artifact path must stay relative: {value}"
        ))
    } else {
        Ok(())
    }
}

fn require_git_revision(label: &str, value: &str) -> Result<(), String> {
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "{label} must be a complete 40-character Git revision"
        ))
    }
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("{label} must be a SHA-256 hex digest"))
    }
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize non-blind history commitment: {error}"))?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::{BenchmarkSourceSeal, SourceSnapshot};

    fn blind_seal_bytes(repository: &str) -> Vec<u8> {
        let mut seal = BenchmarkSourceSeal {
            schema_version: 3,
            census_contract_version: "sniff-source-census-v1".to_string(),
            selection_id: "blind-fixture".to_string(),
            selected_at: "2026-08-13T00:00:00Z".to_string(),
            selection_methodology: "fixture".to_string(),
            selection_attestation: "fixture blind selection".to_string(),
            selection_audit_sha256: "a".repeat(64),
            selection_audit_artifact_path: "selection/audit.json".to_string(),
            selection_audit_artifact_sha256: "b".repeat(64),
            selection_frame_artifact_path: "selection/frame.csv".to_string(),
            selection_frame_sha256: "c".repeat(64),
            selection_components: Vec::new(),
            sources: vec![SourceSnapshot {
                repository: format!("https://{repository}"),
                revision: "1".repeat(40),
                repository_path: "src/main.rs".to_string(),
                artifact_path: "sources/main.rs".to_string(),
                sha256: "d".repeat(64),
            }],
            context_sources: Vec::new(),
            methods: Vec::new(),
            licenses: Vec::new(),
            seal_sha256: String::new(),
        };
        seal.seal_sha256 = seal.computed_seal_sha256().unwrap();
        serde_json::to_vec_pretty(&seal).unwrap()
    }

    fn frame() -> Vec<u8> {
        b"repo,metadata\n\
github.com/example/alpha,fixture\n\
github.com/example/blind,fixture\n\
github.com/example/bravo,fixture\n\
github.com/example/charlie,fixture\n\
not-a-csv-row\n\
github.com/example/alpha,duplicate\n"
            .to_vec()
    }

    fn policy_bytes(frame: &[u8]) -> Vec<u8> {
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "policy_id": "sniffbench-non-blind-v1",
            "prepared_at": "2026-08-13T00:00:00Z",
            "precommit_parent_revision": "1".repeat(40),
            "ranking_seed": "2".repeat(40),
            "no_fallbacks": true,
            "supported_languages": [
                "go", "javascript", "kotlin", "python", "rust", "typescript"
            ],
            "historical_simplification": {
                "sampling_frame_url": "https://example.com/projects.csv",
                "sampling_frame_commit": "3".repeat(40),
                "sampling_frame_blob": "4".repeat(40),
                "sampling_frame_sha256": sha256(frame),
                "repository_ranking_contract": "sha256(sniffbench-non-blind-history-v1\\0 || ranking_seed || \\0 || canonical_repository_identity), ascending digest then identity",
                "assessed_repository_prefix": 3,
                "repositories_per_language": 1,
                "commits_per_repository": 1,
                "excluded_repository_source": "blind-seal.json",
                "commit_ranking_contract": "sha256(sniffbench-non-blind-commit-v1\\0 || ranking_seed || \\0 || canonical_repository_identity || \\0 || full_commit_sha), ascending digest then commit SHA",
                "commit_subject_regex": EXPECTED_SUBJECT_REGEX,
                "commit_requirements": ["fixture deterministic requirement"],
                "source_method_bounds": {"minimum": 1, "maximum": 10}
            },
            "research_trajectories": {
                "required_sources": [
                    {"source_id": "slopcodebench"},
                    {"source_id": "trim"}
                ],
                "selection_rule": "fixture",
                "failure_rule": "fixture"
            },
            "intentional_boundaries": {
                "categories": REQUIRED_BOUNDARY_CATEGORIES,
                "cases_per_category": 2,
                "candidate_ranking_contract": "sha256(sniffbench-intentional-boundary-v1\\0 || ranking_seed || \\0 || immutable_repository_revision || \\0 || repository_path || \\0 || exact_symbol_identity), ascending digest then identity",
                "requirements": REQUIRED_BOUNDARY_REQUIREMENTS
            }
        }))
        .unwrap()
    }

    #[test]
    fn history_worksheet_is_deterministic_and_excludes_blind_repositories() {
        let frame = frame();
        let blind_seal = blind_seal_bytes("github.com/example/blind");
        let policy = policy_bytes(&frame);

        let first = prepare_non_blind_history(&policy, &frame, &blind_seal).unwrap();
        let second = prepare_non_blind_history(&policy, &frame, &blind_seal).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.candidates.len(), 3);
        assert_eq!(
            first.excluded_blind_repositories,
            ["github.com/example/blind"]
        );
        assert!(
            first
                .candidates
                .iter()
                .all(|candidate| candidate.repository != "github.com/example/blind")
        );
        assert_eq!(first.frame_eligibility.ineligible_records.len(), 2);
        for candidate in &first.candidates {
            let expected = sha256(
                [
                    HISTORY_RANK_CONTRACT.as_bytes(),
                    b"\0",
                    b"2222222222222222222222222222222222222222",
                    b"\0",
                    candidate.repository.as_bytes(),
                ]
                .concat()
                .as_slice(),
            );
            assert_eq!(candidate.rank_sha256, expected);
        }
        validate_non_blind_history_worksheet(&policy, &frame, &blind_seal, &first).unwrap();
    }

    #[test]
    fn history_worksheet_rejects_changed_inputs_or_ranks() {
        let frame = frame();
        let blind_seal = blind_seal_bytes("github.com/example/blind");
        let policy = policy_bytes(&frame);
        let mut worksheet = prepare_non_blind_history(&policy, &frame, &blind_seal).unwrap();
        worksheet.candidates.swap(0, 1);

        let error = validate_non_blind_history_worksheet(&policy, &frame, &blind_seal, &worksheet)
            .unwrap_err();
        assert!(error.contains("changed its immutable task"));

        let mut changed_frame = frame.clone();
        changed_frame.extend_from_slice(b"github.com/example/delta,fixture\n");
        let error = prepare_non_blind_history(&policy, &changed_frame, &blind_seal).unwrap_err();
        assert!(error.contains("sampling frame hash mismatch"));

        let other_blind_seal = blind_seal_bytes("github.com/example/alpha");
        let other = prepare_non_blind_history(&policy, &frame, &other_blind_seal).unwrap();
        assert_ne!(
            other.blind_source_seal_sha256,
            worksheet.blind_source_seal_sha256
        );
        assert_ne!(other.task_sha256, worksheet.task_sha256);
    }

    #[test]
    fn policy_rejects_retrofitted_intentional_boundary_selection() {
        let frame = frame();
        let policy = policy_bytes(&frame);
        let parsed: NonBlindSelectionPolicy = serde_json::from_slice(&policy).unwrap();
        validate_policy(&parsed).unwrap();

        let mut changed = parsed.clone();
        changed.intentional_boundaries.categories.swap(0, 1);
        assert!(
            validate_policy(&changed)
                .unwrap_err()
                .contains("intentional-boundary policy changed")
        );

        let mut changed = parsed.clone();
        changed.intentional_boundaries.cases_per_category = 1;
        assert!(
            validate_policy(&changed)
                .unwrap_err()
                .contains("intentional-boundary policy changed")
        );

        let mut changed = parsed.clone();
        changed.intentional_boundaries.candidate_ranking_contract = "pick manually".to_string();
        assert!(
            validate_policy(&changed)
                .unwrap_err()
                .contains("intentional-boundary policy changed")
        );

        let mut changed = parsed;
        changed.intentional_boundaries.requirements.pop();
        assert!(
            validate_policy(&changed)
                .unwrap_err()
                .contains("intentional-boundary policy changed")
        );
    }
}
