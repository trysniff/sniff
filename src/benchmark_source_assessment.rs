use super::{
    SOURCE_ASSESSMENT_CENSUS_CONTRACT, SourceAssessmentEvidenceKind, SourceAssessmentFacts,
    SourceAssessmentSupportingEvidence, SourceCandidateAssessment, SourceSamplingPolicy,
    SourceSelectionDisposition, SourceSelectionWorksheet, complete_source_candidate_assessment,
    selected_counts_for_assessment_prefix, validate_source_selection_worksheet,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "benchmark_source_assessment_census.rs"]
mod assessment_census;
#[path = "benchmark_source_assessment_state.rs"]
mod assessment_state;
#[path = "benchmark_source_assessment_transport.rs"]
mod assessment_transport;

use assessment_census::{census_repository, license_path};
use assessment_state::{
    CloneOutcome, checkout_path, clone_repository, load_checkpoints, remove_generated_worktree,
    write_checkpoint,
};
use assessment_transport::github_metadata;

pub(super) fn deterministic_license_path(root: &Path) -> Result<Option<String>, String> {
    license_path(root)
}

#[derive(Debug, Clone, Serialize)]
struct CensusEvidence {
    census_contract: &'static str,
    revision: Option<String>,
    method_counts: BTreeMap<String, usize>,
    observed_method_count: Option<usize>,
    supported_project_shape: bool,
    license_path: Option<String>,
    source_inventory_sha256: String,
    parse_failure: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubRepository {
    archived: bool,
    fork: bool,
}

struct AssessmentRuntime<'a> {
    client: &'a Client,
    github_token: Option<&'a str>,
    policy: &'a SourceSamplingPolicy,
    work_root: &'a Path,
    checkout_root: &'a Path,
    checkpoint_root: &'a Path,
    task_sha256: &'a str,
}

pub async fn assess_source_selection(
    policy: SourceSamplingPolicy,
    frame: &[u8],
    worksheet: SourceSelectionWorksheet,
    state_directory: &Path,
    checkout_root: &Path,
    github_token: Option<&str>,
) -> Result<SourceSelectionWorksheet, String> {
    validate_source_selection_worksheet(&policy, frame, &worksheet)?;
    fs::create_dir_all(state_directory)
        .map_err(|error| format!("failed to create source-assessment state: {error}"))?;
    fs::create_dir_all(checkout_root)
        .map_err(|error| format!("failed to create source-assessment checkouts: {error}"))?;

    let checkpoint_root = state_directory.join("checkpoints");
    let work_root = state_directory.join("work");
    fs::create_dir_all(&checkpoint_root)
        .map_err(|error| format!("failed to create source-assessment checkpoints: {error}"))?;
    fs::create_dir_all(&work_root)
        .map_err(|error| format!("failed to create source-assessment work root: {error}"))?;

    let client = Client::builder()
        .user_agent("trysniff-sniffbench-source-assessor/1")
        .build()
        .map_err(|error| format!("failed to build GitHub client: {error}"))?;
    let mut completed = load_checkpoints(&worksheet, &checkpoint_root, &work_root, checkout_root)?;
    let mut selected_counts = selected_counts_for_assessment_prefix(&policy, &completed)?;
    let runtime = AssessmentRuntime {
        client: &client,
        github_token,
        policy: &policy,
        work_root: &work_root,
        checkout_root,
        checkpoint_root: &checkpoint_root,
        task_sha256: &worksheet.task_sha256,
    };

    for candidate in worksheet.candidates.iter().skip(completed.len()) {
        eprintln!(
            "Assessing source {}/{}: {}",
            candidate.candidate.rank,
            worksheet.candidates.len(),
            candidate.candidate.repository
        );
        let assessment = assess_candidate(&runtime, candidate, &mut selected_counts).await?;
        completed.push(assessment);
    }

    let mut result = worksheet;
    result.candidates = completed;
    Ok(result)
}

async fn assess_candidate(
    runtime: &AssessmentRuntime<'_>,
    candidate: &SourceCandidateAssessment,
    selected_counts: &mut BTreeMap<String, usize>,
) -> Result<SourceCandidateAssessment, String> {
    let repository = candidate.candidate.repository.as_str();
    let slug = repository
        .strip_prefix("github.com/")
        .ok_or_else(|| format!("ranked source is not a GitHub repository: {repository}"))?;
    let api_url = format!("https://api.github.com/repos/{slug}");
    let (status, metadata_payload) =
        github_metadata(runtime.client, runtime.github_token, &api_url, repository).await?;
    let observed_at = observation_timestamp()?;
    if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
        let facts = SourceAssessmentFacts {
            repository: repository.to_string(),
            selection_quota_language: "unavailable".to_string(),
            observed_method_count: None,
            assessed_revision: None,
            method_counts: BTreeMap::new(),
            method_census_contract: None,
            repository_empty: false,
            accessible: false,
            archived: None,
            fork: None,
            license_path: None,
            supported_project_shape: None,
        };
        let assessment = complete_source_candidate_assessment(
            candidate.candidate.clone(),
            facts,
            observed_at,
            vec![SourceAssessmentSupportingEvidence {
                kind: SourceAssessmentEvidenceKind::RawSource,
                source: api_url,
                payload: metadata_payload,
            }],
            Vec::new(),
            runtime.policy,
            selected_counts,
        )?;
        write_checkpoint(runtime.checkpoint_root, runtime.task_sha256, &assessment)?;
        return Ok(assessment);
    }
    if !status.is_success() {
        return Err(format!(
            "GitHub metadata request returned {status} for {repository}: {}",
            bounded(&metadata_payload, 512)
        ));
    }
    let metadata: GithubRepository = serde_json::from_str(&metadata_payload)
        .map_err(|error| format!("invalid GitHub metadata for {repository}: {error}"))?;

    let worktree = runtime
        .work_root
        .join(format!("rank-{:04}", candidate.candidate.rank));
    remove_generated_worktree(&worktree, runtime.work_root)?;
    let selected_checkout = checkout_path(runtime.checkout_root, repository)?;
    if selected_checkout.exists() {
        return Err(format!(
            "uncheckpointed checkout already exists for {repository}: {}",
            selected_checkout.display()
        ));
    }
    let clone = clone_repository(repository, &worktree, runtime.work_root)?;
    let checkout = worktree.clone();
    if matches!(clone, CloneOutcome::Empty) {
        let facts = SourceAssessmentFacts {
            repository: repository.to_string(),
            selection_quota_language: "unsupported".to_string(),
            observed_method_count: Some(0),
            assessed_revision: None,
            method_counts: BTreeMap::new(),
            method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
            repository_empty: true,
            accessible: true,
            archived: Some(metadata.archived),
            fork: Some(metadata.fork),
            license_path: None,
            supported_project_shape: Some(true),
        };
        let census_payload = serde_json::to_string(&CensusEvidence {
            census_contract: SOURCE_ASSESSMENT_CENSUS_CONTRACT,
            revision: None,
            method_counts: BTreeMap::new(),
            observed_method_count: Some(0),
            supported_project_shape: true,
            license_path: None,
            source_inventory_sha256: sha256(&[]),
            parse_failure: None,
        })
        .map_err(|error| format!("failed to serialize empty source evidence: {error}"))?;
        let assessment = complete_source_candidate_assessment(
            candidate.candidate.clone(),
            facts,
            observed_at,
            vec![
                SourceAssessmentSupportingEvidence {
                    kind: SourceAssessmentEvidenceKind::RawSource,
                    source: api_url,
                    payload: metadata_payload,
                },
                SourceAssessmentSupportingEvidence {
                    kind: SourceAssessmentEvidenceKind::DerivedCensus,
                    source: SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
                    payload: census_payload,
                },
            ],
            Vec::new(),
            runtime.policy,
            selected_counts,
        )?;
        remove_generated_worktree(&worktree, runtime.work_root)?;
        write_checkpoint(runtime.checkpoint_root, runtime.task_sha256, &assessment)?;
        return Ok(assessment);
    }
    let revision = match clone {
        CloneOutcome::CheckedOut { revision } => revision,
        CloneOutcome::UnsupportedCheckout { revision, reason } => {
            let facts = SourceAssessmentFacts {
                repository: repository.to_string(),
                selection_quota_language: "unresolved".to_string(),
                observed_method_count: None,
                assessed_revision: Some(revision.clone()),
                method_counts: BTreeMap::new(),
                method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
                repository_empty: false,
                accessible: true,
                archived: Some(metadata.archived),
                fork: Some(metadata.fork),
                license_path: None,
                supported_project_shape: Some(false),
            };
            let census_payload = serde_json::to_string(&CensusEvidence {
                census_contract: SOURCE_ASSESSMENT_CENSUS_CONTRACT,
                revision: Some(revision),
                method_counts: BTreeMap::new(),
                observed_method_count: None,
                supported_project_shape: false,
                license_path: None,
                source_inventory_sha256: sha256(&[]),
                parse_failure: Some(format!("checkout cannot be materialized: {reason}")),
            })
            .map_err(|error| format!("failed to serialize checkout evidence: {error}"))?;
            let assessment = complete_source_candidate_assessment(
                candidate.candidate.clone(),
                facts,
                observed_at,
                vec![
                    SourceAssessmentSupportingEvidence {
                        kind: SourceAssessmentEvidenceKind::RawSource,
                        source: api_url,
                        payload: metadata_payload,
                    },
                    SourceAssessmentSupportingEvidence {
                        kind: SourceAssessmentEvidenceKind::DerivedCensus,
                        source: SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
                        payload: census_payload,
                    },
                ],
                Vec::new(),
                runtime.policy,
                selected_counts,
            )?;
            remove_generated_worktree(&worktree, runtime.work_root)?;
            write_checkpoint(runtime.checkpoint_root, runtime.task_sha256, &assessment)?;
            return Ok(assessment);
        }
        CloneOutcome::Empty => unreachable!("empty repository returned above"),
    };
    let license_path = license_path(&checkout)?;
    let census = census_repository(&checkout)?;
    let facts = SourceAssessmentFacts {
        repository: repository.to_string(),
        selection_quota_language: census.dominant_language.clone().unwrap_or_else(|| {
            if census.supported_project_shape {
                "unsupported".to_string()
            } else {
                "unresolved".to_string()
            }
        }),
        observed_method_count: census.observed_method_count,
        assessed_revision: Some(revision.clone()),
        method_counts: census.method_counts.clone(),
        method_census_contract: Some(SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string()),
        repository_empty: false,
        accessible: true,
        archived: Some(metadata.archived),
        fork: Some(metadata.fork),
        license_path: license_path.clone(),
        supported_project_shape: Some(census.supported_project_shape),
    };
    let census_payload = serde_json::to_string(&CensusEvidence {
        census_contract: SOURCE_ASSESSMENT_CENSUS_CONTRACT,
        revision: Some(revision.clone()),
        method_counts: census.method_counts,
        observed_method_count: census.observed_method_count,
        supported_project_shape: census.supported_project_shape,
        license_path: license_path.clone(),
        source_inventory_sha256: census.source_inventory_sha256,
        parse_failure: census.parse_failure,
    })
    .map_err(|error| format!("failed to serialize source evidence: {error}"))?;
    let assessment = complete_source_candidate_assessment(
        candidate.candidate.clone(),
        facts,
        observed_at,
        vec![
            SourceAssessmentSupportingEvidence {
                kind: SourceAssessmentEvidenceKind::RawSource,
                source: api_url,
                payload: metadata_payload,
            },
            SourceAssessmentSupportingEvidence {
                kind: SourceAssessmentEvidenceKind::DerivedCensus,
                source: SOURCE_ASSESSMENT_CENSUS_CONTRACT.to_string(),
                payload: census_payload,
            },
        ],
        Vec::new(),
        runtime.policy,
        selected_counts,
    )?;

    if assessment.disposition == Some(SourceSelectionDisposition::Selected) {
        write_checkpoint(runtime.checkpoint_root, runtime.task_sha256, &assessment)?;
        if checkout != selected_checkout {
            if let Some(parent) = selected_checkout.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("failed to create checkout parent: {error}"))?;
            }
            fs::rename(&checkout, &selected_checkout)
                .map_err(|error| format!("failed to retain selected checkout: {error}"))?;
        }
    } else if checkout == worktree {
        remove_generated_worktree(&worktree, runtime.work_root)?;
        write_checkpoint(runtime.checkpoint_root, runtime.task_sha256, &assessment)?;
    }
    Ok(assessment)
}

fn observation_timestamp() -> Result<String, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_secs();
    Ok(format!("unix:{seconds}"))
}

fn bounded(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_source_assessment_tests.rs"]
mod tests;
