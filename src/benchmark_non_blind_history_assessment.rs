use super::non_blind_history::{COMMIT_RANK_CONTRACT, validate_policy};
use super::{
    HistoricalAssessmentDisposition, HistoricalAssessmentEvidence, HistoricalCommitMetadata,
    HistoricalEvidenceKind, HistoricalExclusionReason, HistoricalRepositoryAssessment,
    HistoricalRepositoryCandidate, HistoricalRepositoryFacts, HistoricalSelectedProvenance,
    HistoricalTestOutcome, NON_BLIND_HISTORY_ASSESSMENT_PROTOCOL_SCHEMA_VERSION,
    NON_BLIND_HISTORY_ASSESSMENT_SCHEMA_VERSION, NonBlindHistoryAssessment,
    NonBlindHistoryWorksheet, NonBlindSelectionPolicy,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[path = "benchmark_non_blind_history_assessment_state.rs"]
mod assessment_state;

const ASSESSMENT_CONTRACT: &str = "sniffbench-non-blind-history-assessment-v1";
const FROZEN_PROTOCOL_SHA256: &str =
    "2044866f0d3c84b6220a66f646cf3f92d19fbec2a241e0897918f74fc5541e2b";
const FROZEN_WORKSHEET_PATH: &str = "sniffbench/non-blind-v1-history-worksheet.json";
const SUPPORTED_LANGUAGES: [&str; 6] =
    ["go", "javascript", "kotlin", "python", "rust", "typescript"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalAssessmentProtocol {
    schema_version: u32,
    protocol_id: String,
    prepared_at: String,
    precommit_parent_revision: String,
    no_fallbacks: bool,
    history_worksheet: HistoryWorksheetReference,
    repository_snapshot: serde_json::Value,
    commit_selection: serde_json::Value,
    source_eligibility: serde_json::Value,
    test_recipe: serde_json::Value,
    quota_and_output: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryWorksheetReference {
    artifact_path: String,
    sha256: String,
    task_sha256: String,
    candidate_count: usize,
}

pub fn prepare_non_blind_history_assessment(
    policy_bytes: &[u8],
    worksheet_bytes: &[u8],
    protocol_bytes: &[u8],
) -> Result<NonBlindHistoryAssessment, String> {
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("failed to parse non-blind selection policy: {error}"))?;
    validate_policy(&policy)?;
    let worksheet: NonBlindHistoryWorksheet = serde_json::from_slice(worksheet_bytes)
        .map_err(|error| format!("failed to parse non-blind history worksheet: {error}"))?;
    validate_history_worksheet(&policy, policy_bytes, &worksheet)?;
    let protocol = validate_protocol(protocol_bytes, worksheet_bytes, &worksheet)?;

    let quota_target = policy
        .supported_languages
        .iter()
        .map(|language| {
            (
                language.clone(),
                policy.historical_simplification.repositories_per_language,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let protocol_sha256 = sha256(protocol_bytes);
    let history_worksheet_sha256 = sha256(worksheet_bytes);
    let task_sha256 = json_sha256(&(
        ASSESSMENT_CONTRACT,
        &protocol_sha256,
        &worksheet.policy_sha256,
        &history_worksheet_sha256,
        &worksheet.task_sha256,
        &quota_target,
    ))?;
    let assessments = worksheet
        .candidates
        .iter()
        .cloned()
        .map(blank_assessment)
        .collect();
    let result = NonBlindHistoryAssessment {
        schema_version: NON_BLIND_HISTORY_ASSESSMENT_SCHEMA_VERSION,
        protocol_sha256,
        policy_sha256: worksheet.policy_sha256.clone(),
        history_worksheet_sha256,
        history_task_sha256: protocol.history_worksheet.task_sha256,
        task_sha256,
        quota_target,
        assessments,
    };
    validate_non_blind_history_assessment(policy_bytes, worksheet_bytes, protocol_bytes, &result)?;
    Ok(result)
}

pub fn validate_non_blind_history_assessment(
    policy_bytes: &[u8],
    worksheet_bytes: &[u8],
    protocol_bytes: &[u8],
    assessment: &NonBlindHistoryAssessment,
) -> Result<(), String> {
    let expected = prepare_assessment_header(policy_bytes, worksheet_bytes, protocol_bytes)?;
    if assessment.schema_version != expected.schema_version
        || assessment.protocol_sha256 != expected.protocol_sha256
        || assessment.policy_sha256 != expected.policy_sha256
        || assessment.history_worksheet_sha256 != expected.history_worksheet_sha256
        || assessment.history_task_sha256 != expected.history_task_sha256
        || assessment.task_sha256 != expected.task_sha256
        || assessment.quota_target != expected.quota_target
        || assessment.assessments.len() != expected.assessments.len()
    {
        return Err("historical assessment changed its immutable task".to_string());
    }

    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("failed to parse non-blind selection policy: {error}"))?;
    let subject = Regex::new(&policy.historical_simplification.commit_subject_regex)
        .map_err(|error| format!("invalid frozen historical subject regex: {error}"))?;
    let mut selected_counts = zero_language_counts();
    let mut selected_provenance_ids = HashSet::new();
    let mut incomplete_seen = false;
    for (actual, template) in assessment.assessments.iter().zip(&expected.assessments) {
        if actual.candidate != template.candidate {
            return Err(format!(
                "historical assessment changed immutable rank {}",
                template.candidate.rank
            ));
        }
        match actual.disposition {
            None => {
                incomplete_seen = true;
                validate_blank_assessment(actual)?;
            }
            Some(_) if incomplete_seen => {
                return Err(
                    "historical assessment decisions are not one contiguous ranked prefix"
                        .to_string(),
                );
            }
            Some(disposition) => validate_completed_assessment(
                actual,
                disposition,
                &policy,
                &subject,
                &mut selected_counts,
                &mut selected_provenance_ids,
            )?,
        }
    }
    Ok(())
}

pub fn complete_non_blind_history_assessment(
    policy_bytes: &[u8],
    worksheet_bytes: &[u8],
    protocol_bytes: &[u8],
    assessment: &NonBlindHistoryAssessment,
) -> Result<(), String> {
    validate_non_blind_history_assessment(
        policy_bytes,
        worksheet_bytes,
        protocol_bytes,
        assessment,
    )?;
    if assessment
        .assessments
        .iter()
        .any(|entry| entry.disposition.is_none())
    {
        return Err("historical assessment is incomplete".to_string());
    }
    let mut selected_counts = zero_language_counts();
    for entry in &assessment.assessments {
        if entry.disposition == Some(HistoricalAssessmentDisposition::Selected) {
            let language = entry
                .facts
                .as_ref()
                .and_then(|facts| facts.quota_language.as_ref())
                .ok_or_else(|| "selected historical assessment lost quota language".to_string())?;
            *selected_counts.entry(language.clone()).or_default() += 1;
        }
    }
    if selected_counts != assessment.quota_target {
        return Err(format!(
            "historical assessment did not fill its frozen language quotas: expected {:?}, got {:?}",
            assessment.quota_target, selected_counts
        ));
    }
    Ok(())
}

pub fn load_non_blind_history_checkpoints(
    template: &NonBlindHistoryAssessment,
    root: &std::path::Path,
) -> Result<Vec<HistoricalRepositoryAssessment>, String> {
    assessment_state::load_checkpoints(template, root)
}

pub fn write_non_blind_history_checkpoint(
    root: &std::path::Path,
    task_sha256: &str,
    assessment: &HistoricalRepositoryAssessment,
) -> Result<(), String> {
    assessment_state::write_checkpoint(root, task_sha256, assessment)
}

pub fn rank_historical_commits(
    policy: &NonBlindSelectionPolicy,
    repository: &str,
    commits: &[HistoricalCommitMetadata],
) -> Result<Vec<super::RankedHistoricalCommit>, String> {
    validate_policy(policy)?;
    let subject = Regex::new(&policy.historical_simplification.commit_subject_regex)
        .map_err(|error| format!("invalid frozen historical subject regex: {error}"))?;
    let mut seen = HashSet::new();
    let mut ranked = Vec::new();
    for commit in commits {
        require_git_revision("historical commit SHA", &commit.commit_sha)?;
        if !seen.insert(commit.commit_sha.as_str()) {
            return Err(format!(
                "historical metadata repeats commit {}",
                commit.commit_sha
            ));
        }
        if commit.parent_shas.len() != 1 || !subject.is_match(&commit.subject) {
            continue;
        }
        require_git_revision("historical parent SHA", &commit.parent_shas[0])?;
        validate_changed_paths(&commit.changed_paths)?;
        let metadata_sha256 = json_sha256(commit)?;
        let rank_sha256 = sha256(
            [
                COMMIT_RANK_CONTRACT.as_bytes(),
                b"\0",
                policy.ranking_seed.as_bytes(),
                b"\0",
                repository.as_bytes(),
                b"\0",
                commit.commit_sha.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        ranked.push(super::RankedHistoricalCommit {
            rank: 0,
            commit_sha: commit.commit_sha.clone(),
            parent_sha: commit.parent_shas[0].clone(),
            subject: commit.subject.clone(),
            changed_paths: commit.changed_paths.clone(),
            metadata_sha256,
            rank_sha256,
        });
    }
    ranked.sort_by(|left, right| {
        (&left.rank_sha256, &left.commit_sha).cmp(&(&right.rank_sha256, &right.commit_sha))
    });
    for (index, commit) in ranked.iter_mut().enumerate() {
        commit.rank = index + 1;
    }
    Ok(ranked)
}

fn prepare_assessment_header(
    policy_bytes: &[u8],
    worksheet_bytes: &[u8],
    protocol_bytes: &[u8],
) -> Result<NonBlindHistoryAssessment, String> {
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("failed to parse non-blind selection policy: {error}"))?;
    validate_policy(&policy)?;
    let worksheet: NonBlindHistoryWorksheet = serde_json::from_slice(worksheet_bytes)
        .map_err(|error| format!("failed to parse non-blind history worksheet: {error}"))?;
    validate_history_worksheet(&policy, policy_bytes, &worksheet)?;
    let protocol = validate_protocol(protocol_bytes, worksheet_bytes, &worksheet)?;
    let quota_target = policy
        .supported_languages
        .iter()
        .map(|language| {
            (
                language.clone(),
                policy.historical_simplification.repositories_per_language,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let protocol_sha256 = sha256(protocol_bytes);
    let history_worksheet_sha256 = sha256(worksheet_bytes);
    let task_sha256 = json_sha256(&(
        ASSESSMENT_CONTRACT,
        &protocol_sha256,
        &worksheet.policy_sha256,
        &history_worksheet_sha256,
        &worksheet.task_sha256,
        &quota_target,
    ))?;
    Ok(NonBlindHistoryAssessment {
        schema_version: NON_BLIND_HISTORY_ASSESSMENT_SCHEMA_VERSION,
        protocol_sha256,
        policy_sha256: worksheet.policy_sha256.clone(),
        history_worksheet_sha256,
        history_task_sha256: protocol.history_worksheet.task_sha256,
        task_sha256,
        quota_target,
        assessments: worksheet
            .candidates
            .iter()
            .cloned()
            .map(blank_assessment)
            .collect(),
    })
}

fn validate_protocol(
    bytes: &[u8],
    worksheet_bytes: &[u8],
    worksheet: &NonBlindHistoryWorksheet,
) -> Result<HistoricalAssessmentProtocol, String> {
    let actual_sha256 = sha256(bytes);
    if actual_sha256 != FROZEN_PROTOCOL_SHA256 {
        return Err(format!(
            "historical assessment protocol hash mismatch: expected {FROZEN_PROTOCOL_SHA256}, got {actual_sha256}"
        ));
    }
    let protocol: HistoricalAssessmentProtocol = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse historical assessment protocol: {error}"))?;
    if protocol.schema_version != NON_BLIND_HISTORY_ASSESSMENT_PROTOCOL_SCHEMA_VERSION
        || protocol.protocol_id != ASSESSMENT_CONTRACT
        || !protocol.no_fallbacks
        || protocol.prepared_at.trim().is_empty()
        || !is_git_revision(&protocol.precommit_parent_revision)
        || protocol.history_worksheet.artifact_path != FROZEN_WORKSHEET_PATH
        || protocol.history_worksheet.sha256 != sha256(worksheet_bytes)
        || protocol.history_worksheet.task_sha256 != worksheet.task_sha256
        || protocol.history_worksheet.candidate_count != worksheet.candidates.len()
        || protocol.repository_snapshot.is_null()
        || protocol.commit_selection.is_null()
        || protocol.source_eligibility.is_null()
        || protocol.test_recipe.is_null()
        || protocol.quota_and_output.is_null()
    {
        return Err("historical assessment protocol changed its frozen contract".to_string());
    }
    Ok(protocol)
}

fn validate_history_worksheet(
    policy: &NonBlindSelectionPolicy,
    policy_bytes: &[u8],
    worksheet: &NonBlindHistoryWorksheet,
) -> Result<(), String> {
    if worksheet.schema_version != super::NON_BLIND_HISTORY_WORKSHEET_SCHEMA_VERSION
        || worksheet.policy_sha256 != sha256(policy_bytes)
        || worksheet.candidates.len() != policy.historical_simplification.assessed_repository_prefix
        || worksheet.excluded_blind_repositories.is_empty()
    {
        return Err("non-blind history worksheet changed its frozen scope".to_string());
    }
    let mut repositories = HashSet::new();
    for (index, candidate) in worksheet.candidates.iter().enumerate() {
        if candidate.rank != index + 1
            || !repositories.insert(candidate.repository.as_str())
            || !is_sha256(&candidate.rank_sha256)
        {
            return Err("non-blind history worksheet has invalid ranked candidates".to_string());
        }
    }
    Ok(())
}

fn validate_completed_assessment(
    assessment: &HistoricalRepositoryAssessment,
    disposition: HistoricalAssessmentDisposition,
    policy: &NonBlindSelectionPolicy,
    subject: &Regex,
    selected_counts: &mut BTreeMap<String, usize>,
    selected_provenance_ids: &mut HashSet<String>,
) -> Result<(), String> {
    let facts = assessment.facts.as_ref().ok_or_else(|| {
        format!(
            "historical rank {} requires structured facts",
            assessment.candidate.rank
        )
    })?;
    validate_facts(&assessment.candidate, facts, policy, subject)?;
    validate_evidence(&assessment.evidence)?;
    let derived_exclusion = derive_exclusion(facts, policy, selected_counts)?;
    validate_evidence_coverage(facts, derived_exclusion, &assessment.evidence)?;
    match disposition {
        HistoricalAssessmentDisposition::Selected => {
            if let Some(reason) = derived_exclusion {
                return Err(format!(
                    "selected historical assessment derives exclusion {reason:?}"
                ));
            }
            if assessment.exclusion_reason.is_some() {
                return Err("selected historical assessment cannot record an exclusion".to_string());
            }
            let provenance = assessment.selected_provenance.as_ref().ok_or_else(|| {
                "selected historical assessment requires label-free provenance".to_string()
            })?;
            validate_selected_provenance(&assessment.candidate, facts, provenance)?;
            if !selected_provenance_ids.insert(provenance.provenance_id.clone()) {
                return Err("historical assessment repeats a provenance_id".to_string());
            }
            let language = facts.quota_language.as_ref().ok_or_else(|| {
                "selected historical assessment requires quota language".to_string()
            })?;
            let count = selected_counts
                .get_mut(language)
                .ok_or_else(|| "historical assessment selected unsupported language".to_string())?;
            if *count >= policy.historical_simplification.repositories_per_language {
                return Err("historical assessment overfilled a language quota".to_string());
            }
            *count += 1;
        }
        HistoricalAssessmentDisposition::Excluded => {
            if assessment.selected_provenance.is_some() {
                return Err("excluded historical assessment cannot claim provenance".to_string());
            }
            let recorded = assessment.exclusion_reason.ok_or_else(|| {
                "excluded historical assessment requires a typed reason".to_string()
            })?;
            let derived = derived_exclusion.ok_or_else(|| {
                "excluded historical assessment has no evidence-derived exclusion".to_string()
            })?;
            if recorded != derived {
                return Err(format!(
                    "historical assessment recorded {recorded:?} but evidence derives {derived:?}"
                ));
            }
        }
    }
    Ok(())
}

fn validate_facts(
    candidate: &HistoricalRepositoryCandidate,
    facts: &HistoricalRepositoryFacts,
    policy: &NonBlindSelectionPolicy,
    subject: &Regex,
) -> Result<(), String> {
    if facts.repository != candidate.repository {
        return Err("historical facts changed their ranked repository".to_string());
    }
    if !facts.accessible {
        if facts.repository_empty
            || facts.default_branch.is_some()
            || facts.default_branch_head.is_some()
            || facts.complete_history
            || facts.matching_commit_count.is_some()
            || facts.selected_commit.is_some()
        {
            return Err("inaccessible historical repository claims source facts".to_string());
        }
        return Ok(());
    }
    if facts.repository_empty {
        if facts.default_branch.is_some()
            || facts.default_branch_head.is_some()
            || facts.complete_history
            || facts.matching_commit_count.is_some()
            || facts.selected_commit.is_some()
        {
            return Err("empty historical repository claims commit history".to_string());
        }
        return Ok(());
    }
    if let Some(head) = &facts.default_branch_head {
        require_git_revision("historical default-branch HEAD", head)?;
    }
    if facts.default_branch.as_deref().is_none_or(str::is_empty)
        || facts.default_branch_head.is_none()
    {
        return Err("historical default branch identity is incomplete".to_string());
    }
    if !facts.complete_history {
        return Ok(());
    }
    let matching_commit_count = facts.matching_commit_count.ok_or_else(|| {
        "complete historical repository requires a matching-commit count".to_string()
    })?;
    if (matching_commit_count == 0) != facts.selected_commit.is_none() {
        return Err("historical selected commit disagrees with matching-commit count".to_string());
    }
    if let Some(commit) = &facts.selected_commit {
        if commit.rank != 1
            || !subject.is_match(&commit.subject)
            || commit.commit_sha == commit.parent_sha
        {
            return Err(
                "historical assessment did not use its first qualifying commit".to_string(),
            );
        }
        require_git_revision("historical selected commit", &commit.commit_sha)?;
        require_git_revision("historical selected parent", &commit.parent_sha)?;
        require_sha256("historical commit metadata", &commit.metadata_sha256)?;
        require_sha256("historical commit rank", &commit.rank_sha256)?;
        validate_changed_paths(&commit.changed_paths)?;
        let expected_metadata = HistoricalCommitMetadata {
            commit_sha: commit.commit_sha.clone(),
            parent_shas: vec![commit.parent_sha.clone()],
            subject: commit.subject.clone(),
            changed_paths: commit.changed_paths.clone(),
        };
        if commit.metadata_sha256 != json_sha256(&expected_metadata)? {
            return Err("historical selected commit metadata commitment changed".to_string());
        }
        let expected_rank = sha256(
            [
                COMMIT_RANK_CONTRACT.as_bytes(),
                b"\0",
                policy.ranking_seed.as_bytes(),
                b"\0",
                candidate.repository.as_bytes(),
                b"\0",
                commit.commit_sha.as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        if commit.rank_sha256 != expected_rank {
            return Err("historical selected commit rank commitment changed".to_string());
        }
    }
    if let Some(count) = facts.parent_method_count {
        let sum = facts
            .parent_method_counts
            .values()
            .try_fold(0_usize, |total, value| {
                total
                    .checked_add(*value)
                    .ok_or_else(|| "historical method census overflowed".to_string())
            })?;
        if sum != count {
            return Err("historical parent method census does not sum".to_string());
        }
    } else if !facts.parent_method_counts.is_empty() {
        return Err("historical assessment claimed language counts without a total".to_string());
    }
    if let Some(language) = &facts.quota_language
        && !policy.supported_languages.contains(language)
    {
        return Err("historical assessment claimed unsupported quota language".to_string());
    }
    let mut methods = BTreeSet::new();
    for method in &facts.affected_methods {
        if !policy.supported_languages.contains(&method.language)
            || method.repository_path.trim().is_empty()
            || method.symbol.trim().is_empty()
            || method.start_line == 0
            || method.end_line < method.start_line
            || !is_sha256(&method.source_sha256)
            || !methods.insert(method)
        {
            return Err("historical affected-method ledger is invalid".to_string());
        }
    }
    validate_test_pair(facts)?;
    Ok(())
}

fn validate_test_pair(facts: &HistoricalRepositoryFacts) -> Result<(), String> {
    match (
        facts.test_outcome,
        &facts.test_recipe,
        &facts.parent_test,
        &facts.commit_test,
    ) {
        (None, None, None, None) => Ok(()),
        (Some(HistoricalTestOutcome::Passed), Some(recipe), Some(parent), Some(commit)) => {
            let selected = facts.selected_commit.as_ref().ok_or_else(|| {
                "passing historical test evidence requires a selected commit".to_string()
            })?;
            if recipe.is_empty()
                || parent.command != *recipe
                || commit.command != *recipe
                || parent.runtime_identity.trim().is_empty()
                || commit.runtime_identity != parent.runtime_identity
                || parent.revision != selected.parent_sha
                || commit.revision != selected.commit_sha
                || parent.status_code != Some(0)
                || commit.status_code != Some(0)
                || parent.timed_out
                || commit.timed_out
            {
                return Err("historical test evidence changed its frozen recipe".to_string());
            }
            for result in [parent, commit] {
                require_git_revision("historical tested revision", &result.revision)?;
                for value in [
                    &result.stdout_sha256,
                    &result.stderr_sha256,
                    &result.raw_result_sha256,
                ] {
                    require_sha256("historical test evidence", value)?;
                }
            }
            Ok(())
        }
        (Some(outcome), recipe, parent, commit) if outcome != HistoricalTestOutcome::Passed => {
            if recipe.is_none() && (parent.is_some() || commit.is_some()) {
                return Err(
                    "historical failed test outcome has results without a recipe".to_string(),
                );
            }
            for result in [parent, commit].into_iter().flatten() {
                require_git_revision("historical tested revision", &result.revision)?;
                for value in [
                    &result.stdout_sha256,
                    &result.stderr_sha256,
                    &result.raw_result_sha256,
                ] {
                    require_sha256("historical test evidence", value)?;
                }
            }
            Ok(())
        }
        _ => Err("historical assessment has an incomplete test-evidence pair".to_string()),
    }
}

fn derive_exclusion(
    facts: &HistoricalRepositoryFacts,
    policy: &NonBlindSelectionPolicy,
    selected_counts: &BTreeMap<String, usize>,
) -> Result<Option<HistoricalExclusionReason>, String> {
    if !facts.accessible {
        return Ok(Some(HistoricalExclusionReason::Inaccessible));
    }
    if facts.repository_empty {
        return Ok(Some(HistoricalExclusionReason::EmptyRepository));
    }
    if !facts.complete_history {
        return Ok(Some(HistoricalExclusionReason::IncompleteHistory));
    }
    let matching = facts.matching_commit_count.ok_or_else(|| {
        "historical exclusion derivation requires matching-commit count".to_string()
    })?;
    if matching == 0 {
        return Ok(Some(HistoricalExclusionReason::NoMatchingCommit));
    }
    if facts.selected_commit.is_none() {
        return Err("historical matching commits require selected rank 1".to_string());
    }
    match facts.supported_project_shape {
        Some(false) => return Ok(Some(HistoricalExclusionReason::UnsupportedProjectShape)),
        None => return Err("historical assessment lacks project-shape evidence".to_string()),
        Some(true) => {}
    }
    match facts.qualifying_production_change {
        Some(false) => {
            return Ok(Some(
                HistoricalExclusionReason::NoQualifyingProductionChange,
            ));
        }
        None => return Err("historical assessment lacks production-change evidence".to_string()),
        Some(true) => {}
    }
    if facts.affected_methods.is_empty() {
        return Ok(Some(HistoricalExclusionReason::NoAffectedMethods));
    }
    let count = facts
        .parent_method_count
        .ok_or_else(|| "historical assessment lacks parent method count".to_string())?;
    let bounds = &policy.historical_simplification.source_method_bounds;
    if count < bounds.minimum {
        return Ok(Some(HistoricalExclusionReason::BelowMethodFloor));
    }
    if count > bounds.maximum {
        return Ok(Some(HistoricalExclusionReason::AboveMethodCeiling));
    }
    let before = facts
        .source_non_whitespace_lines_before
        .ok_or_else(|| "historical assessment lacks before source-line evidence".to_string())?;
    let after = facts
        .source_non_whitespace_lines_after
        .ok_or_else(|| "historical assessment lacks after source-line evidence".to_string())?;
    if after >= before {
        return Ok(Some(HistoricalExclusionReason::NoSourceReduction));
    }
    if facts.license_path.as_deref().is_none_or(str::is_empty) {
        return Ok(Some(HistoricalExclusionReason::MissingLicense));
    }
    let test_exclusion = match facts
        .test_outcome
        .ok_or_else(|| "historical assessment lacks test outcome".to_string())?
    {
        HistoricalTestOutcome::Passed => None,
        HistoricalTestOutcome::RecipeUnavailable => {
            Some(HistoricalExclusionReason::TestRecipeUnavailable)
        }
        HistoricalTestOutcome::RecipeAmbiguous => {
            Some(HistoricalExclusionReason::TestRecipeAmbiguous)
        }
        HistoricalTestOutcome::RecipeChanged => Some(HistoricalExclusionReason::TestRecipeChanged),
        HistoricalTestOutcome::RuntimeUnavailable => {
            Some(HistoricalExclusionReason::RuntimeUnavailable)
        }
        HistoricalTestOutcome::SandboxUnavailable => {
            Some(HistoricalExclusionReason::SandboxUnavailable)
        }
        HistoricalTestOutcome::ParentFailed => Some(HistoricalExclusionReason::ParentTestsFailed),
        HistoricalTestOutcome::CommitFailed => Some(HistoricalExclusionReason::CommitTestsFailed),
        HistoricalTestOutcome::TimedOut => Some(HistoricalExclusionReason::TestTimedOut),
    };
    if test_exclusion.is_some() {
        return Ok(test_exclusion);
    }
    let language = derived_quota_language(&facts.affected_methods)?;
    if facts.quota_language.as_deref() != Some(language) {
        return Err("historical quota language disagrees with affected methods".to_string());
    }
    if selected_counts.get(language).copied().unwrap_or_default()
        >= policy.historical_simplification.repositories_per_language
    {
        return Ok(Some(HistoricalExclusionReason::QuotaFilled));
    }
    Ok(None)
}

fn derived_quota_language(methods: &[super::AffectedHistoricalMethod]) -> Result<&str, String> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for method in methods {
        *counts.entry(method.language.as_str()).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(
            |(left_language, left_count), (right_language, right_count)| {
                left_count
                    .cmp(right_count)
                    .then_with(|| right_language.cmp(left_language))
            },
        )
        .map(|(language, _)| language)
        .ok_or_else(|| "historical quota language requires affected methods".to_string())
}

fn validate_evidence(evidence: &[HistoricalAssessmentEvidence]) -> Result<(), String> {
    let mut kinds = BTreeSet::new();
    let mut paths = HashSet::new();
    for entry in evidence {
        if !kinds.insert(entry.kind)
            || !paths.insert(entry.artifact_path.as_str())
            || entry.source.trim().is_empty()
            || entry.observed_at.trim().is_empty()
            || !safe_relative(&entry.artifact_path)
            || !is_sha256(&entry.sha256)
        {
            return Err("historical assessment evidence is invalid or duplicated".to_string());
        }
    }
    Ok(())
}

fn validate_evidence_coverage(
    facts: &HistoricalRepositoryFacts,
    exclusion: Option<HistoricalExclusionReason>,
    evidence: &[HistoricalAssessmentEvidence],
) -> Result<(), String> {
    let present = evidence
        .iter()
        .map(|entry| entry.kind)
        .collect::<BTreeSet<_>>();
    let mut required = BTreeSet::from([HistoricalEvidenceKind::RepositoryRefs]);
    if facts.matching_commit_count.is_some() {
        required.insert(HistoricalEvidenceKind::CommitMetadata);
    }
    if facts.supported_project_shape.is_some() || facts.parent_method_count.is_some() {
        required.insert(HistoricalEvidenceKind::SourceCensus);
    }
    if facts.qualifying_production_change.is_some()
        || facts.source_non_whitespace_lines_before.is_some()
        || facts.source_non_whitespace_lines_after.is_some()
    {
        required.insert(HistoricalEvidenceKind::SourceDelta);
    }
    if facts.license_path.is_some() || exclusion == Some(HistoricalExclusionReason::MissingLicense)
    {
        required.insert(HistoricalEvidenceKind::License);
    }
    if facts.test_outcome.is_some() {
        required.insert(HistoricalEvidenceKind::TestRecipe);
    }
    if facts.parent_test.is_some() {
        required.insert(HistoricalEvidenceKind::ParentTest);
    }
    if facts.commit_test.is_some() {
        required.insert(HistoricalEvidenceKind::CommitTest);
    }
    if !required.is_subset(&present) {
        return Err(format!(
            "historical assessment evidence is incomplete: required {required:?}, got {present:?}"
        ));
    }
    Ok(())
}

fn validate_selected_provenance(
    candidate: &HistoricalRepositoryCandidate,
    facts: &HistoricalRepositoryFacts,
    provenance: &HistoricalSelectedProvenance,
) -> Result<(), String> {
    let commit = facts
        .selected_commit
        .as_ref()
        .ok_or_else(|| "selected historical provenance requires a ranked commit".to_string())?;
    let repository = format!("https://{}", candidate.repository);
    if provenance.provenance_id.trim().is_empty()
        || provenance.upstream_url != repository
        || provenance.upstream_revision != commit.commit_sha
        || provenance.upstream_record_id != commit.commit_sha
        || provenance.before.is_empty()
        || provenance.after.is_empty()
        || provenance.behavioral_evidence.len() < 2
    {
        return Err("selected historical provenance is incomplete or inconsistent".to_string());
    }
    let mut before_paths = HashSet::new();
    for snapshot in &provenance.before {
        validate_provenance_snapshot(snapshot, &repository, &commit.parent_sha, &mut before_paths)?;
    }
    let mut after_paths = HashSet::new();
    for snapshot in &provenance.after {
        validate_provenance_snapshot(snapshot, &repository, &commit.commit_sha, &mut after_paths)?;
    }
    validate_provenance_artifact(&provenance.license)?;
    for artifact in &provenance.behavioral_evidence {
        validate_provenance_artifact(artifact)?;
    }
    Ok(())
}

fn validate_provenance_snapshot<'a>(
    snapshot: &'a super::SourceSnapshot,
    repository: &str,
    revision: &str,
    paths: &mut HashSet<&'a str>,
) -> Result<(), String> {
    if snapshot.repository != repository
        || snapshot.revision != revision
        || !safe_relative(&snapshot.repository_path)
        || !safe_relative(&snapshot.artifact_path)
        || !is_sha256(&snapshot.sha256)
        || !paths.insert(snapshot.repository_path.as_str())
    {
        return Err("selected historical source snapshot is invalid or duplicated".to_string());
    }
    Ok(())
}

fn validate_provenance_artifact(artifact: &super::ProvenanceArtifact) -> Result<(), String> {
    if artifact.description.trim().is_empty()
        || !safe_relative(&artifact.artifact_path)
        || !is_sha256(&artifact.sha256)
    {
        return Err("selected historical provenance artifact is invalid".to_string());
    }
    Ok(())
}

fn validate_blank_assessment(assessment: &HistoricalRepositoryAssessment) -> Result<(), String> {
    if assessment.facts.is_some()
        || !assessment.evidence.is_empty()
        || assessment.exclusion_reason.is_some()
        || assessment.selected_provenance.is_some()
    {
        return Err("unassessed historical rank contains result data".to_string());
    }
    Ok(())
}

fn blank_assessment(candidate: HistoricalRepositoryCandidate) -> HistoricalRepositoryAssessment {
    HistoricalRepositoryAssessment {
        candidate,
        facts: None,
        evidence: Vec::new(),
        disposition: None,
        exclusion_reason: None,
        selected_provenance: None,
    }
}

fn validate_changed_paths(paths: &[super::HistoricalChangedPath]) -> Result<(), String> {
    let mut previous: Option<(&str, &str)> = None;
    for path in paths {
        if !matches!(path.status.as_str(), "A" | "C" | "D" | "M" | "R" | "T")
            || !safe_relative(&path.path)
        {
            return Err("historical commit changed-path ledger is invalid".to_string());
        }
        let current = (path.path.as_str(), path.status.as_str());
        if previous.is_some_and(|value| value >= current) {
            return Err("historical commit changed paths must be unique and sorted".to_string());
        }
        previous = Some(current);
    }
    Ok(())
}

fn zero_language_counts() -> BTreeMap<String, usize> {
    SUPPORTED_LANGUAGES
        .into_iter()
        .map(|language| (language.to_string(), 0))
        .collect()
}

fn safe_relative(value: &str) -> bool {
    let path = std::path::Path::new(value);
    !value.trim().is_empty()
        && !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
}

fn require_git_revision(label: &str, value: &str) -> Result<(), String> {
    if is_git_revision(value) {
        Ok(())
    } else {
        Err(format!("{label} must be a lowercase complete Git SHA"))
    }
}

fn is_git_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(format!("{label} must be a lowercase SHA-256 digest"))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to serialize historical assessment commitment: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_non_blind_history_assessment_tests.rs"]
mod tests;
