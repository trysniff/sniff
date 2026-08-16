use super::{NonBlindHistoryWorksheet, NonBlindSelectionPolicy};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const HISTORY_RANK_DOMAIN: &str = "sniffbench-non-blind-history-v1";

pub(super) fn validate_history_worksheet(
    policy_bytes: &[u8],
    policy: &NonBlindSelectionPolicy,
    blind_bytes: &[u8],
    blind_repositories: &[String],
    worksheet: &NonBlindHistoryWorksheet,
) -> Result<(), String> {
    if policy.schema_version != 1
        || policy.policy_id != "sniffbench-non-blind-v1"
        || !policy.no_fallbacks
        || worksheet.schema_version != 1
        || worksheet.rank_contract != HISTORY_RANK_DOMAIN
        || worksheet.policy_sha256 != sha256(policy_bytes)
        || worksheet.blind_source_seal_sha256 != sha256(blind_bytes)
        || worksheet.candidates.len() != policy.historical_simplification.assessed_repository_prefix
    {
        return Err("historical-v1 worksheet identity or input commitment changed".to_string());
    }
    let excluded = repositories(
        worksheet
            .excluded_blind_repositories
            .iter()
            .map(String::as_str),
    )?;
    if excluded != blind_repositories {
        return Err("historical-v1 blind repository exclusions changed".to_string());
    }
    let mut identities = BTreeSet::new();
    let mut previous = None;
    for (index, candidate) in worksheet.candidates.iter().enumerate() {
        let expected_rank = sha256(
            format!(
                "{HISTORY_RANK_DOMAIN}\0{}\0{}",
                policy.ranking_seed, candidate.repository
            )
            .as_bytes(),
        );
        if candidate.rank != index + 1
            || candidate.rank_sha256 != expected_rank
            || previous
                .is_some_and(|previous| previous >= (&candidate.rank_sha256, &candidate.repository))
            || !identities.insert(canonical_repository(&candidate.repository)?)
        {
            return Err("historical-v1 worksheet ranking or identity changed".to_string());
        }
        previous = Some((&candidate.rank_sha256, &candidate.repository));
    }
    let expected_task_sha256 = hash_json(&(
        HISTORY_RANK_DOMAIN,
        &worksheet.policy_sha256,
        &worksheet.frame_sha256,
        &worksheet.blind_source_seal_sha256,
        &worksheet.frame_eligibility,
        &worksheet.excluded_blind_repositories,
        &worksheet.candidates,
    ))?;
    if worksheet.task_sha256 != expected_task_sha256 {
        return Err("historical-v1 worksheet task commitment changed".to_string());
    }
    Ok(())
}

pub(super) fn research_repositories(
    policy: &NonBlindSelectionPolicy,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut sources = BTreeMap::<String, Vec<String>>::new();
    for source in &policy.research_trajectories.required_sources {
        let source_id = source
            .get("source_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "research exclusion source has no source_id".to_string())?;
        if !matches!(source_id, "slopcodebench" | "trim") || sources.contains_key(source_id) {
            return Err("research exclusion source identity changed or is repeated".to_string());
        }
        let mut repositories = BTreeSet::new();
        collect_github_repositories(source, &mut repositories)?;
        sources.insert(source_id.to_string(), repositories.into_iter().collect());
    }
    if sources.len() != 2 || sources["slopcodebench"].is_empty() {
        return Err("research exclusion sources are incomplete".to_string());
    }
    Ok(sources)
}

pub(super) fn repositories<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<Vec<String>, String> {
    values
        .map(canonical_repository)
        .collect::<Result<BTreeSet<_>, _>>()
        .map(BTreeSet::into_iter)
        .map(Iterator::collect)
}

fn collect_github_repositories(
    value: &Value,
    repositories: &mut BTreeSet<String>,
) -> Result<(), String> {
    match value {
        Value::String(value) if value.contains("github.com/") => {
            repositories.insert(canonical_repository(value)?);
        }
        Value::Array(values) => {
            for value in values {
                collect_github_repositories(value, repositories)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_github_repositories(value, repositories)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn canonical_repository(value: &str) -> Result<String, String> {
    let value = value
        .trim()
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .strip_prefix("https://github.com/")
        .or_else(|| value.strip_prefix("http://github.com/"))
        .or_else(|| value.strip_prefix("github.com/"))
        .unwrap_or(value);
    let mut segments = value.split('/');
    let owner = segments.next().unwrap_or_default();
    let repository = segments.next().unwrap_or_default();
    if segments.next().is_some() || !valid_segment(owner) || !valid_segment(repository) {
        return Err(format!("invalid GitHub repository identity: {value}"));
    }
    Ok(format!("{owner}/{repository}").to_ascii_lowercase())
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v1 worksheet: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
