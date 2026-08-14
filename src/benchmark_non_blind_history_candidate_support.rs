use super::{HistoricalGitDiscovery, HistoricalRepositoryFacts, remove_historical_materialization};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
pub(super) struct RepositoryRefsEvidence<'a> {
    pub(super) repository: &'a str,
    pub(super) state: &'a str,
    pub(super) discovery: Option<&'a HistoricalGitDiscovery>,
    pub(super) inaccessible_probe: Option<&'a InaccessibleProbe>,
}

#[derive(Debug, Serialize)]
pub(super) struct InaccessibleProbe {
    pub(super) url: String,
    pub(super) status: u16,
}

pub(super) fn facts_from_discovery(
    discovery: &HistoricalGitDiscovery,
) -> HistoricalRepositoryFacts {
    let mut facts = base_facts(&discovery.repository, true, false);
    facts.default_branch = Some(discovery.default_branch.clone());
    facts.default_branch_head = Some(discovery.default_branch_head.clone());
    facts.complete_history = true;
    facts.matching_commit_count = Some(discovery.matching_commit_count);
    facts.selected_commit = discovery.selected_commit.clone();
    facts
}

pub(super) fn base_facts(
    repository: &str,
    accessible: bool,
    repository_empty: bool,
) -> HistoricalRepositoryFacts {
    HistoricalRepositoryFacts {
        repository: repository.to_string(),
        accessible,
        repository_empty,
        default_branch: None,
        default_branch_head: None,
        complete_history: false,
        matching_commit_count: None,
        selected_commit: None,
        supported_project_shape: None,
        qualifying_production_change: None,
        parent_method_counts: BTreeMap::new(),
        parent_method_count: None,
        affected_methods: Vec::new(),
        quota_language: None,
        source_non_whitespace_lines_before: None,
        source_non_whitespace_lines_after: None,
        production_paths: Vec::new(),
        license_path: None,
        test_preparation: Vec::new(),
        test_recipe: None,
        parent_test: None,
        commit_test: None,
        test_outcome: None,
    }
}

pub(super) async fn probe_inaccessible(
    client: &Client,
    repository: &str,
) -> Result<Option<InaccessibleProbe>, String> {
    let url = format!("https://{repository}.git/info/refs?service=git-upload-pack");
    let mut last_error = String::new();
    for attempt in 0..3_u32 {
        match client.get(&url).send().await {
            Ok(response) if inaccessible_repository_status(response.status()) => {
                return Ok(Some(InaccessibleProbe {
                    url,
                    status: response.status().as_u16(),
                }));
            }
            Ok(response)
                if response.status().is_server_error()
                    || response.status() == StatusCode::TOO_MANY_REQUESTS =>
            {
                last_error = format!("repository probe returned {}", response.status());
            }
            Ok(_) => return Ok(None),
            Err(error) => last_error = error.to_string(),
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_secs(1_u64 << attempt)).await;
        }
    }
    Err(format!(
        "historical repository availability probe failed for {repository}: {last_error}"
    ))
}

fn inaccessible_repository_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND | StatusCode::GONE
    )
}

pub(super) fn cleanup_rank_work(
    work_root: &Path,
    rank_work: &Path,
    repository_root: &Path,
) -> Result<(), String> {
    let snapshot_root = rank_work.join("snapshots");
    if snapshot_root.exists() && repository_root.exists() {
        remove_historical_materialization(repository_root, &snapshot_root)?;
    }
    remove_generated_rank_work(work_root, rank_work)
}

pub(super) fn remove_generated_rank_work(work_root: &Path, rank_work: &Path) -> Result<(), String> {
    if !rank_work.exists() {
        return Ok(());
    }
    let work_root = fs::canonicalize(work_root)
        .map_err(|error| format!("failed to resolve historical work root: {error}"))?;
    let rank_work = fs::canonicalize(rank_work)
        .map_err(|error| format!("failed to resolve historical rank work: {error}"))?;
    if rank_work == work_root || !rank_work.starts_with(&work_root) {
        return Err("historical rank work escaped its state directory".to_string());
    }
    fs::remove_dir_all(&rank_work).map_err(|error| {
        format!(
            "failed to remove historical rank work {}: {error}",
            rank_work.display()
        )
    })
}

pub(super) fn observation_timestamp() -> Result<String, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_secs();
    Ok(format!("unix:{seconds}"))
}

pub(super) fn provenance_id(repository: &str, revision: &str) -> String {
    let bytes = [
        b"sniffbench-historical-provenance-v1".as_slice(),
        b"\0",
        repository.as_bytes(),
        b"\0",
        revision.as_bytes(),
    ]
    .concat();
    format!("historical-{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_git_auth_challenge_is_a_reproducible_inaccessible_state() {
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::GONE,
        ] {
            assert!(inaccessible_repository_status(status));
        }
        for status in [
            StatusCode::OK,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(!inaccessible_repository_status(status));
        }
    }
}
