use super::source_selection::normalize_repository;
use super::{
    HistoricalChangedPath, HistoricalCommitMetadata, HistoricalGitDiscovery,
    NonBlindSelectionPolicy, rank_historical_commits,
};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const GIT_TIMEOUT: Duration = Duration::from_secs(300);
const HISTORY_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;

pub fn inspect_historical_git_repository(
    policy: &NonBlindSelectionPolicy,
    repository: &str,
    root: &Path,
) -> Result<HistoricalGitDiscovery, String> {
    let repository = normalize_repository(repository)?;
    require_complete_repository(&repository, root)?;
    let origin_head = git_text(root, &["symbolic-ref", "refs/remotes/origin/HEAD"])?;
    let reference = origin_head.trim();
    let default_branch = reference
        .strip_prefix("refs/remotes/origin/")
        .filter(|branch| !branch.is_empty() && !branch.contains(".."))
        .ok_or_else(|| "historical repository has no explicit origin/HEAD branch".to_string())?
        .to_string();
    let default_branch_head = git_text(root, &["rev-parse", "--verify", reference])?
        .trim()
        .to_ascii_lowercase();
    require_git_revision("historical default-branch HEAD", &default_branch_head)?;

    let history = git_bytes(
        root,
        &[
            "log",
            "-z",
            "--no-show-signature",
            "--format=%H%x00%P%x00%s",
            &default_branch_head,
        ],
    )?;
    let summaries = parse_log_records(&history)?;
    if summaries.is_empty() {
        return Err("historical default branch has no reachable commits".to_string());
    }
    let subject = Regex::new(&policy.historical_simplification.commit_subject_regex)
        .map_err(|error| format!("invalid frozen historical subject regex: {error}"))?;
    let mut commits = Vec::new();
    for (commit_sha, parent_shas, commit_subject) in &summaries {
        if parent_shas.len() != 1 || !subject.is_match(commit_subject) {
            continue;
        }
        commits.push(HistoricalCommitMetadata {
            commit_sha: commit_sha.clone(),
            parent_shas: parent_shas.clone(),
            subject: commit_subject.clone(),
            changed_paths: changed_paths(root, &parent_shas[0], commit_sha)?,
        });
    }
    let ranked = rank_historical_commits(policy, &repository, &commits)?;
    let matching_commits_sha256 = sha256(
        &serde_json::to_vec(&ranked)
            .map_err(|error| format!("failed to commit historical Git discovery: {error}"))?,
    );
    Ok(HistoricalGitDiscovery {
        repository,
        default_branch,
        default_branch_head,
        reachable_commit_count: summaries.len(),
        matching_commit_count: ranked.len(),
        matching_commits_sha256,
        selected_commit: ranked.into_iter().next(),
    })
}

fn require_complete_repository(repository: &str, root: &Path) -> Result<(), String> {
    if !root.is_dir() || git_text(root, &["rev-parse", "--is-inside-work-tree"])?.trim() != "true" {
        return Err("historical source is not a Git worktree".to_string());
    }
    if !git_text(root, &["status", "--porcelain=v1", "--untracked-files=all"])?
        .trim()
        .is_empty()
    {
        return Err("historical source worktree is dirty".to_string());
    }
    if git_text(root, &["rev-parse", "--is-shallow-repository"])?.trim() != "false" {
        return Err("historical source repository is shallow".to_string());
    }
    if git_optional_text(root, &["config", "--bool", "core.sparseCheckout"])?
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
    {
        return Err("historical source repository uses sparse checkout".to_string());
    }
    if git_optional_text(
        root,
        &["config", "--get-regexp", "^remote\\..*\\.promisor$"],
    )?
    .is_some_and(|value| !value.trim().is_empty())
    {
        return Err("historical source repository depends on a promisor remote".to_string());
    }
    let origin = git_text(root, &["remote", "get-url", "origin"])?;
    if normalize_repository(origin.trim())? != repository {
        return Err("historical source origin does not match its ranked repository".to_string());
    }
    Ok(())
}

fn parse_log_records(bytes: &[u8]) -> Result<Vec<(String, Vec<String>, String)>, String> {
    let fields = bytes.split(|byte| *byte == 0).collect::<Vec<_>>();
    if !fields.last().is_some_and(|field| field.is_empty()) {
        return Err("historical Git log is not NUL-terminated".to_string());
    }
    let fields = &fields[..fields.len() - 1];
    if fields.len() % 3 != 0 {
        return Err("historical Git log has an invalid field count".to_string());
    }
    let mut records = Vec::new();
    for fields in fields.chunks_exact(3) {
        let commit = utf8(fields[0], "commit SHA")?.to_ascii_lowercase();
        require_git_revision("historical commit SHA", &commit)?;
        let parents = utf8(fields[1], "parent SHAs")?
            .split_ascii_whitespace()
            .map(|parent| {
                let parent = parent.to_ascii_lowercase();
                require_git_revision("historical parent SHA", &parent)?;
                Ok(parent)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let subject = utf8(fields[2], "commit subject")?.to_string();
        if subject.contains('\n') || subject.contains('\r') || subject.contains('\0') {
            return Err("historical commit subject contains a record delimiter".to_string());
        }
        records.push((commit, parents, subject));
    }
    Ok(records)
}

fn changed_paths(
    root: &Path,
    parent: &str,
    commit: &str,
) -> Result<Vec<HistoricalChangedPath>, String> {
    let bytes = git_bytes(
        root,
        &[
            "diff-tree",
            "--no-commit-id",
            "--name-status",
            "-r",
            "-z",
            "-M",
            "-C",
            parent,
            commit,
        ],
    )?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let fields = bytes.split(|byte| *byte == 0).collect::<Vec<_>>();
    if !fields.last().is_some_and(|field| field.is_empty()) {
        return Err("historical changed-path ledger is not NUL-terminated".to_string());
    }
    parse_changed_path_fields(&fields[..fields.len() - 1])
}

fn parse_changed_path_fields(fields: &[&[u8]]) -> Result<Vec<HistoricalChangedPath>, String> {
    let mut index = 0_usize;
    let mut paths = Vec::new();
    while index < fields.len() {
        let status = utf8(fields[index], "changed-path status")?.to_string();
        index += 1;
        let renamed = status.starts_with('R') || status.starts_with('C');
        let previous_path = if renamed {
            let value = fields
                .get(index)
                .ok_or_else(|| "historical rename lacks its previous path".to_string())?;
            index += 1;
            Some(utf8(value, "previous changed path")?.to_string())
        } else {
            None
        };
        let value = fields
            .get(index)
            .ok_or_else(|| "historical change lacks its path".to_string())?;
        index += 1;
        paths.push(HistoricalChangedPath {
            status,
            previous_path,
            path: utf8(value, "changed path")?.to_string(),
        });
    }
    paths.sort_by(|left, right| {
        (
            left.path.as_str(),
            left.previous_path.as_deref(),
            left.status.as_str(),
        )
            .cmp(&(
                right.path.as_str(),
                right.previous_path.as_deref(),
                right.status.as_str(),
            ))
    });
    Ok(paths)
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    String::from_utf8(git_bytes(root, args)?)
        .map_err(|_| format!("git {} returned non-UTF-8 text", args.join(" ")))
}

fn git_optional_text(root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = run_git(root, args)?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|_| format!("git {} returned non-UTF-8 text", args.join(" ")))
    } else {
        Ok(None)
    }
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = run_git(root, args)?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed for {}: {}",
            args.join(" "),
            root.display(),
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(1024)
                .collect::<String>()
        ));
    }
    Ok(output.stdout)
}

fn run_git(root: &Path, args: &[&str]) -> Result<crate::bounded_process::BoundedOutput, String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    let output = crate::bounded_process::run_with_output_limit(
        &mut command,
        GIT_TIMEOUT,
        HISTORY_OUTPUT_LIMIT,
    )
    .map_err(|error| format!("historical assessment requires git: {error}"))?;
    if output.timed_out {
        return Err(format!(
            "git {} exceeded its {}-second deadline",
            args.join(" "),
            GIT_TIMEOUT.as_secs()
        ));
    }
    if output.stdout_truncated || output.stderr_truncated {
        return Err(format!(
            "git {} exceeded the {HISTORY_OUTPUT_LIMIT}-byte evidence limit",
            args.join(" ")
        ));
    }
    Ok(output)
}

fn utf8<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, String> {
    std::str::from_utf8(bytes).map_err(|_| format!("historical {label} is not UTF-8"))
}

fn require_git_revision(label: &str, value: &str) -> Result<(), String> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(format!("{label} must be a lowercase complete Git SHA"))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_non_blind_history_git_tests.rs"]
mod tests;
