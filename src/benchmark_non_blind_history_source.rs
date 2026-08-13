use super::source_assessment::deterministic_license_path;
use super::{
    AffectedHistoricalMethod, HistoricalDiffHunk, HistoricalProductionPathDelta,
    HistoricalRevisionSide, HistoricalSourceDeltaCensus,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
struct SourceMethod {
    symbol: String,
    start_line: usize,
    end_line: usize,
}

#[derive(Debug)]
struct SourceFile {
    language: String,
    sha256: String,
    non_whitespace_lines: usize,
    methods: Vec<SourceMethod>,
}

#[derive(Debug)]
struct SourceInventory {
    files: BTreeMap<String, SourceFile>,
    method_counts: BTreeMap<String, usize>,
    method_count: usize,
    sha256: String,
}

pub fn historical_diff_hunks(
    previous_path: Option<&str>,
    path: &str,
    diff: &[u8],
) -> Result<Vec<HistoricalDiffHunk>, String> {
    require_safe_path(path)?;
    if let Some(previous_path) = previous_path {
        require_safe_path(previous_path)?;
    }
    let text = std::str::from_utf8(diff)
        .map_err(|_| "historical zero-context diff is not UTF-8".to_string())?;
    let mut hunks = Vec::new();
    for line in text.lines() {
        if line.starts_with("@@@") {
            return Err(
                "historical source delta does not support combined merge diffs".to_string(),
            );
        }
        let Some(header) = line.strip_prefix("@@ ") else {
            continue;
        };
        let end = header
            .find(" @@")
            .ok_or_else(|| "historical diff hunk header is incomplete".to_string())?;
        let ranges = header[..end].split_ascii_whitespace().collect::<Vec<_>>();
        if ranges.len() != 2 {
            return Err(
                "historical diff hunk must contain one parent and commit range".to_string(),
            );
        }
        let (parent_start, parent_count) = parse_range(ranges[0], '-')?;
        let (commit_start, commit_count) = parse_range(ranges[1], '+')?;
        hunks.push(HistoricalDiffHunk {
            previous_path: previous_path.map(str::to_string),
            path: path.to_string(),
            parent_start,
            parent_count,
            commit_start,
            commit_count,
        });
    }
    hunks.sort();
    hunks.dedup();
    Ok(hunks)
}

pub fn census_historical_source_delta(
    parent_revision: &str,
    commit_revision: &str,
    parent_root: &Path,
    commit_root: &Path,
    hunks: &[HistoricalDiffHunk],
) -> Result<HistoricalSourceDeltaCensus, String> {
    verify_snapshot(parent_root, parent_revision)?;
    verify_snapshot(commit_root, commit_revision)?;
    let parent = match source_inventory(parent_root) {
        Ok(inventory) => inventory,
        Err(error) => {
            return Ok(failed_census(
                parent_revision,
                commit_revision,
                format!("parent snapshot: {error}"),
            ));
        }
    };
    let commit = match source_inventory(commit_root) {
        Ok(inventory) => inventory,
        Err(error) => {
            return Ok(failed_census(
                parent_revision,
                commit_revision,
                format!("commit snapshot: {error}"),
            ));
        }
    };
    let mut affected = BTreeSet::new();
    let mut changed_paths =
        BTreeMap::<(Option<String>, String), HistoricalProductionPathDelta>::new();
    for hunk in hunks {
        require_safe_path(&hunk.path)?;
        if let Some(previous_path) = &hunk.previous_path {
            require_safe_path(previous_path)?;
        }
        validate_hunk(hunk)?;
        let parent_path = hunk.previous_path.as_deref().unwrap_or(&hunk.path);
        let parent_file = parent.files.get(parent_path);
        let commit_file = commit.files.get(&hunk.path);
        if parent_file.is_none() && commit_file.is_none() {
            continue;
        }
        changed_paths
            .entry((hunk.previous_path.clone(), hunk.path.clone()))
            .or_insert_with(|| HistoricalProductionPathDelta {
                previous_path: hunk.previous_path.clone(),
                path: hunk.path.clone(),
                parent_sha256: parent_file.map(|file| file.sha256.clone()),
                commit_sha256: commit_file.map(|file| file.sha256.clone()),
                parent_non_whitespace_lines: parent_file
                    .map_or(0, |file| file.non_whitespace_lines),
                commit_non_whitespace_lines: commit_file
                    .map_or(0, |file| file.non_whitespace_lines),
            });
        if let Some(file) = parent_file {
            collect_affected(
                &mut affected,
                HistoricalRevisionSide::Parent,
                parent_path,
                file,
                hunk.parent_start,
                hunk.parent_count,
            );
        }
        if let Some(file) = commit_file {
            collect_affected(
                &mut affected,
                HistoricalRevisionSide::Commit,
                &hunk.path,
                file,
                hunk.commit_start,
                hunk.commit_count,
            );
        }
    }
    let production_paths = changed_paths.into_values().collect::<Vec<_>>();
    let before = production_paths
        .iter()
        .try_fold(0_usize, |total, path| {
            total.checked_add(path.parent_non_whitespace_lines)
        })
        .ok_or_else(|| "historical parent source-line census overflowed".to_string())?;
    let after = production_paths
        .iter()
        .try_fold(0_usize, |total, path| {
            total.checked_add(path.commit_non_whitespace_lines)
        })
        .ok_or_else(|| "historical commit source-line census overflowed".to_string())?;
    let affected_methods = affected.into_iter().collect::<Vec<_>>();
    let quota_language = quota_language(&affected_methods);
    Ok(HistoricalSourceDeltaCensus {
        parent_revision: parent_revision.to_string(),
        commit_revision: commit_revision.to_string(),
        supported_project_shape: true,
        parent_method_counts: parent.method_counts,
        parent_method_count: Some(parent.method_count),
        affected_methods,
        quota_language,
        qualifying_production_change: Some(!production_paths.is_empty()),
        production_paths,
        source_non_whitespace_lines_before: Some(before),
        source_non_whitespace_lines_after: Some(after),
        license_path: deterministic_license_path(commit_root)?,
        parent_source_inventory_sha256: parent.sha256,
        commit_source_inventory_sha256: commit.sha256,
        parse_failure: None,
    })
}

fn source_inventory(root: &Path) -> Result<SourceInventory, String> {
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("failed to resolve historical snapshot: {error}"))?;
    let paths = crate::walker::walk(
        canonical_root
            .to_str()
            .ok_or_else(|| "historical snapshot path is not UTF-8".to_string())?,
        &crate::config::ResolvedConfig::default(),
    )?;
    let mut files = BTreeMap::new();
    let mut method_counts = BTreeMap::new();
    let mut committed = Vec::new();
    for path in paths {
        let path = fs::canonicalize(&path)
            .map_err(|error| format!("failed to resolve historical source {path}: {error}"))?;
        let relative = path
            .strip_prefix(&canonical_root)
            .map_err(|_| "historical source escaped its snapshot".to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let length = fs::metadata(&path)
            .map_err(|error| format!("failed to inspect historical source {relative}: {error}"))?
            .len();
        if length > MAX_SOURCE_BYTES {
            return Err(format!(
                "{relative}: source is {length} bytes and exceeds the {MAX_SOURCE_BYTES}-byte parser limit"
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("failed to read historical source {relative}: {error}"))?;
        let record = crate::parser::parse_file_checked(&path.to_string_lossy())
            .map_err(|error| format!("{relative}: {error}"))?;
        *method_counts.entry(record.language.clone()).or_default() += record.methods.len();
        let methods = record
            .methods
            .into_iter()
            .map(|method| SourceMethod {
                symbol: method.name,
                start_line: method.start_line,
                end_line: method.end_line,
            })
            .collect::<Vec<_>>();
        let file_sha256 = sha256(&bytes);
        committed.push((relative.clone(), file_sha256.clone(), methods.len()));
        files.insert(
            relative,
            SourceFile {
                language: record.language,
                sha256: file_sha256,
                non_whitespace_lines: non_whitespace_lines(&bytes)?,
                methods,
            },
        );
    }
    method_counts.retain(|_, count| *count > 0);
    let method_count = method_counts.values().try_fold(0_usize, |total, count| {
        total
            .checked_add(*count)
            .ok_or_else(|| "historical method census overflowed".to_string())
    })?;
    let sha256 = sha256(
        &serde_json::to_vec(&committed)
            .map_err(|error| format!("failed to commit historical source inventory: {error}"))?,
    );
    Ok(SourceInventory {
        files,
        method_counts,
        method_count,
        sha256,
    })
}

fn collect_affected(
    affected: &mut BTreeSet<AffectedHistoricalMethod>,
    side: HistoricalRevisionSide,
    repository_path: &str,
    file: &SourceFile,
    start: usize,
    count: usize,
) {
    if count == 0 {
        return;
    }
    let end = start.saturating_add(count - 1);
    for method in &file.methods {
        if method.start_line <= end && start <= method.end_line {
            affected.insert(AffectedHistoricalMethod {
                side,
                language: file.language.clone(),
                repository_path: repository_path.to_string(),
                symbol: method.symbol.clone(),
                start_line: method.start_line,
                end_line: method.end_line,
                source_sha256: file.sha256.clone(),
            });
        }
    }
}

fn quota_language(methods: &[AffectedHistoricalMethod]) -> Option<String> {
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
        .map(|(language, _)| language.to_string())
}

fn parse_range(value: &str, prefix: char) -> Result<(usize, usize), String> {
    let body = value
        .strip_prefix(prefix)
        .ok_or_else(|| format!("historical diff range must start with {prefix}"))?;
    let (start, count) = body
        .split_once(',')
        .map_or((body, "1"), |(start, count)| (start, count));
    let start = start
        .parse::<usize>()
        .map_err(|_| "historical diff range has an invalid start".to_string())?;
    let count = count
        .parse::<usize>()
        .map_err(|_| "historical diff range has an invalid count".to_string())?;
    if count > 0 && start == 0 {
        return Err("historical diff range uses an invalid zero coordinate".to_string());
    }
    Ok((start, count))
}

fn validate_hunk(hunk: &HistoricalDiffHunk) -> Result<(), String> {
    if (hunk.parent_count > 0 && hunk.parent_start == 0)
        || (hunk.commit_count > 0 && hunk.commit_start == 0)
    {
        Err("historical diff hunk uses invalid coordinates".to_string())
    } else {
        Ok(())
    }
}

fn non_whitespace_lines(bytes: &[u8]) -> Result<usize, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "historical production source is not UTF-8".to_string())?;
    Ok(source
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

fn verify_snapshot(root: &Path, revision: &str) -> Result<(), String> {
    require_git_revision(revision)?;
    let head = git(root, &["rev-parse", "HEAD"])?;
    let status = git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    let shallow = git(root, &["rev-parse", "--is-shallow-repository"])?;
    let sparse = git(
        root,
        &[
            "config",
            "--bool",
            "--default",
            "false",
            "core.sparseCheckout",
        ],
    )?;
    let promisor = git_config_values(root, "remote.*.promisor")?;
    let partial_clone_filter = git_config_values(root, "remote.*.partialclonefilter")?;
    if !head.trim().eq_ignore_ascii_case(revision)
        || !status.trim().is_empty()
        || shallow.trim().eq_ignore_ascii_case("true")
        || sparse.trim().eq_ignore_ascii_case("true")
        || !promisor.trim().is_empty()
        || !partial_clone_filter.trim().is_empty()
    {
        return Err(format!(
            "historical snapshot is dirty, shallow, sparse, partial, or not at revision {revision}: {}",
            root.display()
        ));
    }
    Ok(())
}

fn git_config_values(root: &Path, key: &str) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["config", "--get-regexp", key])
        .output()
        .map_err(|error| format!("historical source census requires git: {error}"))?;
    match output.status.code() {
        Some(0) => String::from_utf8(output.stdout)
            .map_err(|_| format!("git config --get-regexp {key} returned non-UTF-8 output")),
        Some(1) if output.stdout.is_empty() && output.stderr.is_empty() => Ok(String::new()),
        _ => Err(format!(
            "git config --get-regexp {key} failed for {}: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr)
        )),
    }
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("historical source census requires git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed for {}: {}",
            args.join(" "),
            root.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| format!("git {} returned non-UTF-8 output", args.join(" ")))
}

fn failed_census(parent: &str, commit: &str, error: String) -> HistoricalSourceDeltaCensus {
    HistoricalSourceDeltaCensus {
        parent_revision: parent.to_string(),
        commit_revision: commit.to_string(),
        supported_project_shape: false,
        parent_method_counts: BTreeMap::new(),
        parent_method_count: None,
        affected_methods: Vec::new(),
        quota_language: None,
        qualifying_production_change: None,
        production_paths: Vec::new(),
        source_non_whitespace_lines_before: None,
        source_non_whitespace_lines_after: None,
        license_path: None,
        parent_source_inventory_sha256: sha256(&[]),
        commit_source_inventory_sha256: sha256(&[]),
        parse_failure: Some(error),
    }
}

fn require_safe_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        Err(format!(
            "historical source path must stay relative: {value}"
        ))
    } else {
        Ok(())
    }
}

fn require_git_revision(value: &str) -> Result<(), String> {
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("historical source revision must be a complete Git SHA".to_string())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
