use crate::report_types::StaticFlag;
use crate::roles::is_utility_helper_name;
use crate::types::{FileRecord, FindingTier};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::similarity;

struct ChurnMetrics {
    commit_count: usize,
    revert_count: usize,
}

fn collect_churn_metrics(repo_root: &Path, file_path: &str) -> Option<ChurnMetrics> {
    let rel = repo_relative_path(repo_root, file_path);
    let rel_str = rel.to_string_lossy();
    let messages = git_output(
        repo_root,
        &["log", "--follow", "--format=%s", "--", &rel_str],
    )?
    .lines()
    .map(|line| line.trim().to_string())
    .filter(|line| !line.is_empty())
    .collect::<Vec<_>>();
    let commit_count = messages.len();
    if commit_count == 0 {
        return None;
    }
    let revert_count = messages
        .iter()
        .filter(|msg| {
            let msg = msg.to_lowercase();
            msg.contains("revert") || msg.contains("rollback") || msg.contains("undo")
        })
        .count();

    Some(ChurnMetrics {
        commit_count,
        revert_count,
    })
}

fn churn_reasons(metrics: &ChurnMetrics) -> Vec<String> {
    let mut reasons = Vec::new();
    if metrics.commit_count >= 8 {
        reasons.push(format!(
            "high churn ({} commits touched this file)",
            metrics.commit_count
        ));
    }
    if metrics.revert_count >= 1 && metrics.commit_count >= 3 {
        reasons.push(format!(
            "rework-heavy file ({} commits, {} revert-like commits)",
            metrics.commit_count, metrics.revert_count
        ));
    }
    reasons
}

fn git_output(repo_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn repo_relative_path(repo_root: &Path, file_path: &str) -> PathBuf {
    let path = Path::new(file_path);
    if let Ok(stripped) = path.strip_prefix(repo_root) {
        stripped.to_path_buf()
    } else {
        path.to_path_buf()
    }
}

fn is_utility_surface(file: &FileRecord) -> bool {
    !file.methods.is_empty()
        && file
            .methods
            .iter()
            .all(|method| is_utility_helper_name(&method.name))
}

pub(crate) fn churn_flags(file_records: &[FileRecord], repo_root: &Path) -> Vec<StaticFlag> {
    let mut flags = Vec::new();

    for file in file_records {
        if crate::roles::is_intentional_surface_record(file) {
            continue;
        }

        if is_utility_surface(file) {
            continue;
        }

        let Some(metrics) = collect_churn_metrics(repo_root, &file.file_path) else {
            continue;
        };
        let reasons = churn_reasons(&metrics);
        if !reasons.is_empty() {
            flags.push(similarity::make_file_flag(
                &file.file_path,
                reasons.join("; "),
                FindingTier::KindaSlop,
                "churn",
            ));
        }
    }

    flags
}
