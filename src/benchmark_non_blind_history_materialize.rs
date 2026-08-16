use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const GIT_CLONE_TIMEOUT: Duration = Duration::from_secs(900);
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const GIT_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalCloneOutcome {
    Complete,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalSnapshotRoots {
    pub parent: PathBuf,
    pub commit: PathBuf,
}

pub fn materialize_historical_snapshots(
    repository_root: &Path,
    parent_revision: &str,
    commit_revision: &str,
    snapshot_root: &Path,
) -> Result<HistoricalSnapshotRoots, String> {
    require_revision(parent_revision)?;
    require_revision(commit_revision)?;
    if parent_revision == commit_revision {
        return Err("historical parent and commit revisions must differ".to_string());
    }
    let snapshot_root = absolute_new_directory(snapshot_root, "historical snapshot root")?;
    let parent = snapshot_root.join("parent");
    let commit = snapshot_root.join("commit");
    add_worktree(repository_root, &parent, parent_revision)?;
    if let Err(error) = add_worktree(repository_root, &commit, commit_revision) {
        let _ = remove_worktree(repository_root, &parent);
        let _ = fs::remove_dir_all(&snapshot_root);
        return Err(error);
    }
    Ok(HistoricalSnapshotRoots { parent, commit })
}

pub fn remove_historical_materialization(
    repository_root: &Path,
    snapshot_root: &Path,
) -> Result<(), String> {
    let repository_root = canonicalize(repository_root)
        .map_err(|error| format!("failed to resolve historical repository: {error}"))?;
    let snapshot_root = absolute_existing_child(snapshot_root, "historical snapshot root")?;
    for name in ["parent", "commit"] {
        let path = snapshot_root.join(name);
        if path.exists() {
            remove_worktree(&repository_root, &path)?;
        }
    }
    run_git(&repository_root, &["worktree", "prune", "--expire", "now"])?;
    if snapshot_root.exists() {
        fs::remove_dir(&snapshot_root).map_err(|error| {
            format!(
                "failed to remove historical snapshot root {}: {error}",
                snapshot_root.display()
            )
        })?;
    }
    Ok(())
}

pub fn clone_complete_historical_repository(
    repository: &str,
    destination: &Path,
) -> Result<HistoricalCloneOutcome, String> {
    let url = format!("https://{repository}.git");
    clone_complete_historical_repository_url(repository, &url, destination)
}

pub(super) fn clone_complete_historical_repository_url(
    repository: &str,
    url: &str,
    destination: &Path,
) -> Result<HistoricalCloneOutcome, String> {
    let destination = absolute_new_child(destination, "historical clone destination")?;
    let mut last_error = String::new();
    for attempt in 0..3_u32 {
        remove_new_child_if_present(&destination)?;
        let mut command = Command::new("git");
        command.args([
            "-c",
            "core.autocrlf=false",
            "clone",
            "--no-checkout",
            "--no-tags",
            url,
        ]);
        command.arg(&destination);
        let output = run_bounded(&mut command, GIT_CLONE_TIMEOUT)?;
        if output.timed_out {
            last_error = format!(
                "git clone exceeded its {}-second deadline",
                GIT_CLONE_TIMEOUT.as_secs()
            );
        } else if output.status.success() {
            if git_optional(&destination, &["rev-parse", "--verify", "HEAD"])?.is_none() {
                return Ok(HistoricalCloneOutcome::Empty);
            }
            run_git(
                &destination,
                &["checkout", "--force", "--detach", "origin/HEAD"],
            )?;
            return Ok(HistoricalCloneOutcome::Complete);
        } else {
            last_error = bounded(&String::from_utf8_lossy(&output.stderr), 2048);
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_secs(1_u64 << attempt));
        }
    }
    remove_new_child_if_present(&destination)?;
    Err(format!(
        "complete historical clone failed for {repository}: {last_error}"
    ))
}

fn add_worktree(repository: &Path, destination: &Path, revision: &str) -> Result<(), String> {
    if destination.exists() {
        return Err(format!(
            "historical snapshot already exists: {}",
            destination.display()
        ));
    }
    let destination_text = destination
        .to_str()
        .ok_or_else(|| "historical snapshot path is not UTF-8".to_string())?;
    run_git(
        repository,
        &[
            "worktree",
            "add",
            "--detach",
            "--force",
            destination_text,
            revision,
        ],
    )?;
    Ok(())
}

fn remove_worktree(repository: &Path, path: &Path) -> Result<(), String> {
    let path = path
        .to_str()
        .ok_or_else(|| "historical snapshot path is not UTF-8".to_string())?;
    run_git(repository, &["worktree", "remove", "--force", path])?;
    Ok(())
}

fn run_git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    let output = run_bounded(&mut command, GIT_COMMAND_TIMEOUT)?;
    if output.timed_out {
        return Err(format!(
            "git {} exceeded its {}-second deadline",
            args.join(" "),
            GIT_COMMAND_TIMEOUT.as_secs()
        ));
    }
    if !output.status.success() {
        return Err(format!(
            "git {} failed for {}: {}",
            args.join(" "),
            root.display(),
            bounded(&String::from_utf8_lossy(&output.stderr), 2048)
        ));
    }
    Ok(output.stdout)
}

fn git_optional(root: &Path, args: &[&str]) -> Result<Option<Vec<u8>>, String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    let output = run_bounded(&mut command, GIT_COMMAND_TIMEOUT)?;
    if output.timed_out {
        return Err(format!("git {} timed out", args.join(" ")));
    }
    Ok(output.status.success().then_some(output.stdout))
}

fn run_bounded(
    command: &mut Command,
    timeout: Duration,
) -> Result<crate::bounded_process::BoundedOutput, String> {
    let output = crate::bounded_process::run_with_output_limit(command, timeout, GIT_OUTPUT_LIMIT)
        .map_err(|error| format!("historical materialization requires git: {error}"))?;
    if output.stdout_truncated || output.stderr_truncated {
        return Err(format!(
            "historical git output exceeded the {GIT_OUTPUT_LIMIT}-byte limit"
        ));
    }
    Ok(output)
}

fn absolute_new_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = absolute_new_child(path, label)?;
    fs::create_dir(&path)
        .map_err(|error| format!("failed to create {label} {}: {error}", path.display()))?;
    Ok(path)
}

fn absolute_new_child(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.exists() {
        return Err(format!(
            "{label} must be a new absolute path: {}",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} has no parent"))?;
    let parent = canonicalize(parent)
        .map_err(|error| format!("failed to resolve {label} parent: {error}"))?;
    let name = path
        .file_name()
        .ok_or_else(|| format!("{label} has no final component"))?;
    Ok(parent.join(name))
}

fn absolute_existing_child(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() || !path.is_dir() {
        return Err(format!(
            "{label} must be an existing absolute directory: {}",
            path.display()
        ));
    }
    canonicalize(path).map_err(|error| format!("failed to resolve {label}: {error}"))
}

fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    fs::canonicalize(path).map(normalize_path)
}

#[cfg(windows)]
fn normalize_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    text.strip_prefix(r"\\?\").map_or(path, PathBuf::from)
}

#[cfg(not(windows))]
fn normalize_path(path: PathBuf) -> PathBuf {
    path
}

fn remove_new_child_if_present(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(|error| {
            format!(
                "failed to remove incomplete historical clone {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn require_revision(value: &str) -> Result<(), String> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err("historical snapshot revision must be a lowercase complete Git SHA".to_string())
    }
}

fn bounded(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_local_clone_and_detached_snapshots_are_clean() {
        let source = tempfile::tempdir().unwrap();
        git(source.path(), &["init", "-b", "main"]);
        git(
            source.path(),
            &["config", "user.email", "fixture@example.test"],
        );
        git(source.path(), &["config", "user.name", "Fixture"]);
        fs::write(source.path().join("main.rs"), "fn before() {}\n").unwrap();
        git(source.path(), &["add", "."]);
        git(source.path(), &["commit", "-m", "initial"]);
        let parent = text(source.path(), &["rev-parse", "HEAD"]);
        fs::write(source.path().join("main.rs"), "fn after() {}\n").unwrap();
        git(source.path(), &["add", "."]);
        git(source.path(), &["commit", "-m", "simplify"]);
        let commit = text(source.path(), &["rev-parse", "HEAD"]);

        let root = tempfile::tempdir().unwrap();
        let clone = root.path().join("clone");
        let outcome = clone_complete_historical_repository_url(
            "fixture repository",
            &source.path().to_string_lossy(),
            &clone,
        )
        .unwrap();
        assert_eq!(outcome, HistoricalCloneOutcome::Complete);
        assert_eq!(
            text(&clone, &["rev-parse", "--is-shallow-repository"]),
            "false"
        );

        let snapshots = root.path().join("snapshots");
        let materialized =
            materialize_historical_snapshots(&clone, &parent, &commit, &snapshots).unwrap();
        assert_eq!(text(&materialized.parent, &["rev-parse", "HEAD"]), parent);
        assert_eq!(text(&materialized.commit, &["rev-parse", "HEAD"]), commit);
        assert!(text(&materialized.parent, &["status", "--porcelain"]).is_empty());
        assert!(text(&materialized.commit, &["status", "--porcelain"]).is_empty());

        remove_historical_materialization(&clone, &snapshots).unwrap();
        assert!(!snapshots.exists());
    }

    fn git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn text(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }
}
