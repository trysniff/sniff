use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const GIT_TIMEOUT: Duration = Duration::from_secs(300);
const GIT_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;

pub(super) fn deterministic_commit(
    root: &Path,
    tree_oid: &str,
    parent_revision: &str,
    message_path: &str,
) -> Result<String, String> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "commit.gpgSign=false",
            "commit-tree",
            tree_oid,
            "-p",
            parent_revision,
            "-F",
            message_path,
        ])
        .env("GIT_AUTHOR_NAME", "SniffBench")
        .env("GIT_AUTHOR_EMAIL", "sniffbench@invalid")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_NAME", "SniffBench")
        .env("GIT_COMMITTER_EMAIL", "sniffbench@invalid")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z");
    run_git_command(&mut command, "create deterministic patched commit").and_then(output_text)
}

pub(super) fn apply_indexed_patch(
    root: &Path,
    patch_path: &str,
    check_only: bool,
) -> Result<(), String> {
    let mut args = vec!["apply"];
    if check_only {
        args.push("--check");
    }
    args.extend(["--index", "--whitespace=nowarn", patch_path]);
    git(root, &args)
}

pub(super) fn require_exact_commit(root: &Path, revision: &str) -> Result<(), String> {
    let resolved = git_text(
        root,
        &["rev-parse", "--verify", &format!("{revision}^{{commit}}")],
    )?;
    if resolved != revision {
        return Err("historical-v2 base revision did not resolve exactly".to_string());
    }
    Ok(())
}

pub(super) fn require_clean(root: &Path) -> Result<(), String> {
    if !git_text(root, &["status", "--porcelain=v1", "--untracked-files=all"])?.is_empty() {
        return Err(format!(
            "historical-v2 snapshot is not clean: {}",
            root.display()
        ));
    }
    Ok(())
}

pub(super) fn git(root: &Path, args: &[&str]) -> Result<(), String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    run_git_command(&mut command, &format!("git {}", args.join(" "))).map(|_| ())
}

pub(super) fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    run_git_command(&mut command, &format!("git {}", args.join(" "))).and_then(output_text)
}

fn run_git_command(command: &mut Command, label: &str) -> Result<Vec<u8>, String> {
    let output =
        crate::bounded_process::run_with_output_limit(command, GIT_TIMEOUT, GIT_OUTPUT_LIMIT)
            .map_err(|error| format!("historical-v2 materialization requires git: {error}"))?;
    if output.timed_out {
        return Err(format!(
            "{label} exceeded its {}-second deadline",
            GIT_TIMEOUT.as_secs()
        ));
    }
    if output.stdout_truncated || output.stderr_truncated {
        return Err(format!(
            "{label} exceeded the {GIT_OUTPUT_LIMIT}-byte output limit"
        ));
    }
    if !output.status.success() {
        return Err(format!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(4096)
                .collect::<String>()
        ));
    }
    Ok(output.stdout)
}

fn output_text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes)
        .map(|value| value.trim().to_string())
        .map_err(|_| "historical-v2 Git identity is not UTF-8".to_string())
}

pub(super) fn create_new_absolute_directory(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.exists() {
        return Err(format!(
            "historical-v2 slot root must be a new absolute path: {}",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "historical-v2 slot root has no parent".to_string())?;
    let parent = fs::canonicalize(parent)
        .map(normalize_path)
        .map_err(|error| format!("failed to resolve historical-v2 work parent: {error}"))?;
    let name = path
        .file_name()
        .ok_or_else(|| "historical-v2 slot root has no final component".to_string())?;
    let resolved = parent.join(name);
    fs::create_dir(&resolved)
        .map_err(|error| format!("failed to create historical-v2 slot root: {error}"))?;
    Ok(resolved)
}

pub(super) fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            format!("failed to create historical-v2 materialization input: {error}")
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist historical-v2 materialization input: {error}"))
}

pub(super) fn remove_generated_root(path: &Path) -> Result<(), String> {
    let path = fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve historical-v2 generated root: {error}"))?;
    if path.parent().is_none() || !path.is_dir() {
        return Err("refusing to remove unsafe historical-v2 generated root".to_string());
    }
    fs::remove_dir_all(&path).map_err(|error| {
        format!(
            "failed to remove historical-v2 generated root {}: {error}",
            path.display()
        )
    })
}

pub(super) fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| "historical-v2 materialization path is not UTF-8".to_string())
}

pub(super) fn canonical_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map(normalize_path)
        .map_err(|error| format!("failed to resolve historical-v2 {label}: {error}"))
}

pub(super) fn git_common_directory(root: &Path) -> Result<PathBuf, String> {
    let common = PathBuf::from(git_text(root, &["rev-parse", "--git-common-dir"])?);
    let common = if common.is_absolute() {
        common
    } else {
        root.join(common)
    };
    canonical_path(&common, "Git common directory")
}

pub(super) fn require_repository(value: &str) -> Result<(), String> {
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0] != "github.com"
        || parts[1..].iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.ends_with(".git")
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(
            "historical-v2 repository identity is not canonical GitHub owner/repo".to_string(),
        );
    }
    Ok(())
}

pub(super) fn require_revision(value: &str) -> Result<(), String> {
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("historical-v2 base revision must be a complete Git SHA-1".to_string())
    }
}

pub(super) fn require_sha256(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("historical-v2 patch hash must be a SHA-256 digest".to_string())
    }
}

pub(super) fn require_oid(value: &str) -> Result<(), String> {
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("historical-v2 Git object identity must be a complete SHA-1".to_string())
    }
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
