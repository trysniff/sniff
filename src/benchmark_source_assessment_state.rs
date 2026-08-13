use super::{SourceCandidateAssessment, SourceSelectionWorksheet};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const MINIMUM_FREE_BYTES: u64 = 1_073_741_824;

const SOURCE_ASSESSMENT_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SourceAssessmentCheckpoint {
    schema_version: u32,
    task_sha256: String,
    assessment: SourceCandidateAssessment,
}

pub(super) enum CloneOutcome {
    CheckedOut { revision: String },
    Empty,
    UnsupportedCheckout { revision: String, reason: String },
}

pub(super) fn clone_repository(
    repository: &str,
    destination: &Path,
    work_root: &Path,
) -> Result<CloneOutcome, String> {
    clone_repository_url(
        &format!("https://{repository}.git"),
        repository,
        destination,
        work_root,
    )
}

fn clone_repository_url(
    url: &str,
    repository: &str,
    destination: &Path,
    work_root: &Path,
) -> Result<CloneOutcome, String> {
    require_disk_headroom(work_root)?;
    let mut last_error = String::new();
    for attempt in 0..3_u32 {
        remove_generated_worktree(destination, work_root)?;
        let output = Command::new("git")
            .args([
                "-c",
                "core.autocrlf=false",
                "clone",
                "--no-checkout",
                "--depth",
                "1",
                "--no-tags",
                "--single-branch",
                url,
            ])
            .arg(destination)
            .output()
            .map_err(|error| format!("source assessment requires git: {error}"))?;
        if output.status.success() {
            let Some(revision) = git_optional(destination, &["rev-parse", "--verify", "HEAD"])?
            else {
                return Ok(CloneOutcome::Empty);
            };
            let revision = revision.trim().to_ascii_lowercase();
            let checkout = Command::new("git")
                .arg("-c")
                .arg("core.autocrlf=false")
                .arg("-C")
                .arg(destination)
                .args(["checkout", "--force", "HEAD"])
                .output()
                .map_err(|error| format!("source assessment requires git: {error}"))?;
            if checkout.status.success() {
                return Ok(CloneOutcome::CheckedOut { revision });
            }
            return Ok(CloneOutcome::UnsupportedCheckout {
                revision,
                reason: bounded(&String::from_utf8_lossy(&checkout.stderr), 1024),
            });
        }
        last_error = bounded(&String::from_utf8_lossy(&output.stderr), 1024);
        if attempt < 2 {
            std::thread::sleep(Duration::from_secs(1_u64 << attempt));
        }
    }
    remove_generated_worktree(destination, work_root)?;
    Err(format!("git clone failed for {repository}: {last_error}"))
}

#[cfg(test)]
pub(super) fn clone_repository_fixture(
    source: &Path,
    destination: &Path,
    work_root: &Path,
) -> Result<CloneOutcome, String> {
    clone_repository_url(
        &source.to_string_lossy(),
        "fixture repository",
        destination,
        work_root,
    )
}

pub(super) fn require_disk_headroom(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        let mut available = 0_u64;
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err("failed to determine source-assessment free disk space".to_string());
        }
        if available < MINIMUM_FREE_BYTES {
            return Err(format!(
                "source assessment paused before cloning because only {available} bytes are free; at least {MINIMUM_FREE_BYTES} are required"
            ));
        }
    }
    #[cfg(not(windows))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "source-assessment path contains a NUL byte".to_string())?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // `path` is NUL-terminated and `stats` points to writable storage for libc.
        let status = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
        if status != 0 {
            return Err("failed to determine source-assessment free disk space".to_string());
        }
        // Successful `statvfs` initializes the complete output structure.
        let stats = unsafe { stats.assume_init() };
        #[allow(clippy::unnecessary_cast)]
        let available = (stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64);
        if available < MINIMUM_FREE_BYTES {
            return Err(format!(
                "source assessment paused before cloning because only {available} bytes are free; at least {MINIMUM_FREE_BYTES} are required"
            ));
        }
    }
    Ok(())
}

pub(super) fn checkout_path(root: &Path, repository: &str) -> Result<PathBuf, String> {
    let slug = repository
        .strip_prefix("github.com/")
        .ok_or_else(|| "source-assessment repository is not canonical".to_string())?;
    let mut parts = slug.split('/');
    let owner = parts
        .next()
        .ok_or_else(|| "repository owner is missing".to_string())?;
    let name = parts
        .next()
        .ok_or_else(|| "repository name is missing".to_string())?;
    if parts.next().is_some() {
        return Err("source-assessment repository has an invalid path".to_string());
    }
    Ok(root.join(owner).join(name))
}

pub(super) fn load_checkpoints(
    worksheet: &SourceSelectionWorksheet,
    checkpoint_root: &Path,
    work_root: &Path,
    checkout_root: &Path,
) -> Result<Vec<SourceCandidateAssessment>, String> {
    remove_checkpoint_temps(checkpoint_root)?;
    let mut completed = Vec::new();
    let inherited_prefix = worksheet
        .policy
        .continuation
        .as_ref()
        .map_or(0, |continuation| continuation.prior_prefix);
    let mut physical_checkpoints = 0_usize;
    for candidate in &worksheet.candidates {
        if candidate.candidate.rank <= inherited_prefix {
            if let Some(selected) = &candidate.selected_repository {
                let checkout = checkout_path(checkout_root, &candidate.candidate.repository)?;
                verify_retained_checkout(&checkout, &selected.revision)?;
            }
            completed.push(candidate.clone());
            continue;
        }
        let path = checkpoint_path(checkpoint_root, candidate.candidate.rank);
        if !path.exists() {
            break;
        }
        physical_checkpoints += 1;
        let checkpoint: SourceAssessmentCheckpoint = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("failed to read source checkpoint: {error}"))?,
        )
        .map_err(|error| format!("invalid source checkpoint {}: {error}", path.display()))?;
        if checkpoint.schema_version != SOURCE_ASSESSMENT_STATE_SCHEMA_VERSION
            || checkpoint.task_sha256 != worksheet.task_sha256
            || checkpoint.assessment.candidate != candidate.candidate
        {
            return Err(format!(
                "source checkpoint changed immutable rank {}",
                candidate.candidate.rank
            ));
        }
        if let Some(selected) = &checkpoint.assessment.selected_repository {
            let checkout = checkout_path(checkout_root, &candidate.candidate.repository)?;
            let worktree = work_root.join(format!("rank-{:04}", candidate.candidate.rank));
            if !checkout.exists() && worktree.is_dir() {
                verify_retained_checkout(&worktree, &selected.revision)?;
                if let Some(parent) = checkout.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|error| format!("failed to recover checkout parent: {error}"))?;
                }
                fs::rename(&worktree, &checkout)
                    .map_err(|error| format!("failed to recover selected checkout: {error}"))?;
            }
            verify_retained_checkout(&checkout, &selected.revision)?;
        }
        completed.push(checkpoint.assessment);
    }
    let unexpected = fs::read_dir(checkpoint_root)
        .map_err(|error| format!("failed to inspect source checkpoints: {error}"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .count();
    if unexpected != physical_checkpoints {
        return Err(
            "source-assessment checkpoints are not one contiguous ranked prefix".to_string(),
        );
    }
    Ok(completed)
}

pub(super) fn write_checkpoint(
    root: &Path,
    task_sha256: &str,
    assessment: &SourceCandidateAssessment,
) -> Result<(), String> {
    let checkpoint = SourceAssessmentCheckpoint {
        schema_version: SOURCE_ASSESSMENT_STATE_SCHEMA_VERSION,
        task_sha256: task_sha256.to_string(),
        assessment: assessment.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&checkpoint)
        .map_err(|error| format!("failed to serialize source checkpoint: {error}"))?;
    let path = checkpoint_path(root, assessment.candidate.rank);
    if path.exists() {
        return Err(format!(
            "source checkpoint already exists: {}",
            path.display()
        ));
    }
    let temporary = root.join(format!(
        "rank-{:04}.json.tmp-{}",
        assessment.candidate.rank,
        std::process::id()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            format!(
                "failed to create temporary source checkpoint {}: {error}",
                temporary.display()
            )
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to persist source checkpoint: {error}"))?;
    drop(file);
    fs::rename(&temporary, &path)
        .map_err(|error| format!("failed to publish source checkpoint: {error}"))
}

pub(super) fn remove_generated_worktree(path: &Path, root: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "source-assessment worktree has no parent".to_string())?;
    if parent != root
        || !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("rank-"))
    {
        return Err(format!(
            "refusing to remove unexpected source-assessment path: {}",
            path.display()
        ));
    }
    fs::remove_dir_all(path)
        .map_err(|error| format!("failed to remove generated source worktree: {error}"))
}

pub(super) fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("source assessment requires git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed for {}: {}",
            args.join(" "),
            root.display(),
            bounded(&String::from_utf8_lossy(&output.stderr), 1024)
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "git output is not UTF-8".to_string())
}

pub(super) fn git_optional(root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("source assessment requires git: {error}"))?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|_| "git output is not UTF-8".to_string())
    } else {
        Ok(None)
    }
}

fn verify_retained_checkout(root: &Path, revision: &str) -> Result<(), String> {
    let promisor = git_optional(
        root,
        &["config", "--get-regexp", "^remote\\..*\\.promisor$"],
    )?
    .unwrap_or_default();
    if !root.is_dir()
        || !git(root, &["rev-parse", "HEAD"])?
            .trim()
            .eq_ignore_ascii_case(revision)
        || !git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?
            .trim()
            .is_empty()
        || !promisor.trim().is_empty()
    {
        return Err(format!(
            "selected checkout is missing, partial, dirty, or changed: {}",
            root.display()
        ));
    }
    Ok(())
}

fn remove_checkpoint_temps(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect source checkpoints: {error}"))?
    {
        let path = entry
            .map_err(|error| format!("failed to inspect source checkpoint entry: {error}"))?
            .path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("rank-") && name.contains(".json.tmp-") && path.is_file() {
            fs::remove_file(&path)
                .map_err(|error| format!("failed to remove stale checkpoint temp: {error}"))?;
        }
    }
    Ok(())
}

fn checkpoint_path(root: &Path, rank: usize) -> PathBuf {
    root.join(format!("rank-{rank:04}.json"))
}

fn bounded(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}
