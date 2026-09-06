use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SNAPSHOT_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
static RUNTIME_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) struct IntentionalBoundaryRuntimeSnapshot {
    allocation_root: PathBuf,
    checkout_root: PathBuf,
}

impl IntentionalBoundaryRuntimeSnapshot {
    pub(super) fn create(source_root: &Path, revision: &str, label: &str) -> Result<Self, String> {
        let allocation_root = allocate_runtime_directory(&std::env::temp_dir(), label)?;
        let checkout_root = allocation_root.join("checkout");
        let hooks = allocation_root.join("empty-hooks");
        let global_config = allocation_root.join("gitconfig");
        fs::create_dir(&hooks)
            .map_err(|error| format!("failed to create empty Git hooks directory: {error}"))?;
        fs::write(&global_config, b"")
            .map_err(|error| format!("failed to create empty Git configuration: {error}"))?;

        let clone = run_snapshot_git(
            &allocation_root,
            &hooks,
            &global_config,
            [
                "clone".into(),
                "--shared".into(),
                "--no-checkout".into(),
                "--no-tags".into(),
                source_root.as_os_str().to_owned(),
                checkout_root.as_os_str().to_owned(),
            ],
        );
        if let Err(error) = clone {
            let _ = fs::remove_dir_all(&allocation_root);
            return Err(error);
        }
        let checkout = run_snapshot_git(
            &checkout_root,
            &hooks,
            &global_config,
            [
                "checkout".into(),
                "--force".into(),
                "--detach".into(),
                revision.into(),
            ],
        );
        if let Err(error) = checkout {
            let _ = fs::remove_dir_all(&allocation_root);
            return Err(error);
        }
        Ok(Self {
            allocation_root,
            checkout_root,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.checkout_root
    }

    pub(super) fn sandbox_root(&self) -> &Path {
        &self.allocation_root
    }
}

impl Drop for IntentionalBoundaryRuntimeSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.allocation_root);
    }
}

pub(super) fn allocate_runtime_directory(parent: &Path, label: &str) -> Result<PathBuf, String> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("intentional-boundary runtime label is not a safe path component".to_string());
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            format!("system clock cannot allocate intentional-boundary runtime: {error}")
        })?
        .as_nanos();
    for _ in 0..128 {
        let sequence = RUNTIME_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "{label}-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "failed to create intentional-boundary runtime: {error}"
                ));
            }
        }
    }
    Err("failed to allocate a unique intentional-boundary runtime".to_string())
}

fn run_snapshot_git(
    workdir: &Path,
    hooks: &Path,
    global_config: &Path,
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<(), String> {
    let mut command = Command::new("git");
    command
        .current_dir(workdir)
        .arg("-c")
        .arg(format!("core.hooksPath={}", hooks.display()))
        .args(args)
        .env("GIT_CONFIG_GLOBAL", global_config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "Never");
    let output = crate::bounded_process::run_with_output_limit(
        &mut command,
        SNAPSHOT_TIMEOUT,
        SNAPSHOT_OUTPUT_LIMIT,
    )
    .map_err(|error| {
        format!("failed to materialize intentional-boundary runtime snapshot: {error}")
    })?;
    if output.timed_out {
        return Err("intentional-boundary runtime snapshot materialization timed out".to_string());
    }
    if output.stdout_truncated || output.stderr_truncated {
        return Err(
            "intentional-boundary runtime snapshot Git output exceeded its limit".to_string(),
        );
    }
    if !output.status.success() {
        return Err(format!(
            "intentional-boundary runtime snapshot Git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn snapshot_is_exact_and_disposable() {
        let source = tempfile::tempdir().unwrap();
        git(source.path(), &["init", "--quiet"]);
        git(source.path(), &["config", "user.name", "SniffBench"]);
        git(
            source.path(),
            &["config", "user.email", "bench@example.invalid"],
        );
        fs::write(source.path().join("tracked.txt"), "original\n").unwrap();
        git(source.path(), &["add", "."]);
        git(source.path(), &["commit", "--quiet", "-m", "fixture"]);
        let revision = git(source.path(), &["rev-parse", "HEAD"]);

        let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
            source.path(),
            &revision,
            "sniff-runtime-snapshot-test",
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(snapshot.path().join("tracked.txt")).unwrap(),
            "original\n"
        );
        fs::write(snapshot.path().join("tracked.txt"), "changed\n").unwrap();
        assert_eq!(
            fs::read_to_string(source.path().join("tracked.txt")).unwrap(),
            "original\n"
        );
    }

    #[test]
    fn runtime_label_must_be_a_single_safe_component() {
        let error = allocate_runtime_directory(&std::env::temp_dir(), "../escape").unwrap_err();
        assert!(error.contains("safe path component"));
    }
}
