use super::{ExpectedOutput, GeneratorCommand, ReplayFailure, ReplaySuccess, sha256};
use crate::benchmark::release::intentional_boundary_runtime_snapshot::IntentionalBoundaryRuntimeSnapshot;
use crate::benchmark::release::non_blind_history_runtime::{
    HistoricalRuntimePlanError, prepare_historical_runtime,
};
use crate::benchmark::release::{
    IntentionalBoundaryGeneratorExecution, IntentionalBoundaryGeneratorOutput,
    IntentionalBoundaryGeneratorUnresolvedReason,
};
use crate::sandbox::SandboxError;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const CACHE_DIRECTORY: &str = ".sniff-boundary-generator-runtime";
const GIT_TIMEOUT: Duration = Duration::from_secs(60);
const GIT_OUTPUT_LIMIT: usize = 1024 * 1024;
const GENERATOR_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PREPARATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub(super) fn execute_generator_replay(
    source_root: &Path,
    revision: &str,
    command: &GeneratorCommand,
    expected: &[ExpectedOutput],
) -> Result<ReplaySuccess, ReplayFailure> {
    let mut preparations = Vec::new();
    let mut executions = Vec::new();
    let mut run_hashes = Vec::new();
    for run_number in 1..=2 {
        let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
            source_root,
            revision,
            "sniff-boundary-generator",
        )
        .map_err(failed)?;
        invalidate_expected_outputs(snapshot.path(), expected)?;
        let cache = snapshot.path().join(CACHE_DIRECTORY);
        fs::create_dir(&cache)
            .map_err(|error| failed(format!("failed to create generator cache: {error}")))?;
        if let Some(preparation) = &command.preparation {
            let mut plan = prepare_historical_runtime(snapshot.path(), &cache, preparation)
                .map_err(runtime_plan_failure)?;
            extend_environment(&mut plan.command.env, &command.preparation_environment)?;
            plan.command.timeout = PREPARATION_TIMEOUT;
            let output = crate::sandbox::run(&plan.command).map_err(sandbox_failure)?;
            if output.timed_out || output.status_code != Some(0) {
                let stderr = sanitized_runtime_stderr(&output.stderr, snapshot.path(), &cache);
                #[cfg(windows)]
                if windows_python_child_launch_denied(preparation, &stderr) {
                    return Err(ReplayFailure {
                        reason: IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
                        detail: "Windows AppContainer denied uv's Python interpreter child; generator replay requires a supported Linux or macOS proof host"
                            .to_string(),
                    });
                }
                return Err(failed(format!(
                    "generator dependency preparation failed: status={:?}, timed_out={}: {}",
                    output.status_code,
                    output.timed_out,
                    stderr.trim()
                )));
            }
            preparations.push(IntentionalBoundaryGeneratorExecution {
                run_number,
                command: preparation.clone(),
                environment: command.preparation_environment.clone(),
                runtime_identity_sha256: sha256(plan.runtime_identity.as_bytes()),
                status_code: 0,
                timed_out: false,
                network_enabled: true,
                stdout_sha256: output.stdout_sha256,
                stderr_sha256: output.stderr_sha256,
            });
            if is_gradle_execution(&command.execution) {
                cleanup_declared_paths(snapshot.path(), &command.cleanup_paths)?;
            }
            invalidate_expected_outputs(snapshot.path(), expected)?;
        }
        let mut plan = prepare_historical_runtime(snapshot.path(), &cache, &command.execution)
            .map_err(runtime_plan_failure)?;
        extend_environment(&mut plan.command.env, &command.execution_environment)?;
        plan.command.allow_network = false;
        plan.command.timeout = GENERATOR_TIMEOUT;
        #[cfg(target_os = "macos")]
        {
            // Gradle's mandatory single-use daemon uses loopback IPC even with
            // --no-daemon. Seatbelt still denies every non-loopback endpoint.
            plan.command.allow_local_network = is_gradle_execution(&command.execution);
        }
        let output = crate::sandbox::run(&plan.command).map_err(sandbox_failure);
        let cleanup = cleanup_runtime_paths(snapshot.path(), &cache, &command.cleanup_paths);
        let output = output?;
        cleanup?;
        #[cfg(windows)]
        if windows_cargo_child_launch_denied(&output.stderr) {
            return Err(ReplayFailure {
                reason: IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
                detail: "Windows AppContainer denied Cargo's compiler child; generator replay requires a supported Linux proof host"
                    .to_string(),
                });
        }
        #[cfg(windows)]
        if windows_go_child_launch_denied(&command.execution, &output.stderr) {
            return Err(ReplayFailure {
                reason: IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
                detail: "Windows AppContainer denied a Go toolchain child; generator replay requires a supported Linux or macOS proof host"
                    .to_string(),
            });
        }
        if output.timed_out || output.status_code != Some(0) {
            let stderr = sanitized_runtime_stderr(&output.stderr, snapshot.path(), &cache);
            return Err(ReplayFailure {
                reason: IntentionalBoundaryGeneratorUnresolvedReason::ExecutionFailed,
                detail: format!(
                    "generator command failed: status={:?}, timed_out={}: {}",
                    output.status_code,
                    output.timed_out,
                    stderr.trim()
                ),
            });
        }
        let hashes = verify_outputs(snapshot.path(), expected)?;
        verify_clean_snapshot(snapshot.path())?;
        executions.push(IntentionalBoundaryGeneratorExecution {
            run_number,
            command: command.execution.clone(),
            environment: command.execution_environment.clone(),
            runtime_identity_sha256: sha256(plan.runtime_identity.as_bytes()),
            status_code: 0,
            timed_out: false,
            network_enabled: false,
            stdout_sha256: output.stdout_sha256,
            stderr_sha256: output.stderr_sha256,
        });
        run_hashes.push(hashes);
    }
    let outputs = expected
        .iter()
        .enumerate()
        .map(|(index, output)| IntentionalBoundaryGeneratorOutput {
            repository_path: output.repository_path.clone(),
            object_id: output.object_id.clone(),
            byte_length: output.byte_length,
            committed_sha256: output.committed_sha256.clone(),
            first_run_sha256: run_hashes[0][index].clone(),
            second_run_sha256: run_hashes[1][index].clone(),
        })
        .collect();
    Ok(ReplaySuccess {
        outputs,
        preparations,
        executions,
    })
}

fn is_gradle_execution(command: &[String]) -> bool {
    command.first().map(String::as_str) == Some("{sniff_gradle}")
}

fn extend_environment(
    environment: &mut Vec<(String, String)>,
    additions: &std::collections::BTreeMap<String, String>,
) -> Result<(), ReplayFailure> {
    environment.extend(
        additions
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    environment.sort_by(|left, right| left.0.cmp(&right.0));
    if environment.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(failed(
            "generator command environment overrides a private runtime variable",
        ));
    }
    Ok(())
}

fn invalidate_expected_outputs(
    root: &Path,
    expected: &[ExpectedOutput],
) -> Result<(), ReplayFailure> {
    for output in expected {
        match fs::remove_file(root.join(&output.repository_path)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(failed(format!(
                    "failed to invalidate generated output {}: {error}",
                    output.repository_path
                )));
            }
        }
    }
    Ok(())
}

fn sanitized_runtime_stderr(stderr: &str, repository: &Path, cache: &Path) -> String {
    stderr
        .replace(&cache.to_string_lossy().to_string(), "<cache>")
        .replace(&repository.to_string_lossy().to_string(), "<repository>")
}

fn cleanup_runtime_paths(
    root: &Path,
    cache: &Path,
    cleanup_paths: &[String],
) -> Result<(), ReplayFailure> {
    cleanup_declared_paths(root, cleanup_paths)?;
    fs::remove_dir_all(cache)
        .map_err(|error| failed(format!("failed to remove generator cache: {error}")))
}

fn cleanup_declared_paths(root: &Path, cleanup_paths: &[String]) -> Result<(), ReplayFailure> {
    for relative in cleanup_paths {
        let path = root.join(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(failed(format!(
                    "failed to inspect generator runtime path {relative}: {error}"
                )));
            }
        };
        let result = if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        if let Err(error) = result {
            return Err(failed(format!(
                "failed to remove generator runtime path {relative}: {error}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn gradle_interphase_cleanup_preserves_the_private_dependency_cache() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join(CACHE_DIRECTORY);
        let output = root.path().join("build/generated/state.txt");
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir_all(output.parent().unwrap()).unwrap();
        fs::write(cache.join("dependency"), "cached").unwrap();
        fs::write(&output, "prepared").unwrap();

        assert!(cleanup_declared_paths(root.path(), &["build/generated".to_string()]).is_ok());

        assert!(!output.exists());
        assert_eq!(
            fs::read_to_string(cache.join("dependency")).unwrap(),
            "cached"
        );
    }
}

#[cfg(windows)]
fn windows_cargo_child_launch_denied(stderr: &str) -> bool {
    stderr.contains("could not execute process")
        && stderr.contains("never executed")
        && stderr.contains("Access is denied. (os error 5)")
}

#[cfg(windows)]
fn windows_python_child_launch_denied(command: &[String], stderr: &str) -> bool {
    command.first().is_some_and(|program| program == "uv")
        && stderr.contains("Failed to query Python interpreter")
        && stderr.contains("Access is denied. (os error 5)")
}

#[cfg(windows)]
fn windows_go_child_launch_denied(command: &[String], stderr: &str) -> bool {
    command.first().is_some_and(|program| program == "go")
        && stderr.contains("Access is denied")
        && (stderr.contains("fork/exec")
            || stderr.contains("CreateProcess")
            || stderr.contains("could not execute"))
}

fn verify_outputs(root: &Path, expected: &[ExpectedOutput]) -> Result<Vec<String>, ReplayFailure> {
    expected
        .iter()
        .map(|output| {
            let bytes =
                fs::read(root.join(&output.repository_path)).map_err(|error| ReplayFailure {
                    reason: IntentionalBoundaryGeneratorUnresolvedReason::OutputMissing,
                    detail: format!(
                        "generator did not recreate {}: {error}",
                        output.repository_path
                    ),
                })?;
            let actual = sha256(&bytes);
            if bytes.len() as u64 != output.byte_length || actual != output.committed_sha256 {
                return Err(ReplayFailure {
                    reason: IntentionalBoundaryGeneratorUnresolvedReason::OutputChanged,
                    detail: format!(
                        "generator output differs from committed bytes: {}",
                        output.repository_path
                    ),
                });
            }
            Ok(actual)
        })
        .collect()
}

fn verify_clean_snapshot(root: &Path) -> Result<(), ReplayFailure> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain=v1", "--untracked-files=all"]);
    let output =
        crate::bounded_process::run_with_output_limit(&mut command, GIT_TIMEOUT, GIT_OUTPUT_LIMIT)
            .map_err(|error| failed(format!("failed to verify generator snapshot: {error}")))?;
    if output.timed_out
        || output.stdout_truncated
        || output.stderr_truncated
        || !output.status.success()
    {
        return Err(failed("generator snapshot verification failed"));
    }
    if !output.stdout.is_empty() {
        return Err(ReplayFailure {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::RepositoryMutation,
            detail: format!(
                "generator changed repository paths after replay: {}",
                bounded_status_summary(&output.stdout)
            ),
        });
    }
    Ok(())
}

fn bounded_status_summary(status: &[u8]) -> String {
    let status = String::from_utf8_lossy(status);
    let entries = status
        .lines()
        .take(8)
        .map(|line| {
            line.chars()
                .flat_map(char::escape_default)
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        "<non-text status output>".to_string()
    } else {
        entries.join("; ")
    }
}

fn runtime_plan_failure(error: HistoricalRuntimePlanError) -> ReplayFailure {
    match error {
        HistoricalRuntimePlanError::Unavailable(detail) => ReplayFailure {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::RuntimeUnavailable,
            detail,
        },
        HistoricalRuntimePlanError::Invalid(detail) => failed(detail),
    }
}

fn sandbox_failure(error: SandboxError) -> ReplayFailure {
    match error {
        SandboxError::Unavailable(detail) => ReplayFailure {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
            detail,
        },
        #[cfg(windows)]
        SandboxError::Failed(detail)
            if detail.starts_with("grant Windows AppContainer access to ") =>
        {
            ReplayFailure {
                reason: IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
                detail,
            }
        }
        SandboxError::Invalid(detail) | SandboxError::Failed(detail) => failed(detail),
    }
}

fn failed(detail: impl Into<String>) -> ReplayFailure {
    ReplayFailure {
        reason: IntentionalBoundaryGeneratorUnresolvedReason::ExecutionFailed,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded_status_summary, is_gradle_execution, sanitized_runtime_stderr};

    #[test]
    fn loopback_exception_is_identified_only_for_the_pinned_gradle_adapter() {
        assert!(is_gradle_execution(&["{sniff_gradle}".to_string()]));
        assert!(!is_gradle_execution(&["gradle".to_string()]));
        assert!(!is_gradle_execution(&["cargo".to_string()]));
        assert!(!is_gradle_execution(&[]));
    }

    #[test]
    fn repository_mutation_summary_is_bounded_and_escaped() {
        let status = (0..10)
            .map(|index| format!("?? path-{index}\\t.rs"))
            .collect::<Vec<_>>()
            .join("\n");

        let summary = bounded_status_summary(status.as_bytes());

        assert_eq!(summary.matches("?? path-").count(), 8);
        assert!(summary.contains("path-0\\\\t.rs"));
        assert!(!summary.contains("path-8"));
    }

    #[test]
    fn runtime_failure_stderr_redacts_snapshot_and_cache_paths() {
        let root = std::path::Path::new("/private/sniff/repository");
        let cache = root.join(".sniff-boundary-generator-runtime");
        let stderr = format!("failed in {} using {}", root.display(), cache.display());

        let sanitized = sanitized_runtime_stderr(&stderr, root, &cache);

        assert_eq!(sanitized, "failed in <repository> using <cache>");
        assert!(!sanitized.contains("/private/sniff"));
    }
}
