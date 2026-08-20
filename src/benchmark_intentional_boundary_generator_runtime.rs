use super::{ExpectedOutput, ReplayFailure, ReplaySuccess, sha256};
use crate::benchmark::release::intentional_boundary_runtime_snapshot::IntentionalBoundaryRuntimeSnapshot;
use crate::benchmark::release::non_blind_history_runtime::{
    HistoricalRuntimePlanError, prepare_historical_runtime,
};
use crate::benchmark::release::{
    IntentionalBoundaryGeneratorExecution, IntentionalBoundaryGeneratorOutput,
    IntentionalBoundaryGeneratorUnresolvedReason, IntentionalBoundaryManifestDeclaration,
};
use crate::sandbox::SandboxError;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const CACHE_DIRECTORY: &str = ".sniff-boundary-generator-runtime";
const GIT_TIMEOUT: Duration = Duration::from_secs(60);
const GIT_OUTPUT_LIMIT: usize = 1024 * 1024;

pub(super) fn execute_generator_replay(
    source_root: &Path,
    revision: &str,
    _declaration: &IntentionalBoundaryManifestDeclaration,
    command: &[String],
    expected: &[ExpectedOutput],
) -> Result<ReplaySuccess, ReplayFailure> {
    let mut executions = Vec::new();
    let mut run_hashes = Vec::new();
    for run_number in 1..=2 {
        let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
            source_root,
            revision,
            "sniff-boundary-generator",
        )
        .map_err(failed)?;
        for output in expected {
            fs::write(snapshot.path().join(&output.repository_path), []).map_err(|error| {
                failed(format!(
                    "failed to invalidate generated output {}: {error}",
                    output.repository_path
                ))
            })?;
        }
        let cache = snapshot.path().join(CACHE_DIRECTORY);
        fs::create_dir(&cache)
            .map_err(|error| failed(format!("failed to create generator cache: {error}")))?;
        let mut plan = prepare_historical_runtime(snapshot.path(), &cache, command)
            .map_err(runtime_plan_failure)?;
        plan.command.allow_network = false;
        #[cfg(target_os = "macos")]
        {
            plan.command.allow_local_network = false;
        }
        let output = crate::sandbox::run(&plan.command).map_err(sandbox_failure);
        let cleanup = fs::remove_dir_all(&cache)
            .map_err(|error| failed(format!("failed to remove generator cache: {error}")));
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
        if output.timed_out || output.status_code != Some(0) {
            let stderr = output
                .stderr
                .replace(
                    &snapshot.path().to_string_lossy().to_string(),
                    "<repository>",
                )
                .replace(&cache.to_string_lossy().to_string(), "<cache>");
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
            command: command.to_vec(),
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
        executions,
    })
}

#[cfg(windows)]
fn windows_cargo_child_launch_denied(stderr: &str) -> bool {
    stderr.contains("could not execute process")
        && stderr.contains("never executed")
        && stderr.contains("Access is denied. (os error 5)")
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
    use super::bounded_status_summary;

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
}
