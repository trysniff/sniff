use super::super::IntentionalBoundaryProjectModelFailurePhase;
use super::super::intentional_boundary_project_model::hash_json;
use super::super::intentional_boundary_project_model_outcome::{
    ProjectModelDerivationError, ProjectModelDerivationErrorKind, project_model_error,
    project_model_process_error, project_model_runtime_plan_error, project_model_sandbox_error,
};
use super::super::non_blind_history_runtime::{HistoricalRuntimePlan, prepare_historical_runtime};
use super::Provider;
use std::path::Path;
use std::time::Duration;

const GO_COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const GO_COMMAND_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;
const GO_DEPENDENCY_PREPARATION_ATTEMPTS: usize = 3;
const GO_DEPENDENCY_RETRY_DELAYS: [Duration; GO_DEPENDENCY_PREPARATION_ATTEMPTS - 1] =
    [Duration::from_secs(2), Duration::from_secs(8)];
const GO_DEPENDENCY_PREPARATION_CONTRACT: &str = "sniff-go-project-model-dependency-preparation-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GoCommandNetworkPolicy {
    DependencyPreparation,
    OfflineModel,
}

pub(super) fn prepare_go_dependency_cache(
    root: &Path,
    cache: &Path,
    manifest_repository_path: &str,
    module_directory: &str,
) -> Result<String, ProjectModelDerivationError> {
    let logical_command = vec![
        "go".to_string(),
        "-C".to_string(),
        module_directory.to_string(),
        "mod".to_string(),
        "download".to_string(),
    ];
    for attempt in 1..=GO_DEPENDENCY_PREPARATION_ATTEMPTS {
        let plan = prepare_go_command_plan(
            root,
            cache,
            manifest_repository_path,
            &logical_command,
            &[],
            GoCommandNetworkPolicy::DependencyPreparation,
            "Go dependency-preparation runtime",
        )?;
        let runtime_identity = plan.runtime_identity.clone();
        let output = crate::sandbox::run(&plan.command).map_err(|error| {
            project_model_sandbox_error(
                Provider::GoList,
                manifest_repository_path,
                "sandboxed Go dependency preparation failed",
                error,
            )
        })?;
        if output.status_code == Some(0) && !output.timed_out {
            return hash_json(&(GO_DEPENDENCY_PREPARATION_CONTRACT, runtime_identity)).map_err(
                |detail| {
                    project_model_error(
                        ProjectModelDerivationErrorKind::InfrastructureFailed,
                        Provider::GoList,
                        IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
                        Some(manifest_repository_path),
                        detail,
                    )
                },
            );
        }
        if let Some(delay) = retry_delay(&output, attempt) {
            std::thread::sleep(delay);
            continue;
        }
        return Err(preparation_failure(
            manifest_repository_path,
            attempt,
            output,
        ));
    }
    unreachable!("the bounded Go dependency preparation loop always returns")
}

pub(super) fn prepare_go_command_plan(
    root: &Path,
    cache: &Path,
    manifest_repository_path: &str,
    logical_command: &[String],
    explicit_context: &[(String, String)],
    network_policy: GoCommandNetworkPolicy,
    runtime_label: &str,
) -> Result<HistoricalRuntimePlan, ProjectModelDerivationError> {
    let mut plan = prepare_historical_runtime(root, cache, logical_command).map_err(|error| {
        project_model_runtime_plan_error(
            Provider::GoList,
            manifest_repository_path,
            runtime_label,
            error,
        )
    })?;
    plan.command.env.extend([
        ("GOENV".to_string(), "off".to_string()),
        ("GOFLAGS".to_string(), String::new()),
        ("GOTOOLCHAIN".to_string(), "local".to_string()),
        ("GOWORK".to_string(), "off".to_string()),
    ]);
    if network_policy == GoCommandNetworkPolicy::OfflineModel {
        plan.command.env.extend([
            ("GOPROXY".to_string(), "off".to_string()),
            ("GOSUMDB".to_string(), "off".to_string()),
        ]);
    }
    plan.command.env.extend(explicit_context.iter().cloned());
    plan.command.env.sort_by(|left, right| left.0.cmp(&right.0));
    if plan
        .command
        .env
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(project_model_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            Provider::GoList,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(manifest_repository_path),
            "Go project-model runtime environment contains duplicate names",
        ));
    }
    plan.command.allow_network = network_policy == GoCommandNetworkPolicy::DependencyPreparation;
    #[cfg(target_os = "macos")]
    {
        plan.command.allow_local_network =
            network_policy == GoCommandNetworkPolicy::DependencyPreparation;
    }
    plan.command.timeout = GO_COMMAND_TIMEOUT;
    plan.command.output_limit = GO_COMMAND_OUTPUT_LIMIT;
    Ok(plan)
}

fn retry_delay(output: &crate::sandbox::SandboxOutput, attempt: usize) -> Option<Duration> {
    has_transient_transport_failure(output)
        .then(|| attempt.checked_sub(1))
        .flatten()
        .and_then(|index| GO_DEPENDENCY_RETRY_DELAYS.get(index))
        .copied()
}

fn has_transient_transport_failure(output: &crate::sandbox::SandboxOutput) -> bool {
    if output.timed_out
        || output.memory_limit_exceeded
        || output.process_limit_exceeded
        || output.status_code.is_none()
    {
        return false;
    }
    let evidence = format!("{}\n{}", output.stdout, output.stderr).to_ascii_lowercase();
    const EVIDENCE: &[&str] = &[
        "connection reset by peer",
        "connection refused",
        "connection timed out",
        "context deadline exceeded",
        "http2: server sent goaway",
        "i/o timeout",
        "internal_error; received from peer",
        "network is unreachable",
        "no such host",
        "proxyconnect tcp",
        "server misbehaving",
        "status code 429",
        "status code 500",
        "status code 502",
        "status code 503",
        "status code 504",
        "stream error:",
        "temporary failure in name resolution",
        "tls handshake timeout",
        "unexpected eof",
    ];
    EVIDENCE.iter().any(|needle| evidence.contains(needle))
}

fn preparation_failure(
    manifest_repository_path: &str,
    attempt: usize,
    output: crate::sandbox::SandboxOutput,
) -> ProjectModelDerivationError {
    let stderr = output.stderr.trim();
    let detail = if output.timed_out {
        "sandboxed Go dependency preparation timed out".to_string()
    } else {
        format!(
            "sandboxed Go dependency preparation exited with status {}{}{}",
            output
                .status_code
                .map_or_else(|| "unknown".to_string(), |status| status.to_string()),
            if stderr.is_empty() { "" } else { ": " },
            stderr,
        )
    };
    let kind = if output.timed_out || output.status_code.is_some() {
        // Registry-backed preparation cannot attribute a nonzero result to the
        // repository without typed registry evidence.
        ProjectModelDerivationErrorKind::InfrastructureUnavailable
    } else {
        ProjectModelDerivationErrorKind::InfrastructureFailed
    };
    project_model_process_error(
        kind,
        Provider::GoList,
        IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
        manifest_repository_path,
        if attempt > 1 {
            format!("{detail} after {attempt} bounded attempts")
        } else {
            detail
        },
        output,
    )
}
