use super::non_blind_history_runtime::HistoricalRuntimePlanError;
use super::{IntentionalBoundaryProjectModelFailurePhase, IntentionalBoundaryProjectModelProvider};
use crate::sandbox::{SandboxError, SandboxOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectModelDerivationErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
    UnsupportedProjectShape,
    ProviderRejectedRepository,
    ProviderOutputIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectModelProcessOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub timed_out: bool,
}

impl From<SandboxOutput> for ProjectModelProcessOutput {
    fn from(output: SandboxOutput) -> Self {
        Self {
            status_code: output.status_code,
            stdout: output.stdout,
            stderr: output.stderr,
            stdout_sha256: output.stdout_sha256,
            stderr_sha256: output.stderr_sha256,
            timed_out: output.timed_out,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectModelDerivationError {
    pub kind: ProjectModelDerivationErrorKind,
    pub provider: IntentionalBoundaryProjectModelProvider,
    pub phase: IntentionalBoundaryProjectModelFailurePhase,
    pub invocation_anchor_repository_path: Option<String>,
    pub detail: String,
    pub process: Option<Box<ProjectModelProcessOutput>>,
}

pub(super) fn project_model_error(
    kind: ProjectModelDerivationErrorKind,
    provider: IntentionalBoundaryProjectModelProvider,
    phase: IntentionalBoundaryProjectModelFailurePhase,
    invocation_anchor_repository_path: Option<&str>,
    detail: impl Into<String>,
) -> ProjectModelDerivationError {
    ProjectModelDerivationError {
        kind,
        provider,
        phase,
        invocation_anchor_repository_path: invocation_anchor_repository_path.map(str::to_string),
        detail: detail.into(),
        process: None,
    }
}

pub(super) fn project_model_process_error(
    kind: ProjectModelDerivationErrorKind,
    provider: IntentionalBoundaryProjectModelProvider,
    phase: IntentionalBoundaryProjectModelFailurePhase,
    invocation_anchor_repository_path: &str,
    detail: impl Into<String>,
    process: SandboxOutput,
) -> ProjectModelDerivationError {
    ProjectModelDerivationError {
        kind,
        provider,
        phase,
        invocation_anchor_repository_path: Some(invocation_anchor_repository_path.to_string()),
        detail: detail.into(),
        process: Some(Box::new(process.into())),
    }
}

pub(super) fn legacy_project_model_error(error: ProjectModelDerivationError) -> String {
    error.detail
}

pub(super) fn project_model_runtime_plan_error(
    provider: IntentionalBoundaryProjectModelProvider,
    invocation_anchor_repository_path: &str,
    label: &str,
    error: HistoricalRuntimePlanError,
) -> ProjectModelDerivationError {
    let (kind, state, detail) = match error {
        HistoricalRuntimePlanError::Unavailable(detail) => (
            ProjectModelDerivationErrorKind::InfrastructureUnavailable,
            "unavailable",
            detail,
        ),
        HistoricalRuntimePlanError::Invalid(detail) => (
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            "invalid",
            detail,
        ),
    };
    project_model_error(
        kind,
        provider,
        IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
        Some(invocation_anchor_repository_path),
        format!("{label} is {state}: {detail}"),
    )
}

pub(super) fn project_model_sandbox_error(
    provider: IntentionalBoundaryProjectModelProvider,
    invocation_anchor_repository_path: &str,
    label: &str,
    error: SandboxError,
) -> ProjectModelDerivationError {
    let (kind, detail) = match error {
        SandboxError::Unavailable(detail) => (
            ProjectModelDerivationErrorKind::InfrastructureUnavailable,
            detail,
        ),
        SandboxError::Invalid(detail) | SandboxError::Failed(detail) => (
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            detail,
        ),
    };
    project_model_error(
        kind,
        provider,
        IntentionalBoundaryProjectModelFailurePhase::Execution,
        Some(invocation_anchor_repository_path),
        format!("{label}: {detail}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_and_sandbox_errors_map_by_type_not_detail() {
        let provider = IntentionalBoundaryProjectModelProvider::CargoMetadata;
        for (source, expected) in [
            (
                HistoricalRuntimePlanError::Unavailable("same".to_string()),
                ProjectModelDerivationErrorKind::InfrastructureUnavailable,
            ),
            (
                HistoricalRuntimePlanError::Invalid("same".to_string()),
                ProjectModelDerivationErrorKind::InfrastructureFailed,
            ),
        ] {
            assert_eq!(
                project_model_runtime_plan_error(provider, "Cargo.toml", "runtime", source).kind,
                expected
            );
        }
        for (source, expected) in [
            (
                SandboxError::Unavailable("same".to_string()),
                ProjectModelDerivationErrorKind::InfrastructureUnavailable,
            ),
            (
                SandboxError::Invalid("same".to_string()),
                ProjectModelDerivationErrorKind::InfrastructureFailed,
            ),
            (
                SandboxError::Failed("same".to_string()),
                ProjectModelDerivationErrorKind::InfrastructureFailed,
            ),
        ] {
            assert_eq!(
                project_model_sandbox_error(provider, "Cargo.toml", "sandbox", source).kind,
                expected
            );
        }
    }
}
