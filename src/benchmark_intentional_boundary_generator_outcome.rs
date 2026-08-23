#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GeneratorDerivationErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GeneratorDerivationError {
    pub kind: GeneratorDerivationErrorKind,
    pub detail: String,
}

pub(super) fn generator_invalid(detail: impl Into<String>) -> GeneratorDerivationError {
    GeneratorDerivationError {
        kind: GeneratorDerivationErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

pub(super) fn generator_unavailable(detail: impl Into<String>) -> GeneratorDerivationError {
    GeneratorDerivationError {
        kind: GeneratorDerivationErrorKind::InfrastructureUnavailable,
        detail: detail.into(),
    }
}

pub(super) fn generator_failed(detail: impl Into<String>) -> GeneratorDerivationError {
    GeneratorDerivationError {
        kind: GeneratorDerivationErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReplayFailureKind {
    Terminal,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

pub(super) struct ReplayFailure {
    pub kind: ReplayFailureKind,
    pub reason: IntentionalBoundaryGeneratorUnresolvedReason,
    pub detail: String,
}

impl ReplayFailure {
    pub fn terminal(
        reason: IntentionalBoundaryGeneratorUnresolvedReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind: ReplayFailureKind::Terminal,
            reason,
            detail: detail.into(),
        }
    }

    pub fn unavailable(
        reason: IntentionalBoundaryGeneratorUnresolvedReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind: ReplayFailureKind::InfrastructureUnavailable,
            reason,
            detail: detail.into(),
        }
    }

    pub fn failed(detail: impl Into<String>) -> Self {
        Self {
            kind: ReplayFailureKind::InfrastructureFailed,
            reason: IntentionalBoundaryGeneratorUnresolvedReason::ExecutionFailed,
            detail: detail.into(),
        }
    }
}

pub(super) fn generator_replay_operational_error(
    configuration_id: &str,
    failure: &ReplayFailure,
) -> Option<GeneratorDerivationError> {
    let detail = || {
        format!(
            "generator configuration {configuration_id} could not be replayed: {}",
            failure.detail
        )
    };
    match failure.kind {
        ReplayFailureKind::Terminal => None,
        ReplayFailureKind::InfrastructureUnavailable => Some(generator_unavailable(detail())),
        ReplayFailureKind::InfrastructureFailed => Some(generator_failed(detail())),
    }
}
use super::IntentionalBoundaryGeneratorUnresolvedReason;
