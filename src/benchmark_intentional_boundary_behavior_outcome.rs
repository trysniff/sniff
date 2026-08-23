use super::{IntentionalBoundaryBehaviorExecution, IntentionalBoundaryBehaviorWitnessOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BehaviorDerivationErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BehaviorDerivationError {
    pub kind: BehaviorDerivationErrorKind,
    pub detail: String,
}

pub(super) fn behavior_invalid(detail: impl Into<String>) -> BehaviorDerivationError {
    BehaviorDerivationError {
        kind: BehaviorDerivationErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

pub(super) fn behavior_unavailable(detail: impl Into<String>) -> BehaviorDerivationError {
    BehaviorDerivationError {
        kind: BehaviorDerivationErrorKind::InfrastructureUnavailable,
        detail: detail.into(),
    }
}

pub(super) fn behavior_failed(detail: impl Into<String>) -> BehaviorDerivationError {
    BehaviorDerivationError {
        kind: BehaviorDerivationErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

pub(super) fn legacy_behavior_error(error: BehaviorDerivationError) -> String {
    error.detail
}

#[derive(Clone)]
pub(super) struct BehaviorExecutionAttempt {
    pub execution: Option<IntentionalBoundaryBehaviorExecution>,
    pub outcome: IntentionalBoundaryBehaviorWitnessOutcome,
}
