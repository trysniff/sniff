use super::{PinnedIndexer, SemanticIndexerKind};
use crate::semantic_index::SemanticIndex;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticIndexerRunFailureKind {
    UnsupportedProjectShape,
    RepositoryRejected,
    IncompleteOutput,
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticIndexerRunPhase {
    RepositoryValidation,
    InstallationVerification,
    Preparation,
    Execution,
    OutputValidation,
    Cleanup,
    IntegrityVerification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticIndexerProcessEvidence {
    pub(crate) status_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) stdout_sha256: String,
    pub(crate) stderr_sha256: String,
    pub(crate) timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticIndexerRunFailure {
    pub(crate) kind: SemanticIndexerRunFailureKind,
    pub(crate) phase: SemanticIndexerRunPhase,
    pub(crate) indexer: Option<SemanticIndexerKind>,
    pub(crate) detail: String,
    pub(crate) process: Option<Box<SemanticIndexerProcessEvidence>>,
}

#[derive(Debug)]
pub(crate) struct SemanticIndexerBatchOutcome {
    pub(crate) indexes: BTreeMap<SemanticIndexerKind, SemanticIndex>,
    pub(crate) failures: Vec<SemanticIndexerRunFailure>,
}

pub(super) fn failure(
    kind: SemanticIndexerRunFailureKind,
    phase: SemanticIndexerRunPhase,
    indexer: Option<SemanticIndexerKind>,
    detail: impl Into<String>,
) -> SemanticIndexerRunFailure {
    SemanticIndexerRunFailure {
        kind,
        phase,
        indexer,
        detail: detail.into(),
        process: None,
    }
}

pub(super) fn indexer_failure(
    spec: PinnedIndexer,
    kind: SemanticIndexerRunFailureKind,
    phase: SemanticIndexerRunPhase,
    detail: impl Into<String>,
) -> SemanticIndexerRunFailure {
    failure(kind, phase, Some(spec.kind), detail)
}

pub(super) fn indexer_process_failure(
    spec: PinnedIndexer,
    kind: SemanticIndexerRunFailureKind,
    phase: SemanticIndexerRunPhase,
    detail: impl Into<String>,
    output: crate::sandbox::SandboxOutput,
) -> SemanticIndexerRunFailure {
    SemanticIndexerRunFailure {
        kind,
        phase,
        indexer: Some(spec.kind),
        detail: detail.into(),
        process: Some(Box::new(process_evidence(output))),
    }
}

pub(super) fn process_evidence(
    output: crate::sandbox::SandboxOutput,
) -> SemanticIndexerProcessEvidence {
    SemanticIndexerProcessEvidence {
        status_code: output.status_code,
        stdout: output.stdout,
        stderr: output.stderr,
        stdout_sha256: output.stdout_sha256,
        stderr_sha256: output.stderr_sha256,
        timed_out: output.timed_out,
    }
}

pub(super) fn combine_typed_run_and_integrity<T>(
    run_result: Result<T, SemanticIndexerRunFailure>,
    integrity_result: Result<(), SemanticIndexerRunFailure>,
) -> Result<T, SemanticIndexerRunFailure> {
    match (run_result, integrity_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(run_error), Err(mut integrity_error)) => {
            integrity_error.detail = format!(
                "{}; additionally, {}",
                run_error.detail, integrity_error.detail
            );
            Err(integrity_error)
        }
    }
}
