use super::intentional_boundary_semantic::indexer_kind;
use super::{
    IntentionalBoundarySemanticCensusExclusionReason,
    IntentionalBoundarySemanticCensusFailureEvidence,
    IntentionalBoundarySemanticCensusFailurePhase, IntentionalBoundarySemanticCensusStageError,
    IntentionalBoundarySemanticCensusStageErrorKind, IntentionalBoundarySemanticProcessEvidence,
};
use crate::semantic_index::SemanticIndex;
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::semantic_indexer_runner::{
    SemanticIndexerBatchOutcome, SemanticIndexerProcessEvidence, SemanticIndexerRunFailure,
    SemanticIndexerRunFailureKind, SemanticIndexerRunPhase,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const RETAINED_EVIDENCE_LIMIT: usize = 4 * 1024;

pub(super) enum ResolvedSemanticRun {
    Completed(BTreeMap<SemanticIndexerKind, SemanticIndex>),
    Excluded(Vec<IntentionalBoundarySemanticCensusFailureEvidence>),
}

pub(super) fn resolve_semantic_run(
    result: Result<SemanticIndexerBatchOutcome, SemanticIndexerRunFailure>,
) -> Result<ResolvedSemanticRun, IntentionalBoundarySemanticCensusStageError> {
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(failure) => {
            return match classify_failure(failure) {
                Ok(evidence) => Ok(ResolvedSemanticRun::Excluded(vec![evidence])),
                Err(error) => Err(error),
            };
        }
    };
    let mut terminal = Vec::new();
    let mut operational = Vec::new();
    for failure in outcome.failures {
        match classify_failure(failure) {
            Ok(evidence) => terminal.push(evidence),
            Err(error) => operational.push(error),
        }
    }
    if !operational.is_empty() {
        return Err(combine_errors(operational));
    }
    if terminal.is_empty() {
        Ok(ResolvedSemanticRun::Completed(outcome.indexes))
    } else {
        terminal.sort_by(failure_key);
        Ok(ResolvedSemanticRun::Excluded(terminal))
    }
}

pub(super) fn assembly_failure(detail: String) -> IntentionalBoundarySemanticCensusFailureEvidence {
    let (retained_detail, detail_truncated) = retain(&detail);
    IntentionalBoundarySemanticCensusFailureEvidence {
        reason: IntentionalBoundarySemanticCensusExclusionReason::CompilerCensusIncomplete,
        indexer: None,
        phase: IntentionalBoundarySemanticCensusFailurePhase::CensusAssembly,
        detail_sha256: sha256(detail.as_bytes()),
        retained_detail,
        detail_truncated,
        process: None,
    }
}

fn classify_failure(
    failure: SemanticIndexerRunFailure,
) -> Result<
    IntentionalBoundarySemanticCensusFailureEvidence,
    IntentionalBoundarySemanticCensusStageError,
> {
    let reason = match failure.kind {
        SemanticIndexerRunFailureKind::UnsupportedProjectShape => {
            IntentionalBoundarySemanticCensusExclusionReason::UnsupportedProjectShape
        }
        SemanticIndexerRunFailureKind::RepositoryRejected => {
            IntentionalBoundarySemanticCensusExclusionReason::CompilerIndexerRejectedRepository
        }
        SemanticIndexerRunFailureKind::IncompleteOutput => {
            IntentionalBoundarySemanticCensusExclusionReason::CompilerCensusIncomplete
        }
        SemanticIndexerRunFailureKind::InvalidInput => {
            return Err(stage_error(
                IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput,
                failure.detail,
            ));
        }
        SemanticIndexerRunFailureKind::InfrastructureUnavailable => {
            return Err(stage_error(
                IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureUnavailable,
                failure.detail,
            ));
        }
        SemanticIndexerRunFailureKind::InfrastructureFailed => {
            return Err(stage_error(
                IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureFailed,
                failure.detail,
            ));
        }
    };
    let (retained_detail, detail_truncated) = retain(&failure.detail);
    Ok(IntentionalBoundarySemanticCensusFailureEvidence {
        reason,
        indexer: failure.indexer.map(indexer_kind),
        phase: phase(failure.phase),
        detail_sha256: sha256(failure.detail.as_bytes()),
        retained_detail,
        detail_truncated,
        process: failure.process.map(|process| process_evidence(*process)),
    })
}

fn combine_errors(
    errors: Vec<IntentionalBoundarySemanticCensusStageError>,
) -> IntentionalBoundarySemanticCensusStageError {
    let kind = if errors
        .iter()
        .any(|error| error.kind == IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput)
    {
        IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput
    } else if errors.iter().any(|error| {
        error.kind == IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureFailed
    }) {
        IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureFailed
    } else {
        IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureUnavailable
    };
    IntentionalBoundarySemanticCensusStageError {
        kind,
        detail: errors
            .into_iter()
            .map(|error| error.detail)
            .collect::<Vec<_>>()
            .join("; additionally, "),
    }
}

fn stage_error(
    kind: IntentionalBoundarySemanticCensusStageErrorKind,
    detail: String,
) -> IntentionalBoundarySemanticCensusStageError {
    IntentionalBoundarySemanticCensusStageError { kind, detail }
}

fn phase(value: SemanticIndexerRunPhase) -> IntentionalBoundarySemanticCensusFailurePhase {
    match value {
        SemanticIndexerRunPhase::RepositoryValidation => {
            IntentionalBoundarySemanticCensusFailurePhase::RepositoryValidation
        }
        SemanticIndexerRunPhase::InstallationVerification => {
            IntentionalBoundarySemanticCensusFailurePhase::InstallationVerification
        }
        SemanticIndexerRunPhase::Preparation => {
            IntentionalBoundarySemanticCensusFailurePhase::Preparation
        }
        SemanticIndexerRunPhase::Execution => {
            IntentionalBoundarySemanticCensusFailurePhase::Execution
        }
        SemanticIndexerRunPhase::OutputValidation => {
            IntentionalBoundarySemanticCensusFailurePhase::OutputValidation
        }
        SemanticIndexerRunPhase::SnapshotAssembly => {
            IntentionalBoundarySemanticCensusFailurePhase::CensusAssembly
        }
        SemanticIndexerRunPhase::Cleanup => IntentionalBoundarySemanticCensusFailurePhase::Cleanup,
        SemanticIndexerRunPhase::IntegrityVerification => {
            IntentionalBoundarySemanticCensusFailurePhase::IntegrityVerification
        }
    }
}

fn process_evidence(
    process: SemanticIndexerProcessEvidence,
) -> IntentionalBoundarySemanticProcessEvidence {
    let (retained_stdout, locally_truncated_stdout) = retain(&process.stdout);
    let (retained_stderr, locally_truncated_stderr) = retain(&process.stderr);
    IntentionalBoundarySemanticProcessEvidence {
        status_code: process.status_code,
        stdout_sha256: process.stdout_sha256.clone(),
        stderr_sha256: process.stderr_sha256.clone(),
        retained_stdout,
        retained_stderr,
        stdout_truncated: locally_truncated_stdout
            || sha256(process.stdout.as_bytes()) != process.stdout_sha256,
        stderr_truncated: locally_truncated_stderr
            || sha256(process.stderr.as_bytes()) != process.stderr_sha256,
        timed_out: process.timed_out,
    }
}

pub(super) fn failure_key(
    left: &IntentionalBoundarySemanticCensusFailureEvidence,
    right: &IntentionalBoundarySemanticCensusFailureEvidence,
) -> std::cmp::Ordering {
    (left.indexer, left.phase, left.reason, &left.detail_sha256).cmp(&(
        right.indexer,
        right.phase,
        right.reason,
        &right.detail_sha256,
    ))
}

fn retain(value: &str) -> (String, bool) {
    if value.len() <= RETAINED_EVIDENCE_LIMIT {
        return (value.to_string(), false);
    }
    let mut end = RETAINED_EVIDENCE_LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
