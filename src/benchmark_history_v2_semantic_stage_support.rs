use super::*;

pub(super) fn resolve_indexer_run(
    side: HistoricalV2SemanticSnapshotSide,
    revision: &str,
    result: Result<SemanticIndexerBatchOutcome, SemanticIndexerRunFailure>,
    failures: &mut Vec<HistoricalV2SemanticCensusFailureEvidence>,
    stage_errors: &mut Vec<HistoricalV2SlotStageError>,
) -> Option<BTreeMap<SemanticIndexerKind, SemanticIndex>> {
    match result {
        Ok(outcome) if outcome.failures.is_empty() => Some(outcome.indexes),
        Ok(outcome) => {
            for failure in outcome.failures {
                match indexer_failure_evidence(side, revision, failure) {
                    Ok(evidence) => failures.push(evidence),
                    Err(error) => stage_errors.push(error),
                }
            }
            None
        }
        Err(failure) => match indexer_failure_evidence(side, revision, failure) {
            Ok(evidence) => {
                failures.push(evidence);
                None
            }
            Err(error) => {
                stage_errors.push(error);
                None
            }
        },
    }
}

pub(super) fn indexer_failure_evidence(
    side: HistoricalV2SemanticSnapshotSide,
    revision: &str,
    failure: SemanticIndexerRunFailure,
) -> Result<HistoricalV2SemanticCensusFailureEvidence, HistoricalV2SlotStageError> {
    let reason = match failure.kind {
        SemanticIndexerRunFailureKind::UnsupportedProjectShape => {
            HistoricalV2SemanticCensusExclusionReason::UnsupportedProjectShape
        }
        SemanticIndexerRunFailureKind::RepositoryRejected => {
            HistoricalV2SemanticCensusExclusionReason::CompilerIndexerRejectedRepository
        }
        SemanticIndexerRunFailureKind::IncompleteOutput => {
            HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete
        }
        SemanticIndexerRunFailureKind::InvalidInput => {
            return Err(stage_error(
                HistoricalV2SlotStageErrorKind::InvalidInput,
                side,
                failure.detail,
            ));
        }
        SemanticIndexerRunFailureKind::InfrastructureUnavailable => {
            return Err(stage_error(
                HistoricalV2SlotStageErrorKind::InfrastructureUnavailable,
                side,
                failure.detail,
            ));
        }
        SemanticIndexerRunFailureKind::InfrastructureFailed => {
            return Err(stage_error(
                HistoricalV2SlotStageErrorKind::InfrastructureFailed,
                side,
                failure.detail,
            ));
        }
    };
    let (retained_detail, detail_truncated) = retain(&failure.detail);
    Ok(HistoricalV2SemanticCensusFailureEvidence {
        side,
        revision: revision.to_string(),
        reason,
        indexer: failure.indexer.map(indexer_kind),
        phase: semantic_phase(failure.phase),
        detail_sha256: sha256(failure.detail.as_bytes()),
        retained_detail,
        detail_truncated,
        process: failure.process.map(|process| process_evidence(*process)),
    })
}

pub(super) fn resolve_snapshot_build(
    side: HistoricalV2SemanticSnapshotSide,
    revision: &str,
    result: Result<HistoricalV2SemanticSnapshotCensus, String>,
    failures: &mut Vec<HistoricalV2SemanticCensusFailureEvidence>,
) -> Option<HistoricalV2SemanticSnapshotCensus> {
    match result {
        Ok(snapshot) => Some(snapshot),
        Err(detail) => {
            let (retained_detail, detail_truncated) = retain(&detail);
            failures.push(HistoricalV2SemanticCensusFailureEvidence {
                side,
                revision: revision.to_string(),
                reason: HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete,
                indexer: None,
                phase: HistoricalV2SemanticCensusFailurePhase::SnapshotAssembly,
                detail_sha256: sha256(detail.as_bytes()),
                retained_detail,
                detail_truncated,
                process: None,
            });
            None
        }
    }
}

pub(super) fn terminal_exclusion(
    materialization: &HistoricalV2Materialization,
    source_census: &HistoricalV2SourceCensus,
    failures: Vec<HistoricalV2SemanticCensusFailureEvidence>,
) -> Result<SemanticCensusStageResult, HistoricalV2SlotStageError> {
    let exclusion = seal_semantic_census_exclusion(
        &materialization.materialization_sha256,
        &source_census.source_census_sha256,
        failures,
    )
    .map_err(|error| infrastructure(error.detail))?;
    Ok(HistoricalV2StageResult::Excluded(exclusion))
}

pub(super) fn combine_stage_errors(
    errors: Vec<HistoricalV2SlotStageError>,
) -> HistoricalV2SlotStageError {
    let kind = if errors
        .iter()
        .any(|error| error.kind == HistoricalV2SlotStageErrorKind::InvalidInput)
    {
        HistoricalV2SlotStageErrorKind::InvalidInput
    } else if errors
        .iter()
        .any(|error| error.kind == HistoricalV2SlotStageErrorKind::InfrastructureFailed)
    {
        HistoricalV2SlotStageErrorKind::InfrastructureFailed
    } else {
        HistoricalV2SlotStageErrorKind::InfrastructureUnavailable
    };
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::SemanticCensus,
        kind,
        detail: errors
            .into_iter()
            .map(|error| error.detail)
            .collect::<Vec<_>>()
            .join("; additionally, "),
    }
}

fn stage_error(
    kind: HistoricalV2SlotStageErrorKind,
    side: HistoricalV2SemanticSnapshotSide,
    detail: String,
) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::SemanticCensus,
        kind,
        detail: format!("{side:?} semantic census failed: {detail}"),
    }
}

fn semantic_phase(phase: SemanticIndexerRunPhase) -> HistoricalV2SemanticCensusFailurePhase {
    match phase {
        SemanticIndexerRunPhase::RepositoryValidation => {
            HistoricalV2SemanticCensusFailurePhase::RepositoryValidation
        }
        SemanticIndexerRunPhase::InstallationVerification => {
            HistoricalV2SemanticCensusFailurePhase::InstallationVerification
        }
        SemanticIndexerRunPhase::Preparation => HistoricalV2SemanticCensusFailurePhase::Preparation,
        SemanticIndexerRunPhase::Execution => HistoricalV2SemanticCensusFailurePhase::Execution,
        SemanticIndexerRunPhase::OutputValidation => {
            HistoricalV2SemanticCensusFailurePhase::OutputValidation
        }
        SemanticIndexerRunPhase::SnapshotAssembly => {
            HistoricalV2SemanticCensusFailurePhase::SnapshotAssembly
        }
        SemanticIndexerRunPhase::Cleanup => HistoricalV2SemanticCensusFailurePhase::Cleanup,
        SemanticIndexerRunPhase::IntegrityVerification => {
            HistoricalV2SemanticCensusFailurePhase::IntegrityVerification
        }
    }
}

fn process_evidence(
    process: SemanticIndexerProcessEvidence,
) -> HistoricalV2SemanticProcessEvidence {
    let (retained_stdout, locally_truncated_stdout) = retain(&process.stdout);
    let (retained_stderr, locally_truncated_stderr) = retain(&process.stderr);
    HistoricalV2SemanticProcessEvidence {
        status_code: process.status_code,
        stdout_sha256: process.stdout_sha256.clone(),
        stderr_sha256: process.stderr_sha256.clone(),
        stdout_truncated: locally_truncated_stdout
            || sha256(process.stdout.as_bytes()) != process.stdout_sha256,
        stderr_truncated: locally_truncated_stderr
            || sha256(process.stderr.as_bytes()) != process.stderr_sha256,
        retained_stdout,
        retained_stderr,
        timed_out: process.timed_out,
    }
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
