use super::history_v2_materialization_git::require_sha256;
use super::{
    HISTORICAL_V2_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION, HistoricalV2SemanticCensusExclusion,
    HistoricalV2SemanticCensusExclusionReason, HistoricalV2SemanticCensusFailureEvidence,
    HistoricalV2SemanticCensusFailurePhase, HistoricalV2SemanticProcessEvidence,
    HistoricalV2SlotStage, HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const EXCLUSION_CONTRACT: &str = "sniffbench-historical-v2-semantic-census-exclusion-v1";
pub(super) const RETAINED_EVIDENCE_LIMIT: usize = 4 * 1024;

pub fn validate_historical_v2_semantic_census_exclusion(
    exclusion: &HistoricalV2SemanticCensusExclusion,
) -> Result<(), String> {
    require_sha256(&exclusion.materialization_sha256)?;
    require_sha256(&exclusion.source_census_sha256)?;
    if exclusion.schema_version != HISTORICAL_V2_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION
        || exclusion.exclusion_contract != EXCLUSION_CONTRACT
        || exclusion.exclusion_sha256 != exclusion_sha256(exclusion)?
        || exclusion.failures.is_empty()
    {
        return Err("historical-v2 semantic exclusion commitment changed".to_string());
    }
    let expected_reasons = exclusion
        .failures
        .iter()
        .map(|failure| failure.reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if exclusion.reasons != expected_reasons
        || !exclusion
            .failures
            .windows(2)
            .all(|pair| failure_key(&pair[0]) < failure_key(&pair[1]))
    {
        return Err("historical-v2 semantic exclusion ordering changed".to_string());
    }
    for failure in &exclusion.failures {
        validate_failure(failure)?;
    }
    Ok(())
}

pub(super) fn seal_semantic_census_exclusion(
    materialization_sha256: &str,
    source_census_sha256: &str,
    mut failures: Vec<HistoricalV2SemanticCensusFailureEvidence>,
) -> Result<HistoricalV2SemanticCensusExclusion, HistoricalV2SlotStageError> {
    failures.sort_by_key(failure_key);
    if failures
        .windows(2)
        .any(|pair| failure_key(&pair[0]) == failure_key(&pair[1]))
    {
        return Err(invalid(
            "historical-v2 semantic census repeated failure evidence",
        ));
    }
    let reasons = failures
        .iter()
        .map(|failure| failure.reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut exclusion = HistoricalV2SemanticCensusExclusion {
        schema_version: HISTORICAL_V2_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        materialization_sha256: materialization_sha256.to_string(),
        source_census_sha256: source_census_sha256.to_string(),
        reasons,
        failures,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion).map_err(invalid)?;
    validate_historical_v2_semantic_census_exclusion(&exclusion).map_err(invalid)?;
    Ok(exclusion)
}

fn validate_failure(failure: &HistoricalV2SemanticCensusFailureEvidence) -> Result<(), String> {
    require_oid(&failure.revision)?;
    require_sha256(&failure.detail_sha256)?;
    if failure.retained_detail.is_empty() {
        return Err("historical-v2 semantic failure detail is empty".to_string());
    }
    validate_retained(
        &failure.retained_detail,
        failure.detail_truncated,
        &failure.detail_sha256,
    )?;
    match failure.reason {
        HistoricalV2SemanticCensusExclusionReason::UnsupportedProjectShape => {
            if failure.phase != HistoricalV2SemanticCensusFailurePhase::RepositoryValidation
                && failure.phase != HistoricalV2SemanticCensusFailurePhase::Preparation
            {
                return Err("historical-v2 unsupported shape phase changed".to_string());
            }
        }
        HistoricalV2SemanticCensusExclusionReason::CompilerIndexerRejectedRepository => {
            if failure.indexer.is_none()
                || failure.phase != HistoricalV2SemanticCensusFailurePhase::Execution
                || failure.process.is_none()
                || failure.process.as_ref().is_some_and(|process| {
                    process.status_code.is_none() || process.status_code == Some(0)
                })
            {
                return Err("historical-v2 indexer rejection evidence changed".to_string());
            }
        }
        HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete => {
            if !matches!(
                failure.phase,
                HistoricalV2SemanticCensusFailurePhase::OutputValidation
                    | HistoricalV2SemanticCensusFailurePhase::SnapshotAssembly
            ) {
                return Err("historical-v2 incomplete census phase changed".to_string());
            }
            if failure.phase == HistoricalV2SemanticCensusFailurePhase::OutputValidation
                && failure
                    .process
                    .as_ref()
                    .is_none_or(|process| process.status_code != Some(0))
            {
                return Err("historical-v2 incomplete output process status changed".to_string());
            }
        }
    }
    if let Some(process) = &failure.process {
        validate_process(process)?;
    }
    Ok(())
}

fn validate_process(process: &HistoricalV2SemanticProcessEvidence) -> Result<(), String> {
    require_sha256(&process.stdout_sha256)?;
    require_sha256(&process.stderr_sha256)?;
    validate_retained(
        &process.retained_stdout,
        process.stdout_truncated,
        &process.stdout_sha256,
    )?;
    validate_retained(
        &process.retained_stderr,
        process.stderr_truncated,
        &process.stderr_sha256,
    )?;
    if process.timed_out {
        return Err("terminal semantic evidence cannot be a timeout".to_string());
    }
    Ok(())
}

fn validate_retained(value: &str, truncated: bool, complete_sha256: &str) -> Result<(), String> {
    if value.len() > RETAINED_EVIDENCE_LIMIT
        || (!truncated && sha256(value.as_bytes()) != complete_sha256)
    {
        return Err("historical-v2 retained semantic evidence changed".to_string());
    }
    Ok(())
}

fn require_oid(value: &str) -> Result<(), String> {
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("historical-v2 semantic revision changed".to_string())
    }
}

fn failure_key(
    failure: &HistoricalV2SemanticCensusFailureEvidence,
) -> (
    super::HistoricalV2SemanticSnapshotSide,
    HistoricalV2SemanticCensusExclusionReason,
    Option<super::IntentionalBoundaryIndexerKind>,
    HistoricalV2SemanticCensusFailurePhase,
) {
    (failure.side, failure.reason, failure.indexer, failure.phase)
}

fn exclusion_sha256(value: &HistoricalV2SemanticCensusExclusion) -> Result<String, String> {
    let mut committed = value.clone();
    committed.exclusion_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 semantic exclusion: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::SemanticCensus,
        kind: HistoricalV2SlotStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
