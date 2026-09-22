use super::super::{
    IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticCensusExclusionReason,
    IntentionalBoundarySemanticCensusFailureEvidence,
    IntentionalBoundarySemanticCensusFailurePhase,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const RETAINED_EVIDENCE_LIMIT: usize = 4 * 1024;

pub(super) fn validate_failure(
    failure: &IntentionalBoundarySemanticCensusFailureEvidence,
    expected_indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
) -> Result<(), String> {
    if !valid_sha256(&failure.detail_sha256)
        || failure.retained_detail.is_empty()
        || failure.retained_detail.len() > RETAINED_EVIDENCE_LIMIT
        || (!failure.detail_truncated
            && sha256(failure.retained_detail.as_bytes()) != failure.detail_sha256)
        || failure
            .indexer
            .is_some_and(|indexer| !expected_indexers.contains(&indexer))
    {
        return Err("historical-v3 semantic failure detail changed".to_string());
    }
    if failure.phase == IntentionalBoundarySemanticCensusFailurePhase::CensusAssembly {
        if failure.indexer.is_some()
            || failure.process.is_some()
            || failure.reason
                != IntentionalBoundarySemanticCensusExclusionReason::CompilerCensusIncomplete
        {
            return Err("historical-v3 semantic assembly failure changed".to_string());
        }
    } else if failure.indexer.is_none() {
        return Err("historical-v3 semantic indexer failure has no indexer".to_string());
    }
    if let Some(process) = &failure.process
        && (!valid_sha256(&process.stdout_sha256)
            || !valid_sha256(&process.stderr_sha256)
            || process.retained_stdout.len() > RETAINED_EVIDENCE_LIMIT
            || process.retained_stderr.len() > RETAINED_EVIDENCE_LIMIT
            || (!process.stdout_truncated
                && sha256(process.retained_stdout.as_bytes()) != process.stdout_sha256)
            || (!process.stderr_truncated
                && sha256(process.retained_stderr.as_bytes()) != process.stderr_sha256))
    {
        return Err("historical-v3 semantic process evidence changed".to_string());
    }
    Ok(())
}

pub(super) fn failure_key(
    failure: &IntentionalBoundarySemanticCensusFailureEvidence,
) -> (
    Option<IntentionalBoundaryIndexerKind>,
    IntentionalBoundarySemanticCensusFailurePhase,
    IntentionalBoundarySemanticCensusExclusionReason,
    &str,
) {
    (
        failure.indexer,
        failure.phase,
        failure.reason,
        &failure.detail_sha256,
    )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
