use super::history_v2_materialization_git::require_sha256;
use super::{
    HISTORICAL_V2_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION, HistoricalV2SlotStage,
    HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind, HistoricalV2SourceCensusExclusion,
    HistoricalV2SourceCensusExclusionReason, HistoricalV2SourceCensusFailureEvidence,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path};

const EXCLUSION_CONTRACT: &str = "sniffbench-historical-v2-source-census-exclusion-v1";

pub fn validate_historical_v2_source_census_exclusion(
    exclusion: &HistoricalV2SourceCensusExclusion,
) -> Result<(), String> {
    require_sha256(&exclusion.materialization_sha256)?;
    if exclusion.schema_version != HISTORICAL_V2_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION
        || exclusion.exclusion_contract != EXCLUSION_CONTRACT
        || exclusion.exclusion_sha256 != exclusion_sha256(exclusion)?
        || exclusion.failures.is_empty()
    {
        return Err("historical-v2 source census exclusion commitment changed".to_string());
    }
    let expected_reasons = exclusion
        .failures
        .iter()
        .map(failure_reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if exclusion.reasons != expected_reasons
        || !exclusion
            .failures
            .windows(2)
            .all(|pair| failure_key(&pair[0]) < failure_key(&pair[1]))
    {
        return Err("historical-v2 source census exclusion ordering changed".to_string());
    }
    for failure in &exclusion.failures {
        validate_failure(failure)?;
    }
    Ok(())
}

pub(super) fn seal_source_census_exclusion(
    materialization_sha256: &str,
    mut failures: Vec<HistoricalV2SourceCensusFailureEvidence>,
) -> Result<HistoricalV2SourceCensusExclusion, HistoricalV2SlotStageError> {
    failures.sort_by(|left, right| failure_key(left).cmp(&failure_key(right)));
    if failures
        .windows(2)
        .any(|pair| failure_key(&pair[0]) == failure_key(&pair[1]))
    {
        return Err(invalid(
            "historical-v2 source census repeated failure evidence",
        ));
    }
    let reasons = failures
        .iter()
        .map(failure_reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut exclusion = HistoricalV2SourceCensusExclusion {
        schema_version: HISTORICAL_V2_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        materialization_sha256: materialization_sha256.to_string(),
        reasons,
        failures,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion).map_err(invalid)?;
    validate_historical_v2_source_census_exclusion(&exclusion).map_err(invalid)?;
    Ok(exclusion)
}

pub(super) fn failure_reason(
    failure: &HistoricalV2SourceCensusFailureEvidence,
) -> HistoricalV2SourceCensusExclusionReason {
    match failure {
        HistoricalV2SourceCensusFailureEvidence::RepositoryContainsGitlink { .. } => {
            HistoricalV2SourceCensusExclusionReason::RepositoryContainsGitlink
        }
        HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob { .. } => {
            HistoricalV2SourceCensusExclusionReason::SupportedSourceIsNotRegularBlob
        }
        HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotUtf8 { .. } => {
            HistoricalV2SourceCensusExclusionReason::SupportedSourceIsNotUtf8
        }
        HistoricalV2SourceCensusFailureEvidence::SupportedSourceCannotBeParsed { .. } => {
            HistoricalV2SourceCensusExclusionReason::SupportedSourceCannotBeParsed
        }
    }
}

fn validate_failure(failure: &HistoricalV2SourceCensusFailureEvidence) -> Result<(), String> {
    let (revision, repository_path, object_id) = failure_identity(failure);
    require_oid(revision)?;
    require_oid(object_id)?;
    require_repository_path(repository_path)?;
    match failure {
        HistoricalV2SourceCensusFailureEvidence::RepositoryContainsGitlink { .. } => {}
        HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
            entry_kind,
            ..
        } => {
            if matches!(
                entry_kind,
                super::BoundaryGitEntryKind::RegularBlob
                    | super::BoundaryGitEntryKind::ExecutableBlob
            ) {
                return Err("historical-v2 non-blob evidence names a regular blob".to_string());
            }
        }
        HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
            byte_length,
            source_sha256,
            language,
            valid_up_to,
            error_length,
            ..
        } => {
            require_source_identity(*byte_length, source_sha256, language)?;
            if *valid_up_to >= *byte_length as usize
                || error_length.is_some_and(|length| length == 0)
            {
                return Err("historical-v2 UTF-8 rejection evidence changed".to_string());
            }
        }
        HistoricalV2SourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
            byte_length,
            source_sha256,
            language,
            parser_error_sha256,
            retained_parser_error,
            parser_error_truncated,
            ..
        } => {
            require_source_identity(*byte_length, source_sha256, language)?;
            require_sha256(parser_error_sha256)?;
            if retained_parser_error.is_empty()
                || retained_parser_error.len() > super::history_v2_source_census::PARSER_ERROR_LIMIT
                || (!parser_error_truncated
                    && format!("{:x}", Sha256::digest(retained_parser_error.as_bytes()))
                        != *parser_error_sha256)
            {
                return Err("historical-v2 parser rejection evidence changed".to_string());
            }
        }
    }
    Ok(())
}

fn require_source_identity(
    byte_length: u64,
    source_sha256: &str,
    language: &str,
) -> Result<(), String> {
    require_sha256(source_sha256)?;
    if byte_length == 0 || language.trim().is_empty() {
        return Err("historical-v2 source rejection identity changed".to_string());
    }
    Ok(())
}

fn require_oid(value: &str) -> Result<(), String> {
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("historical-v2 source rejection Git identity changed".to_string())
    }
}

fn require_repository_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("historical-v2 source rejection path changed".to_string());
    }
    Ok(())
}

fn failure_key(
    failure: &HistoricalV2SourceCensusFailureEvidence,
) -> (
    super::HistoricalV2SourceSnapshotSide,
    &str,
    HistoricalV2SourceCensusExclusionReason,
) {
    let (side, path) = match failure {
        HistoricalV2SourceCensusFailureEvidence::RepositoryContainsGitlink {
            side,
            repository_path,
            ..
        }
        | HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
            side,
            repository_path,
            ..
        }
        | HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
            side,
            repository_path,
            ..
        }
        | HistoricalV2SourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
            side,
            repository_path,
            ..
        } => (*side, repository_path.as_str()),
    };
    (side, path, failure_reason(failure))
}

fn failure_identity(failure: &HistoricalV2SourceCensusFailureEvidence) -> (&str, &str, &str) {
    match failure {
        HistoricalV2SourceCensusFailureEvidence::RepositoryContainsGitlink {
            revision,
            repository_path,
            object_id,
            ..
        }
        | HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob {
            revision,
            repository_path,
            object_id,
            ..
        }
        | HistoricalV2SourceCensusFailureEvidence::SupportedSourceIsNotUtf8 {
            revision,
            repository_path,
            object_id,
            ..
        }
        | HistoricalV2SourceCensusFailureEvidence::SupportedSourceCannotBeParsed {
            revision,
            repository_path,
            object_id,
            ..
        } => (revision, repository_path, object_id),
    }
}

fn exclusion_sha256(value: &HistoricalV2SourceCensusExclusion) -> Result<String, String> {
    let mut committed = value.clone();
    committed.exclusion_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 source exclusion: {error}"))
}

fn invalid(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::SourceCensus,
        kind: HistoricalV2SlotStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
