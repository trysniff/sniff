use super::history_v2_materialization_git::{
    require_oid, require_repository, require_revision, require_sha256,
};
use super::{
    HISTORICAL_V2_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
    HistoricalV2GitCommandRejectionEvidence, HistoricalV2MaterializationExclusion,
    HistoricalV2MaterializationExclusionEvidence, HistoricalV2MaterializationExclusionReason,
    HistoricalV2SlotStage, HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const EXCLUSION_CONTRACT: &str = "sniffbench-historical-v2-materialization-exclusion-v1";

pub fn validate_historical_v2_materialization_exclusion(
    exclusion: &HistoricalV2MaterializationExclusion,
) -> Result<(), String> {
    require_repository(&exclusion.canonical_repository)?;
    require_revision(&exclusion.base_revision)?;
    require_sha256(&exclusion.historical_patch_sha256)?;
    if exclusion.schema_version != HISTORICAL_V2_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION
        || exclusion.exclusion_contract != EXCLUSION_CONTRACT
        || exclusion.exclusion_sha256 != materialization_exclusion_sha256(exclusion)?
        || !matching_exclusion_evidence(exclusion)
    {
        return Err("historical-v2 materialization exclusion commitment changed".to_string());
    }
    validate_exclusion_evidence(exclusion)
}

pub(super) fn seal_materialization_exclusion(
    canonical_repository: &str,
    base_revision: &str,
    historical_patch_sha256: &str,
    reason: HistoricalV2MaterializationExclusionReason,
    evidence: HistoricalV2MaterializationExclusionEvidence,
) -> Result<HistoricalV2MaterializationExclusion, HistoricalV2SlotStageError> {
    let mut exclusion = HistoricalV2MaterializationExclusion {
        schema_version: HISTORICAL_V2_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        canonical_repository: canonical_repository.to_string(),
        base_revision: base_revision.to_string(),
        historical_patch_sha256: historical_patch_sha256.to_string(),
        reason,
        evidence,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = materialization_exclusion_sha256(&exclusion).map_err(invalid)?;
    validate_historical_v2_materialization_exclusion(&exclusion).map_err(invalid)?;
    Ok(exclusion)
}

fn matching_exclusion_evidence(exclusion: &HistoricalV2MaterializationExclusion) -> bool {
    use HistoricalV2MaterializationExclusionEvidence as Evidence;
    use HistoricalV2MaterializationExclusionReason as Reason;

    matches!(
        (&exclusion.reason, &exclusion.evidence),
        (
            Reason::RepositoryUnavailable,
            Evidence::RepositoryProbe { .. }
        ) | (Reason::RepositoryEmpty, Evidence::RepositoryEmpty { .. })
            | (
                Reason::BaseRevisionUnavailable,
                Evidence::BaseRevisionUnavailable { .. }
            )
            | (
                Reason::UnsupportedGitObjectFormat,
                Evidence::UnsupportedGitObjectFormat { .. }
            )
            | (
                Reason::HistoricalPatchDoesNotApply,
                Evidence::HistoricalPatchRejected { .. }
            )
            | (
                Reason::HistoricalPatchProducesNoTreeChange,
                Evidence::HistoricalPatchProducesNoTreeChange { .. }
            )
    )
}

fn validate_exclusion_evidence(
    exclusion: &HistoricalV2MaterializationExclusion,
) -> Result<(), String> {
    use HistoricalV2MaterializationExclusionEvidence as Evidence;

    match &exclusion.evidence {
        Evidence::RepositoryProbe { url, status } => {
            let expected = format!(
                "https://{}.git/info/refs?service=git-upload-pack",
                exclusion.canonical_repository
            );
            if url != &expected || !matches!(*status, 401 | 404 | 410) {
                return Err("historical-v2 repository exclusion probe changed".to_string());
            }
        }
        Evidence::RepositoryEmpty { clone_url } => {
            if clone_url.is_empty() {
                return Err("historical-v2 empty repository evidence is missing".to_string());
            }
        }
        Evidence::BaseRevisionUnavailable { revision, command } => {
            if revision != &exclusion.base_revision {
                return Err("historical-v2 unavailable base revision changed".to_string());
            }
            validate_git_rejection(command)?;
        }
        Evidence::UnsupportedGitObjectFormat { object_format } => {
            if object_format.is_empty() || object_format == "sha1" {
                return Err("historical-v2 unsupported object format evidence changed".to_string());
            }
        }
        Evidence::HistoricalPatchRejected {
            patch_sha256,
            command,
        } => {
            if patch_sha256 != &exclusion.historical_patch_sha256 {
                return Err("historical-v2 rejected patch identity changed".to_string());
            }
            validate_git_rejection(command)?;
        }
        Evidence::HistoricalPatchProducesNoTreeChange { base_tree_oid } => {
            require_oid(base_tree_oid)?;
        }
    }
    Ok(())
}

fn validate_git_rejection(
    evidence: &HistoricalV2GitCommandRejectionEvidence,
) -> Result<(), String> {
    if evidence.command_label.is_empty()
        || evidence.stdout_sha256.len() != 64
        || !evidence
            .stdout_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || evidence.stderr_sha256.len() != 64
        || !evidence
            .stderr_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || evidence.retained_stderr.chars().count() > 4096
    {
        return Err("historical-v2 rejected Git command evidence changed".to_string());
    }
    Ok(())
}

fn materialization_exclusion_sha256(
    value: &HistoricalV2MaterializationExclusion,
) -> Result<String, String> {
    hash_json(&(
        value.schema_version,
        &value.exclusion_contract,
        &value.canonical_repository,
        &value.base_revision,
        &value.historical_patch_sha256,
        value.reason,
        &value.evidence,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            format!("failed to commit historical-v2 materialization exclusion: {error}")
        })
}

fn invalid(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::Materialization,
        kind: HistoricalV2SlotStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
