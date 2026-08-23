use super::intentional_boundary_license_commitment::validate_license_payload_commitment;
use super::intentional_boundary_license_filename::{
    INTENTIONAL_BOUNDARY_LICENSE_FILENAME_CONTRACT, match_license_filename,
};
use super::{
    BoundaryGitEntryKind, INTENTIONAL_BOUNDARY_LICENSE_CENSUS_EXCLUSION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_LICENSE_CENSUS_STAGE_SCHEMA_VERSION, IntentionalBoundaryFrameTask,
    IntentionalBoundaryInventoryError, IntentionalBoundaryInventoryErrorKind,
    IntentionalBoundaryLicenseArtifact, IntentionalBoundaryLicenseCandidateRejection,
    IntentionalBoundaryLicenseCensusExclusion, IntentionalBoundaryLicenseCensusExclusionReason,
    IntentionalBoundaryLicenseCensusStage, IntentionalBoundaryLicenseCensusStageError,
    IntentionalBoundaryLicenseCensusStageErrorKind, IntentionalBoundaryLicenseCensusStageOutcome,
    IntentionalBoundaryLicenseFailureEvidence, IntentionalBoundaryMaterialization,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySourceCensusStage,
    IntentionalBoundarySourceCensusStageError, IntentionalBoundarySourceCensusStageErrorKind,
    read_intentional_boundary_git_blob_typed, validate_committed_source_census_stage,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-license-census-stage-v1";
const EXCLUSION_CONTRACT: &str = "sniffbench-intentional-boundary-license-census-exclusion-v1";

pub fn census_intentional_boundary_repository_licenses(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
) -> Result<IntentionalBoundaryLicenseCensusStageOutcome, IntentionalBoundaryLicenseCensusStageError>
{
    validate_source_census(task, materialization, inventory, source_census)?;
    let inspection = inspect_license_candidates(root, inventory)?;

    if !inspection.failures.is_empty() {
        return exclusion(
            task,
            materialization,
            inventory,
            source_census,
            IntentionalBoundaryLicenseCensusExclusionReason::UnsupportedProjectShape,
            inspection,
        )
        .map(IntentionalBoundaryLicenseCensusStageOutcome::Excluded);
    }
    if inspection.artifacts.is_empty() {
        return exclusion(
            task,
            materialization,
            inventory,
            source_census,
            IntentionalBoundaryLicenseCensusExclusionReason::MissingLicense,
            inspection,
        )
        .map(IntentionalBoundaryLicenseCensusStageOutcome::Excluded);
    }

    let mut stage = IntentionalBoundaryLicenseCensusStage {
        schema_version: INTENTIONAL_BOUNDARY_LICENSE_CENSUS_STAGE_SCHEMA_VERSION,
        stage_contract: STAGE_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_census.stage_sha256.clone(),
        filename_contract: INTENTIONAL_BOUNDARY_LICENSE_FILENAME_CONTRACT.to_string(),
        tracked_entry_count: inventory.tracked_entries.len(),
        matched_candidate_count: inspection.matched_candidate_count,
        license_artifacts: inspection.artifacts,
        rejected_candidates: inspection.rejected,
        stage_sha256: String::new(),
    };
    stage.stage_sha256 = stage_sha256(&stage)?;
    Ok(IntentionalBoundaryLicenseCensusStageOutcome::Completed(
        stage,
    ))
}

pub fn validate_intentional_boundary_license_census_stage_outcome(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    outcome: &IntentionalBoundaryLicenseCensusStageOutcome,
) -> Result<(), IntentionalBoundaryLicenseCensusStageError> {
    let expected = census_intentional_boundary_repository_licenses(
        task,
        materialization,
        root,
        inventory,
        source_census,
    )?;
    if outcome != &expected {
        return Err(invalid(
            "intentional-boundary license census stage outcome changed",
        ));
    }
    Ok(())
}

pub(super) fn validate_committed_license_census_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    stage: &IntentionalBoundaryLicenseCensusStage,
) -> Result<(), IntentionalBoundaryLicenseCensusStageError> {
    validate_source_census(task, materialization, inventory, source_census)?;
    validate_license_payload_commitment(inventory, stage).map_err(invalid)?;
    if stage.schema_version != INTENTIONAL_BOUNDARY_LICENSE_CENSUS_STAGE_SCHEMA_VERSION
        || stage.stage_contract != STAGE_CONTRACT
        || stage.frame_task_sha256 != task.task_sha256
        || stage.population_rank != materialization.population_rank
        || stage.materialization_sha256 != materialization.materialization_sha256
        || stage.inventory_sha256 != inventory.inventory_sha256
        || stage.source_census_stage_sha256 != source_census.stage_sha256
        || stage.filename_contract != INTENTIONAL_BOUNDARY_LICENSE_FILENAME_CONTRACT
        || stage.tracked_entry_count != inventory.tracked_entries.len()
        || stage.stage_sha256 != stage_sha256(stage)?
    {
        return Err(invalid(
            "intentional-boundary committed license census stage changed",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct LicenseInspection {
    matched_candidate_count: usize,
    artifacts: Vec<IntentionalBoundaryLicenseArtifact>,
    rejected: Vec<IntentionalBoundaryLicenseCandidateRejection>,
    failures: Vec<IntentionalBoundaryLicenseFailureEvidence>,
}

fn inspect_license_candidates(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<LicenseInspection, IntentionalBoundaryLicenseCensusStageError> {
    let mut inspection = LicenseInspection::default();
    for entry in &inventory.tracked_entries {
        let Some(filename_match) = match_license_filename(&entry.repository_path) else {
            continue;
        };
        inspection.matched_candidate_count = inspection
            .matched_candidate_count
            .checked_add(1)
            .ok_or_else(|| invalid("intentional-boundary license candidate count overflowed"))?;
        if !matches!(
            entry.kind,
            BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob
        ) {
            inspection.failures.push(
                IntentionalBoundaryLicenseFailureEvidence::CandidateIsNotBlob {
                    repository_path: entry.repository_path.clone(),
                    object_id: entry.object_id.clone(),
                    entry_kind: entry.kind,
                    filename_rule: filename_match.rule,
                    filename_score_basis_points: filename_match.score_basis_points,
                },
            );
            continue;
        }
        let byte_length = entry.byte_length.ok_or_else(|| {
            invalid(format!(
                "license candidate {} has no committed byte length",
                entry.repository_path
            ))
        })?;
        let bytes = read_intentional_boundary_git_blob_typed(root, &entry.object_id, byte_length)
            .map_err(map_inventory_error)?;
        let checkout_bytes = fs::read(root.join(&entry.repository_path)).map_err(|error| {
            failed(format!(
                "failed to read checked-out license candidate {}: {error}",
                entry.repository_path
            ))
        })?;
        if checkout_bytes != bytes {
            return Err(invalid(format!(
                "checked-out license candidate {} differs from committed Git blob {}",
                entry.repository_path, entry.object_id
            )));
        }
        let content_sha256 = sha256(&bytes);
        if bytes.iter().all(u8::is_ascii_whitespace) {
            inspection.rejected.push(
                IntentionalBoundaryLicenseCandidateRejection::EmptyOrWhitespace {
                    repository_path: entry.repository_path.clone(),
                    object_id: entry.object_id.clone(),
                    byte_length,
                    content_sha256,
                    filename_rule: filename_match.rule,
                    filename_score_basis_points: filename_match.score_basis_points,
                },
            );
        } else {
            inspection
                .artifacts
                .push(IntentionalBoundaryLicenseArtifact {
                    repository_path: entry.repository_path.clone(),
                    object_id: entry.object_id.clone(),
                    byte_length,
                    content_sha256,
                    filename_rule: filename_match.rule,
                    filename_score_basis_points: filename_match.score_basis_points,
                });
        }
    }
    Ok(inspection)
}

fn exclusion(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    reason: IntentionalBoundaryLicenseCensusExclusionReason,
    inspection: LicenseInspection,
) -> Result<IntentionalBoundaryLicenseCensusExclusion, IntentionalBoundaryLicenseCensusStageError> {
    let evidence_matches_reason = match reason {
        IntentionalBoundaryLicenseCensusExclusionReason::MissingLicense => {
            inspection.artifacts.is_empty() && inspection.failures.is_empty()
        }
        IntentionalBoundaryLicenseCensusExclusionReason::UnsupportedProjectShape => {
            !inspection.failures.is_empty()
        }
    };
    if !evidence_matches_reason {
        return Err(invalid(
            "intentional-boundary license exclusion evidence contradicts its reason",
        ));
    }
    let mut exclusion = IntentionalBoundaryLicenseCensusExclusion {
        schema_version: INTENTIONAL_BOUNDARY_LICENSE_CENSUS_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        repository: materialization.repository.clone(),
        revision: materialization.revision.clone(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_census.stage_sha256.clone(),
        filename_contract: INTENTIONAL_BOUNDARY_LICENSE_FILENAME_CONTRACT.to_string(),
        reason,
        tracked_entry_count: inventory.tracked_entries.len(),
        matched_candidate_count: inspection.matched_candidate_count,
        rejected_candidates: inspection.rejected,
        failures: inspection.failures,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion)?;
    Ok(exclusion)
}

fn validate_source_census(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
) -> Result<(), IntentionalBoundaryLicenseCensusStageError> {
    validate_committed_source_census_stage(task, materialization, inventory, source_census)
        .map_err(map_source_error)
}

fn stage_sha256(
    value: &IntentionalBoundaryLicenseCensusStage,
) -> Result<String, IntentionalBoundaryLicenseCensusStageError> {
    hash_json(&(
        value.schema_version,
        &value.stage_contract,
        &value.frame_task_sha256,
        value.population_rank,
        &value.materialization_sha256,
        &value.inventory_sha256,
        &value.source_census_stage_sha256,
        &value.filename_contract,
        value.tracked_entry_count,
        value.matched_candidate_count,
        &value.license_artifacts,
        &value.rejected_candidates,
    ))
}

fn exclusion_sha256(
    value: &IntentionalBoundaryLicenseCensusExclusion,
) -> Result<String, IntentionalBoundaryLicenseCensusStageError> {
    hash_json(&(
        value.schema_version,
        &value.exclusion_contract,
        &value.frame_task_sha256,
        value.population_rank,
        &value.repository,
        &value.revision,
        &value.materialization_sha256,
        &value.inventory_sha256,
        &value.source_census_stage_sha256,
        &value.filename_contract,
        value.reason,
        value.tracked_entry_count,
        value.matched_candidate_count,
        &value.rejected_candidates,
        &value.failures,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryLicenseCensusStageError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| invalid(format!("failed to commit license census stage: {error}")))
}

fn map_source_error(
    error: IntentionalBoundarySourceCensusStageError,
) -> IntentionalBoundaryLicenseCensusStageError {
    IntentionalBoundaryLicenseCensusStageError {
        kind: match error.kind {
            IntentionalBoundarySourceCensusStageErrorKind::InvalidInput => {
                IntentionalBoundaryLicenseCensusStageErrorKind::InvalidInput
            }
            IntentionalBoundarySourceCensusStageErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundarySourceCensusStageErrorKind::InfrastructureFailed => {
                IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn map_inventory_error(
    error: IntentionalBoundaryInventoryError,
) -> IntentionalBoundaryLicenseCensusStageError {
    IntentionalBoundaryLicenseCensusStageError {
        kind: match error.kind {
            IntentionalBoundaryInventoryErrorKind::InvalidInput => {
                IntentionalBoundaryLicenseCensusStageErrorKind::InvalidInput
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureFailed => {
                IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryLicenseCensusStageError {
    IntentionalBoundaryLicenseCensusStageError {
        kind: IntentionalBoundaryLicenseCensusStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

fn failed(detail: impl Into<String>) -> IntentionalBoundaryLicenseCensusStageError {
    IntentionalBoundaryLicenseCensusStageError {
        kind: IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_license_census_tests.rs"]
mod tests;
