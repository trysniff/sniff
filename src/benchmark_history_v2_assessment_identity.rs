use super::{
    HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION, HistoricalV2AssessmentIdentity,
    HistoricalV2ExclusionManifest, HistoricalV2Frame, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2SelectedPayload, HistoricalV2SelectedPayloads,
    HistoricalV2SemanticCensus, HistoricalV2SlotOutcome, HistoricalV2SlotSelection,
    HistoricalV2SourceCensus, HistoricalV2TestMaterialization, HistoricalV2TestMaterializedRoots,
    validate_historical_v2_protocol, validate_historical_v2_selected_payloads_commitment,
    validate_historical_v2_semantic_census, validate_historical_v2_semantic_census_commitment,
    validate_historical_v2_slot_selection, validate_historical_v2_test_materialization,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const ASSESSMENT_IDENTITY_CONTRACT: &str = "sniffbench-historical-v2-assessment-identity-v1";

#[derive(Debug, Clone, Copy)]
pub struct HistoricalV2TestMaterializationBinding<'a> {
    pub artifact: &'a HistoricalV2TestMaterialization,
    pub roots: &'a HistoricalV2TestMaterializedRoots,
}

#[derive(Debug, Clone, Copy)]
pub struct HistoricalV2AssessmentIdentityInputs<'a> {
    pub protocol_bytes: &'a [u8],
    pub artifact_root: &'a Path,
    pub frame: &'a HistoricalV2Frame,
    pub exclusions: &'a HistoricalV2ExclusionManifest,
    pub selection: &'a HistoricalV2SlotSelection,
    pub payloads: &'a HistoricalV2SelectedPayloads,
    pub language: &'a str,
    pub slot_number: usize,
    pub materialization: &'a HistoricalV2Materialization,
    pub materialized_roots: &'a HistoricalV2MaterializedRoots,
    pub test_materialization: Option<HistoricalV2TestMaterializationBinding<'a>>,
    pub source_census: &'a HistoricalV2SourceCensus,
    pub semantic_census: &'a HistoricalV2SemanticCensus,
}

pub fn bind_historical_v2_assessment_identity(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
) -> Result<HistoricalV2AssessmentIdentity, String> {
    let protocol = validate_historical_v2_protocol(inputs.protocol_bytes)?;
    validate_historical_v2_slot_selection(
        inputs.protocol_bytes,
        inputs.artifact_root,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
    )?;
    validate_historical_v2_selected_payloads_commitment(
        &protocol,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
        inputs.payloads,
    )?;
    validate_historical_v2_semantic_census_commitment(
        inputs.materialization,
        inputs.materialized_roots,
        inputs.source_census,
        inputs.semantic_census,
    )?;

    let slot = selected_slot(inputs.selection, inputs.language, inputs.slot_number)?;
    let payload = selected_payload(inputs.payloads, inputs.language, inputs.slot_number)?;
    validate_slot_lineage(&slot, payload, inputs.materialization)?;
    let test_materialization_sha256 = validate_test_lineage(inputs, payload)?;

    seal_identity(HistoricalV2AssessmentIdentity {
        schema_version: HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION,
        assessment_identity_contract: ASSESSMENT_IDENTITY_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256,
        frame_sha256: inputs.frame.frame_sha256.clone(),
        exclusion_manifest_sha256: inputs.exclusions.manifest_sha256.clone(),
        selection_sha256: inputs.selection.selection_sha256.clone(),
        payloads_sha256: inputs.payloads.payloads_sha256.clone(),
        language: inputs.language.to_string(),
        slot_number: inputs.slot_number,
        global_row_index: payload.global_row_index,
        instance_id: payload.instance_id.clone(),
        canonical_repository: slot.canonical_repository.to_string(),
        pull_number: slot.pull_number,
        base_revision: slot.base_revision.to_string(),
        rank_sha256: slot.rank_sha256.to_string(),
        payload_sha256: payload.payload_sha256.clone(),
        historical_patch_sha256: payload.patch_sha256.clone(),
        install_config_sha256: payload.install_config_sha256.clone(),
        test_patch_sha256: payload.test_patch_sha256.clone(),
        materialization_sha256: inputs.materialization.materialization_sha256.clone(),
        test_materialization_sha256,
        source_census_sha256: inputs.source_census.source_census_sha256.clone(),
        base_source_snapshot_sha256: inputs.source_census.base.snapshot_census_sha256.clone(),
        patched_source_snapshot_sha256: inputs.source_census.patched.snapshot_census_sha256.clone(),
        semantic_census_sha256: inputs.semantic_census.semantic_census_sha256.clone(),
        base_semantic_snapshot_sha256: inputs.semantic_census.base.semantic_snapshot_sha256.clone(),
        patched_semantic_snapshot_sha256: inputs
            .semantic_census
            .patched
            .semantic_snapshot_sha256
            .clone(),
        assessment_identity_sha256: String::new(),
    })
}

pub fn validate_historical_v2_assessment_identity_commitment(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<(), String> {
    let expected = bind_historical_v2_assessment_identity(inputs)?;
    if identity != &expected {
        return Err("historical-v2 assessment identity changed".to_string());
    }
    Ok(())
}

pub async fn validate_historical_v2_assessment_identity(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<(), String> {
    validate_historical_v2_assessment_identity_commitment(inputs, identity)?;
    validate_historical_v2_semantic_census(
        inputs.materialization,
        inputs.materialized_roots,
        inputs.source_census,
        inputs.semantic_census,
    )
    .await
}

struct SelectedSlot<'a> {
    global_row_index: usize,
    instance_id: &'a str,
    canonical_repository: &'a str,
    pull_number: u64,
    base_revision: &'a str,
    patch_sha256: &'a str,
    rank_sha256: &'a str,
}

fn selected_slot<'a>(
    selection: &'a HistoricalV2SlotSelection,
    language: &str,
    slot_number: usize,
) -> Result<SelectedSlot<'a>, String> {
    let slot = selection
        .slots
        .iter()
        .find(|slot| slot.language == language && slot.slot_number == slot_number)
        .ok_or_else(|| "historical-v2 assessment slot is absent".to_string())?;
    let HistoricalV2SlotOutcome::Selected {
        global_row_index,
        instance_id,
        canonical_repository,
        pull_number,
        base_revision,
        patch_sha256,
        rank_sha256,
    } = &slot.outcome
    else {
        return Err("historical-v2 assessment slot is unfilled".to_string());
    };
    Ok(SelectedSlot {
        global_row_index: *global_row_index,
        instance_id,
        canonical_repository,
        pull_number: *pull_number,
        base_revision,
        patch_sha256,
        rank_sha256,
    })
}

fn selected_payload<'a>(
    payloads: &'a HistoricalV2SelectedPayloads,
    language: &str,
    slot_number: usize,
) -> Result<&'a HistoricalV2SelectedPayload, String> {
    payloads
        .records
        .iter()
        .find(|payload| payload.language == language && payload.slot_number == slot_number)
        .ok_or_else(|| "historical-v2 assessment payload is absent".to_string())
}

fn validate_slot_lineage(
    slot: &SelectedSlot<'_>,
    payload: &HistoricalV2SelectedPayload,
    materialization: &HistoricalV2Materialization,
) -> Result<(), String> {
    if payload.global_row_index != slot.global_row_index
        || payload.instance_id != slot.instance_id
        || payload.patch_sha256 != slot.patch_sha256
        || materialization.canonical_repository != slot.canonical_repository
        || materialization.base_revision != slot.base_revision
        || materialization.historical_patch_sha256 != slot.patch_sha256
    {
        return Err("historical-v2 assessment artifacts cross slot boundaries".to_string());
    }
    Ok(())
}

fn validate_test_lineage(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    payload: &HistoricalV2SelectedPayload,
) -> Result<Option<String>, String> {
    match (
        payload.test_patch_sha256.as_deref(),
        inputs.test_materialization,
    ) {
        (None, None) => Ok(None),
        (Some(expected), Some(binding)) => {
            validate_historical_v2_test_materialization(
                inputs.materialization,
                inputs.materialized_roots,
                expected,
                binding.artifact,
                binding.roots,
            )?;
            Ok(Some(binding.artifact.test_materialization_sha256.clone()))
        }
        _ => Err(
            "historical-v2 test materialization presence changed from the selected payload"
                .to_string(),
        ),
    }
}

fn seal_identity(
    mut identity: HistoricalV2AssessmentIdentity,
) -> Result<HistoricalV2AssessmentIdentity, String> {
    if !identity.assessment_identity_sha256.is_empty() {
        return Err("historical-v2 assessment identity is already sealed".to_string());
    }
    identity.assessment_identity_sha256 = identity_sha256(&identity)?;
    Ok(identity)
}

fn identity_sha256(identity: &HistoricalV2AssessmentIdentity) -> Result<String, String> {
    let mut committed = identity.clone();
    committed.assessment_identity_sha256.clear();
    hash_json(&committed)
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 assessment identity: {error}"))
}

#[cfg(test)]
#[path = "benchmark_history_v2_assessment_identity_tests.rs"]
mod tests;
