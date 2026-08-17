use super::{
    HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION, HistoricalV2AssessmentIdentity,
    HistoricalV2AssessmentIdentityInputs, HistoricalV2ExclusionManifest, HistoricalV2Frame,
    HistoricalV2IdenticalTestExecution, HistoricalV2IdenticalTestOutcome,
    HistoricalV2IdenticalTestPlan, HistoricalV2Materialization,
    HistoricalV2MaterializationExclusion, HistoricalV2MaterializedRoots,
    HistoricalV2NoTestPatchArtifact, HistoricalV2Qualification, HistoricalV2QualificationOutcome,
    HistoricalV2SelectedPayloads, HistoricalV2SelectedSlotPayloadArtifact,
    HistoricalV2SemanticCensus, HistoricalV2SemanticCensusExclusion, HistoricalV2SlotOutcome,
    HistoricalV2SlotSelection, HistoricalV2SlotStage, HistoricalV2SlotStageCheckpoint,
    HistoricalV2SlotStageCheckpointInput, HistoricalV2SlotStageError, HistoricalV2SlotStageJournal,
    HistoricalV2SlotStageOutcome, HistoricalV2SourceCensus, HistoricalV2SourceCensusExclusion,
    HistoricalV2StageArtifactKind, HistoricalV2StageResult, HistoricalV2TerminalExclusionReason,
    HistoricalV2TestMaterializationBinding, HistoricalV2TestMaterializationExclusion,
    HistoricalV2TestRecipe, HistoricalV2TestRecipeOutcome, census_historical_v2_semantics_typed,
    census_historical_v2_sources_typed, validate_historical_v2_assessment_identity_commitment,
    validate_historical_v2_identical_test_execution, validate_historical_v2_materialization,
    validate_historical_v2_materialization_exclusion, validate_historical_v2_protocol,
    validate_historical_v2_qualification_commitment,
    validate_historical_v2_selected_payloads_commitment,
    validate_historical_v2_semantic_census_commitment,
    validate_historical_v2_semantic_census_exclusion, validate_historical_v2_slot_selection,
    validate_historical_v2_source_census, validate_historical_v2_source_census_exclusion,
    validate_historical_v2_test_materialization,
    validate_historical_v2_test_materialization_exclusion, validate_historical_v2_test_recipe,
};
use std::path::Path;

const SELECTED_PAYLOAD_CONTRACT: &str = "sniffbench-historical-v2-selected-slot-payload-v1";
const NO_TEST_PATCH_CONTRACT: &str = "sniffbench-historical-v2-no-test-patch-v1";

pub struct HistoricalV2PayloadStageInputs<'a> {
    pub protocol_bytes: &'a [u8],
    pub artifact_root: &'a Path,
    pub frame: &'a HistoricalV2Frame,
    pub exclusions: &'a HistoricalV2ExclusionManifest,
    pub selection: &'a HistoricalV2SlotSelection,
    pub payloads: &'a HistoricalV2SelectedPayloads,
    pub language: &'a str,
    pub slot_number: usize,
}

pub(crate) fn prepare_historical_v2_selected_slot_payload(
    inputs: &HistoricalV2PayloadStageInputs<'_>,
) -> Result<HistoricalV2SelectedSlotPayloadArtifact, HistoricalV2SlotStageError> {
    selected_slot_payload(inputs)
        .and_then(seal_selected_slot_payload)
        .map_err(|detail| {
            HistoricalV2SlotStageError::invalid(HistoricalV2SlotStage::Payload, detail)
        })
}

pub fn checkpoint_historical_v2_payload(
    journal: &mut HistoricalV2SlotStageJournal,
    inputs: &HistoricalV2PayloadStageInputs<'_>,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::Payload;
    let protocol = validate_historical_v2_protocol(inputs.protocol_bytes)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    validate_historical_v2_slot_selection(
        inputs.protocol_bytes,
        inputs.artifact_root,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
    )
    .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    validate_historical_v2_selected_payloads_commitment(
        &protocol,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
        inputs.payloads,
    )
    .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    let artifact = prepare_historical_v2_selected_slot_payload(inputs)?;
    journal.append(
        HistoricalV2SlotStageCheckpointInput {
            selection_sha256: &artifact.selection_sha256,
            language: &artifact.language,
            slot_number: artifact.slot_number,
            canonical_repository: &artifact.canonical_repository,
            stage,
            outcome: HistoricalV2SlotStageOutcome::Completed {
                artifact_kind: HistoricalV2StageArtifactKind::SelectedPayload,
                artifact_sha256: artifact.artifact_sha256.clone(),
            },
        },
        Some(&artifact),
    )
}

pub(crate) fn prepare_historical_v2_no_test_patch(
    payload: &HistoricalV2SelectedSlotPayloadArtifact,
    materialization: &HistoricalV2Materialization,
) -> Result<HistoricalV2NoTestPatchArtifact, HistoricalV2SlotStageError> {
    seal_no_test_patch(HistoricalV2NoTestPatchArtifact {
        schema_version: HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION,
        artifact_contract: NO_TEST_PATCH_CONTRACT.to_string(),
        selected_slot_payload_sha256: payload.artifact_sha256.clone(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        language: payload.language.clone(),
        slot_number: payload.slot_number,
        canonical_repository: payload.canonical_repository.clone(),
        artifact_sha256: String::new(),
    })
    .map_err(|detail| {
        HistoricalV2SlotStageError::invalid(HistoricalV2SlotStage::TestMaterialization, detail)
    })
}

pub fn checkpoint_historical_v2_materialization(
    journal: &mut HistoricalV2SlotStageJournal,
    artifact: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::Materialization;
    validate_historical_v2_materialization(artifact, roots)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    let payload = stored_artifact::<HistoricalV2SelectedSlotPayloadArtifact>(journal, 0, stage)?;
    validate_selected_slot_payload(&payload)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    if artifact.canonical_repository != payload.canonical_repository
        || artifact.base_revision != payload.base_revision
        || artifact.historical_patch_sha256 != payload.payload.patch_sha256
    {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 materialization crossed its selected payload boundary",
        ));
    }
    append_same_slot(
        journal,
        stage,
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::Materialization,
            artifact_sha256: artifact.materialization_sha256.clone(),
        },
        Some(artifact),
    )
}

pub fn checkpoint_historical_v2_materialization_exclusion(
    journal: &mut HistoricalV2SlotStageJournal,
    exclusion: &HistoricalV2MaterializationExclusion,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::Materialization;
    validate_historical_v2_materialization_exclusion(exclusion)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    let payload = stored_artifact::<HistoricalV2SelectedSlotPayloadArtifact>(journal, 0, stage)?;
    validate_selected_slot_payload(&payload)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    if exclusion.canonical_repository != payload.canonical_repository
        || exclusion.base_revision != payload.base_revision
        || exclusion.historical_patch_sha256 != payload.payload.patch_sha256
    {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 materialization exclusion crossed its selected payload boundary",
        ));
    }
    append_same_slot(
        journal,
        stage,
        materialization_exclusion_outcome(exclusion),
        Some(exclusion),
    )
}

pub fn checkpoint_historical_v2_test_materialization(
    journal: &mut HistoricalV2SlotStageJournal,
    materialization: &HistoricalV2Materialization,
    materialized_roots: &HistoricalV2MaterializedRoots,
    binding: Option<HistoricalV2TestMaterializationBinding<'_>>,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::TestMaterialization;
    require_completed_artifact(
        journal,
        1,
        HistoricalV2StageArtifactKind::Materialization,
        &materialization.materialization_sha256,
        stage,
    )?;
    validate_historical_v2_materialization(materialization, materialized_roots)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    let payload = stored_artifact::<HistoricalV2SelectedSlotPayloadArtifact>(journal, 0, stage)?;
    validate_selected_slot_payload(&payload)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    match (payload.payload.test_patch_sha256.as_deref(), binding) {
        (Some(expected_sha256), Some(binding)) => {
            validate_historical_v2_test_materialization(
                materialization,
                materialized_roots,
                expected_sha256,
                binding.artifact,
                binding.roots,
            )
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
            append_same_slot(
                journal,
                stage,
                HistoricalV2SlotStageOutcome::Completed {
                    artifact_kind: HistoricalV2StageArtifactKind::TestMaterialization,
                    artifact_sha256: binding.artifact.test_materialization_sha256.clone(),
                },
                Some(binding.artifact),
            )
        }
        (None, None) => {
            let artifact = prepare_historical_v2_no_test_patch(&payload, materialization)?;
            append_same_slot(
                journal,
                stage,
                HistoricalV2SlotStageOutcome::Completed {
                    artifact_kind: HistoricalV2StageArtifactKind::NoTestPatch,
                    artifact_sha256: artifact.artifact_sha256.clone(),
                },
                Some(&artifact),
            )
        }
        _ => Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 test materialization disagrees with its selected payload",
        )),
    }
}

pub fn checkpoint_historical_v2_test_materialization_exclusion(
    journal: &mut HistoricalV2SlotStageJournal,
    materialization: &HistoricalV2Materialization,
    materialized_roots: &HistoricalV2MaterializedRoots,
    exclusion: &HistoricalV2TestMaterializationExclusion,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::TestMaterialization;
    require_completed_artifact(
        journal,
        1,
        HistoricalV2StageArtifactKind::Materialization,
        &materialization.materialization_sha256,
        stage,
    )?;
    validate_historical_v2_materialization(materialization, materialized_roots)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    validate_historical_v2_test_materialization_exclusion(exclusion)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    let payload = stored_artifact::<HistoricalV2SelectedSlotPayloadArtifact>(journal, 0, stage)?;
    validate_selected_slot_payload(&payload)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    if payload.payload.test_patch_sha256.as_deref() != Some(&exclusion.test_patch_sha256)
        || exclusion.materialization_sha256 != materialization.materialization_sha256
    {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 test materialization exclusion crossed its selected payload boundary",
        ));
    }
    append_same_slot(
        journal,
        stage,
        test_materialization_exclusion_outcome(exclusion),
        Some(exclusion),
    )
}

pub fn checkpoint_historical_v2_source_census(
    journal: &mut HistoricalV2SlotStageJournal,
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    census: &HistoricalV2SourceCensus,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::SourceCensus;
    require_completed_artifact(
        journal,
        1,
        HistoricalV2StageArtifactKind::Materialization,
        &materialization.materialization_sha256,
        stage,
    )?;
    validate_historical_v2_source_census(materialization, roots, census)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(
        journal,
        stage,
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::SourceCensus,
            artifact_sha256: census.source_census_sha256.clone(),
        },
        Some(census),
    )
}

pub fn checkpoint_historical_v2_source_census_exclusion(
    journal: &mut HistoricalV2SlotStageJournal,
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    exclusion: &HistoricalV2SourceCensusExclusion,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::SourceCensus;
    require_completed_artifact(
        journal,
        1,
        HistoricalV2StageArtifactKind::Materialization,
        &materialization.materialization_sha256,
        stage,
    )?;
    validate_historical_v2_materialization(materialization, roots)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    validate_historical_v2_source_census_exclusion(exclusion)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    if exclusion.materialization_sha256 != materialization.materialization_sha256 {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 source exclusion crossed its materialization boundary",
        ));
    }
    match census_historical_v2_sources_typed(materialization, roots)? {
        HistoricalV2StageResult::Excluded(expected) if expected == *exclusion => {}
        HistoricalV2StageResult::Excluded(_) => {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 source exclusion changed from the exact materialized trees",
            ));
        }
        HistoricalV2StageResult::Completed(_) => {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 source exclusion is not reproduced by the materialized trees",
            ));
        }
    }
    append_same_slot(
        journal,
        stage,
        source_census_exclusion_outcome(exclusion),
        Some(exclusion),
    )
}

pub fn checkpoint_historical_v2_semantic_census(
    journal: &mut HistoricalV2SlotStageJournal,
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    census: &HistoricalV2SemanticCensus,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::SemanticCensus;
    require_completed_artifact(
        journal,
        1,
        HistoricalV2StageArtifactKind::Materialization,
        &materialization.materialization_sha256,
        stage,
    )?;
    require_completed_artifact(
        journal,
        3,
        HistoricalV2StageArtifactKind::SourceCensus,
        &source_census.source_census_sha256,
        stage,
    )?;
    validate_historical_v2_semantic_census_commitment(
        materialization,
        roots,
        source_census,
        census,
    )
    .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(
        journal,
        stage,
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::SemanticCensus,
            artifact_sha256: census.semantic_census_sha256.clone(),
        },
        Some(census),
    )
}

pub async fn checkpoint_historical_v2_semantic_census_exclusion(
    journal: &mut HistoricalV2SlotStageJournal,
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    exclusion: &HistoricalV2SemanticCensusExclusion,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::SemanticCensus;
    require_completed_artifact(
        journal,
        1,
        HistoricalV2StageArtifactKind::Materialization,
        &materialization.materialization_sha256,
        stage,
    )?;
    require_completed_artifact(
        journal,
        3,
        HistoricalV2StageArtifactKind::SourceCensus,
        &source_census.source_census_sha256,
        stage,
    )?;
    validate_historical_v2_semantic_census_exclusion(exclusion)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    if exclusion.materialization_sha256 != materialization.materialization_sha256
        || exclusion.source_census_sha256 != source_census.source_census_sha256
    {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 semantic exclusion crossed its source boundary",
        ));
    }
    match census_historical_v2_semantics_typed(materialization, roots, source_census).await? {
        HistoricalV2StageResult::Excluded(expected) if expected == *exclusion => {}
        HistoricalV2StageResult::Excluded(_) => {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 semantic exclusion changed on exact replay",
            ));
        }
        HistoricalV2StageResult::Completed(_) => {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 semantic exclusion is not reproduced by exact replay",
            ));
        }
    }
    append_same_slot(
        journal,
        stage,
        semantic_census_exclusion_outcome(exclusion),
        Some(exclusion),
    )
}

pub fn checkpoint_historical_v2_assessment_identity(
    journal: &mut HistoricalV2SlotStageJournal,
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::AssessmentIdentity;
    require_completed_artifact(
        journal,
        1,
        HistoricalV2StageArtifactKind::Materialization,
        &identity.materialization_sha256,
        stage,
    )?;
    require_completed_artifact(
        journal,
        3,
        HistoricalV2StageArtifactKind::SourceCensus,
        &identity.source_census_sha256,
        stage,
    )?;
    require_completed_artifact(
        journal,
        4,
        HistoricalV2StageArtifactKind::SemanticCensus,
        &identity.semantic_census_sha256,
        stage,
    )?;
    match identity.test_materialization_sha256.as_deref() {
        Some(test_materialization_sha256) => require_completed_artifact(
            journal,
            2,
            HistoricalV2StageArtifactKind::TestMaterialization,
            test_materialization_sha256,
            stage,
        )?,
        None => {
            require_completed_artifact_kind(
                journal,
                2,
                HistoricalV2StageArtifactKind::NoTestPatch,
                stage,
            )?;
            let no_patch = stored_artifact::<HistoricalV2NoTestPatchArtifact>(journal, 2, stage)?;
            validate_no_test_patch(&no_patch)
                .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
            if no_patch.materialization_sha256 != identity.materialization_sha256
                || no_patch.language != identity.language
                || no_patch.slot_number != identity.slot_number
                || no_patch.canonical_repository != identity.canonical_repository
            {
                return Err(HistoricalV2SlotStageError::invalid(
                    stage,
                    "historical-v2 no-test-patch artifact crossed its assessment identity",
                ));
            }
        }
    }
    validate_historical_v2_assessment_identity_commitment(inputs, identity)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(
        journal,
        stage,
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::AssessmentIdentity,
            artifact_sha256: identity.assessment_identity_sha256.clone(),
        },
        Some(identity),
    )
}

pub fn checkpoint_historical_v2_qualification(
    journal: &mut HistoricalV2SlotStageJournal,
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::Qualification;
    require_completed_artifact(
        journal,
        5,
        HistoricalV2StageArtifactKind::AssessmentIdentity,
        &identity.assessment_identity_sha256,
        stage,
    )?;
    validate_historical_v2_qualification_commitment(inputs, identity, qualification)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(
        journal,
        stage,
        qualification_outcome(qualification),
        Some(qualification),
    )
}

pub fn checkpoint_historical_v2_test_recipe(
    journal: &mut HistoricalV2SlotStageJournal,
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
    recipe: &HistoricalV2TestRecipe,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::TestRecipe;
    require_completed_artifact(
        journal,
        6,
        HistoricalV2StageArtifactKind::Qualification,
        &qualification.qualification_sha256,
        stage,
    )?;
    validate_historical_v2_test_recipe(inputs, identity, qualification, recipe)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(journal, stage, test_recipe_outcome(recipe), Some(recipe))
}

pub fn checkpoint_historical_v2_identical_test_execution(
    journal: &mut HistoricalV2SlotStageJournal,
    plan: &HistoricalV2IdenticalTestPlan,
    execution: &HistoricalV2IdenticalTestExecution,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::IdenticalTests;
    require_completed_artifact(
        journal,
        5,
        HistoricalV2StageArtifactKind::AssessmentIdentity,
        &plan.assessment_identity_sha256,
        stage,
    )?;
    require_completed_artifact(
        journal,
        6,
        HistoricalV2StageArtifactKind::Qualification,
        &plan.qualification_sha256,
        stage,
    )?;
    require_completed_artifact(
        journal,
        7,
        HistoricalV2StageArtifactKind::TestRecipe,
        &plan.test_recipe_sha256,
        stage,
    )?;
    validate_historical_v2_identical_test_execution(plan, execution)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(
        journal,
        stage,
        identical_test_outcome(execution),
        Some(execution),
    )
}

pub fn checkpoint_historical_v2_ready_for_review(
    journal: &mut HistoricalV2SlotStageJournal,
    plan: &HistoricalV2IdenticalTestPlan,
    execution: &HistoricalV2IdenticalTestExecution,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::ReadyForReview;
    require_completed_artifact(
        journal,
        8,
        HistoricalV2StageArtifactKind::IdenticalTestExecution,
        &execution.execution_sha256,
        stage,
    )?;
    validate_historical_v2_identical_test_execution(plan, execution)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    if !matches!(execution.outcome, HistoricalV2IdenticalTestOutcome::Passed) {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 excluded execution cannot become ready for review",
        ));
    }
    append_same_slot::<serde_json::Value>(
        journal,
        stage,
        HistoricalV2SlotStageOutcome::ReadyForReview,
        None,
    )
}

#[path = "benchmark_history_v2_stage_adapters_support.rs"]
mod support;

use support::*;
#[cfg(test)]
#[path = "benchmark_history_v2_stage_adapters_tests.rs"]
mod tests;
