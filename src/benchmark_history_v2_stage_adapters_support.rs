use super::*;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub(super) fn append_same_slot<T: Serialize>(
    journal: &mut HistoricalV2SlotStageJournal,
    stage: HistoricalV2SlotStage,
    outcome: HistoricalV2SlotStageOutcome,
    artifact: Option<&T>,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let first = journal.history().first().ok_or_else(|| {
        HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 slot journal has no payload identity",
        )
    })?;
    let selection_sha256 = first.checkpoint.selection_sha256.clone();
    let language = first.checkpoint.language.clone();
    let slot_number = first.checkpoint.slot_number;
    let canonical_repository = first.checkpoint.canonical_repository.clone();
    journal.append(
        HistoricalV2SlotStageCheckpointInput {
            selection_sha256: &selection_sha256,
            language: &language,
            slot_number,
            canonical_repository: &canonical_repository,
            stage,
            outcome,
        },
        artifact,
    )
}

pub(super) fn qualification_outcome(
    qualification: &HistoricalV2Qualification,
) -> HistoricalV2SlotStageOutcome {
    match &qualification.outcome {
        HistoricalV2QualificationOutcome::Qualified => HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::Qualification,
            artifact_sha256: qualification.qualification_sha256.clone(),
        },
        HistoricalV2QualificationOutcome::Excluded { reasons } => {
            HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::Qualification(reasons.clone()),
                artifact_kind: HistoricalV2StageArtifactKind::Qualification,
                artifact_sha256: qualification.qualification_sha256.clone(),
            }
        }
    }
}

pub(super) fn materialization_exclusion_outcome(
    exclusion: &HistoricalV2MaterializationExclusion,
) -> HistoricalV2SlotStageOutcome {
    HistoricalV2SlotStageOutcome::Excluded {
        reason: HistoricalV2TerminalExclusionReason::Materialization(exclusion.reason),
        artifact_kind: HistoricalV2StageArtifactKind::MaterializationExclusion,
        artifact_sha256: exclusion.exclusion_sha256.clone(),
    }
}

pub(super) fn test_materialization_exclusion_outcome(
    exclusion: &HistoricalV2TestMaterializationExclusion,
) -> HistoricalV2SlotStageOutcome {
    HistoricalV2SlotStageOutcome::Excluded {
        reason: HistoricalV2TerminalExclusionReason::TestMaterialization(exclusion.reason),
        artifact_kind: HistoricalV2StageArtifactKind::TestMaterializationExclusion,
        artifact_sha256: exclusion.exclusion_sha256.clone(),
    }
}

pub(super) fn source_census_exclusion_outcome(
    exclusion: &HistoricalV2SourceCensusExclusion,
) -> HistoricalV2SlotStageOutcome {
    HistoricalV2SlotStageOutcome::Excluded {
        reason: HistoricalV2TerminalExclusionReason::SourceCensus(exclusion.reasons.clone()),
        artifact_kind: HistoricalV2StageArtifactKind::SourceCensusExclusion,
        artifact_sha256: exclusion.exclusion_sha256.clone(),
    }
}

pub(super) fn test_recipe_outcome(recipe: &HistoricalV2TestRecipe) -> HistoricalV2SlotStageOutcome {
    match &recipe.outcome {
        HistoricalV2TestRecipeOutcome::Selected { .. } => HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::TestRecipe,
            artifact_sha256: recipe.test_recipe_sha256.clone(),
        },
        HistoricalV2TestRecipeOutcome::Excluded { reason } => {
            HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::TestRecipe(*reason),
                artifact_kind: HistoricalV2StageArtifactKind::TestRecipe,
                artifact_sha256: recipe.test_recipe_sha256.clone(),
            }
        }
    }
}

pub(super) fn identical_test_outcome(
    execution: &HistoricalV2IdenticalTestExecution,
) -> HistoricalV2SlotStageOutcome {
    match &execution.outcome {
        HistoricalV2IdenticalTestOutcome::Passed => HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::IdenticalTestExecution,
            artifact_sha256: execution.execution_sha256.clone(),
        },
        HistoricalV2IdenticalTestOutcome::Excluded { reason } => {
            HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::IdenticalTests(reason.clone()),
                artifact_kind: HistoricalV2StageArtifactKind::IdenticalTestExecution,
                artifact_sha256: execution.execution_sha256.clone(),
            }
        }
    }
}

pub(super) fn selected_slot_payload(
    inputs: &HistoricalV2PayloadStageInputs<'_>,
) -> Result<HistoricalV2SelectedSlotPayloadArtifact, String> {
    let slot = inputs
        .selection
        .slots
        .iter()
        .find(|slot| slot.language == inputs.language && slot.slot_number == inputs.slot_number)
        .ok_or_else(|| "historical-v2 payload checkpoint slot is missing".to_string())?;
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
        return Err("historical-v2 payload checkpoint requires a selected slot".to_string());
    };
    let payload = inputs
        .payloads
        .records
        .iter()
        .find(|payload| {
            payload.language == inputs.language && payload.slot_number == inputs.slot_number
        })
        .ok_or_else(|| "historical-v2 selected payload is missing".to_string())?;
    if payload.global_row_index != *global_row_index
        || payload.instance_id != *instance_id
        || payload.patch_sha256 != *patch_sha256
    {
        return Err("historical-v2 payload checkpoint crossed its fixed slot".to_string());
    }
    Ok(HistoricalV2SelectedSlotPayloadArtifact {
        schema_version: HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION,
        artifact_contract: SELECTED_PAYLOAD_CONTRACT.to_string(),
        selection_sha256: inputs.selection.selection_sha256.clone(),
        language: inputs.language.to_string(),
        slot_number: inputs.slot_number,
        global_row_index: *global_row_index,
        instance_id: instance_id.clone(),
        canonical_repository: canonical_repository.clone(),
        pull_number: *pull_number,
        base_revision: base_revision.clone(),
        rank_sha256: rank_sha256.clone(),
        payload: payload.clone(),
        artifact_sha256: String::new(),
    })
}

pub(super) fn seal_selected_slot_payload(
    mut artifact: HistoricalV2SelectedSlotPayloadArtifact,
) -> Result<HistoricalV2SelectedSlotPayloadArtifact, String> {
    if !artifact.artifact_sha256.is_empty() {
        return Err("historical-v2 selected slot payload is already sealed".to_string());
    }
    artifact.artifact_sha256 = selected_slot_payload_sha256(&artifact)?;
    validate_selected_slot_payload(&artifact)?;
    Ok(artifact)
}

pub(super) fn validate_selected_slot_payload(
    artifact: &HistoricalV2SelectedSlotPayloadArtifact,
) -> Result<(), String> {
    if artifact.schema_version != HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION
        || artifact.artifact_contract != SELECTED_PAYLOAD_CONTRACT
        || !valid_sha256(&artifact.selection_sha256)
        || !valid_sha256(&artifact.rank_sha256)
        || artifact.base_revision.len() != 40
        || !artifact
            .base_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || artifact.slot_number == 0
        || artifact.language != artifact.payload.language
        || artifact.slot_number != artifact.payload.slot_number
        || artifact.global_row_index != artifact.payload.global_row_index
        || artifact.instance_id != artifact.payload.instance_id
        || artifact.artifact_sha256 != selected_slot_payload_sha256(artifact)?
    {
        return Err("historical-v2 selected slot payload commitment changed".to_string());
    }
    Ok(())
}

pub(super) fn seal_no_test_patch(
    mut artifact: HistoricalV2NoTestPatchArtifact,
) -> Result<HistoricalV2NoTestPatchArtifact, String> {
    if !artifact.artifact_sha256.is_empty() {
        return Err("historical-v2 no-test-patch artifact is already sealed".to_string());
    }
    artifact.artifact_sha256 = no_test_patch_sha256(&artifact)?;
    validate_no_test_patch(&artifact)?;
    Ok(artifact)
}

pub(super) fn validate_no_test_patch(
    artifact: &HistoricalV2NoTestPatchArtifact,
) -> Result<(), String> {
    if artifact.schema_version != HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION
        || artifact.artifact_contract != NO_TEST_PATCH_CONTRACT
        || !valid_sha256(&artifact.selected_slot_payload_sha256)
        || !valid_sha256(&artifact.materialization_sha256)
        || artifact.slot_number == 0
        || artifact.artifact_sha256 != no_test_patch_sha256(artifact)?
    {
        return Err("historical-v2 no-test-patch commitment changed".to_string());
    }
    Ok(())
}

pub(super) fn selected_slot_payload_sha256(
    artifact: &HistoricalV2SelectedSlotPayloadArtifact,
) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.artifact_sha256.clear();
    hash_json(&committed)
}

pub(super) fn no_test_patch_sha256(
    artifact: &HistoricalV2NoTestPatchArtifact,
) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.artifact_sha256.clear();
    hash_json(&committed)
}

pub(super) fn require_completed_artifact(
    journal: &HistoricalV2SlotStageJournal,
    index: usize,
    expected_kind: HistoricalV2StageArtifactKind,
    expected_sha256: &str,
    stage: HistoricalV2SlotStage,
) -> Result<(), HistoricalV2SlotStageError> {
    let checkpoint = journal
        .history()
        .get(index)
        .map(|stored| &stored.checkpoint)
        .ok_or_else(|| {
            HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 prerequisite stage checkpoint is missing",
            )
        })?;
    if matches!(
        &checkpoint.outcome,
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind,
            artifact_sha256,
        } if *artifact_kind == expected_kind && artifact_sha256 == expected_sha256
    ) {
        Ok(())
    } else {
        Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 prerequisite stage commitment changed",
        ))
    }
}

pub(super) fn require_completed_artifact_kind(
    journal: &HistoricalV2SlotStageJournal,
    index: usize,
    expected_kind: HistoricalV2StageArtifactKind,
    stage: HistoricalV2SlotStage,
) -> Result<(), HistoricalV2SlotStageError> {
    let checkpoint = journal
        .history()
        .get(index)
        .map(|stored| &stored.checkpoint)
        .ok_or_else(|| {
            HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 prerequisite stage checkpoint is missing",
            )
        })?;
    if matches!(
        &checkpoint.outcome,
        HistoricalV2SlotStageOutcome::Completed { artifact_kind, .. }
            if *artifact_kind == expected_kind
    ) {
        Ok(())
    } else {
        Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 prerequisite stage kind changed",
        ))
    }
}

pub(super) fn stored_artifact<T: DeserializeOwned>(
    journal: &HistoricalV2SlotStageJournal,
    index: usize,
    stage: HistoricalV2SlotStage,
) -> Result<T, HistoricalV2SlotStageError> {
    let value = journal
        .history()
        .get(index)
        .and_then(|stored| stored.artifact.clone())
        .ok_or_else(|| {
            HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 prerequisite stage artifact is missing",
            )
        })?;
    serde_json::from_value(value).map_err(|error| {
        HistoricalV2SlotStageError::invalid(
            stage,
            format!("invalid historical-v2 prerequisite stage artifact: {error}"),
        )
    })
}

pub(super) fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 stage artifact: {error}"))
}

pub(super) fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
