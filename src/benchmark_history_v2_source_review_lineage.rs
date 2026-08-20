use super::*;
use serde::de::DeserializeOwned;
use std::fs;

pub(super) fn validate_ready_slot<'a>(
    inputs: &'a HistoricalV2SourceReviewBundleInputs<'a>,
    history: &'a [HistoricalV2StoredSlotStage],
) -> Result<PreparedReviewSlot<'a>, String> {
    let protocol = validate_historical_v2_protocol(inputs.protocol_bytes)?;
    validate_review_contract(&protocol)?;
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
    let checkpoints = history
        .iter()
        .map(|stage| stage.checkpoint.clone())
        .collect::<Vec<_>>();
    validate_historical_v2_slot_stage_history(&checkpoints)?;
    require_ready_history(inputs, history)?;

    let first = &history[0].checkpoint;
    let payload: HistoricalV2SelectedSlotPayloadArtifact =
        stage_artifact(history, 0, HistoricalV2StageArtifactKind::SelectedPayload)?;
    validate_payload(inputs, first, history, &payload)?;
    let selected_payload = selected_payload(inputs)?;

    let materialization: HistoricalV2Materialization =
        stage_artifact(history, 1, HistoricalV2StageArtifactKind::Materialization)?;
    let source_census: HistoricalV2SourceCensus =
        stage_artifact(history, 3, HistoricalV2StageArtifactKind::SourceCensus)?;
    let semantic_census: HistoricalV2SemanticCensus =
        stage_artifact(history, 4, HistoricalV2StageArtifactKind::SemanticCensus)?;
    let assessment: HistoricalV2AssessmentIdentity = stage_artifact(
        history,
        5,
        HistoricalV2StageArtifactKind::AssessmentIdentity,
    )?;
    let qualification: HistoricalV2Qualification =
        stage_artifact(history, 6, HistoricalV2StageArtifactKind::Qualification)?;
    let recipe: HistoricalV2TestRecipe =
        stage_artifact(history, 7, HistoricalV2StageArtifactKind::TestRecipe)?;
    let execution: HistoricalV2IdenticalTestExecution = stage_artifact(
        history,
        8,
        HistoricalV2StageArtifactKind::IdenticalTestExecution,
    )?;
    validate_artifact_hashes(
        history,
        &materialization,
        &source_census,
        &semantic_census,
        &assessment,
        &qualification,
        &recipe,
        &execution,
    )?;

    let slot_root = inputs
        .work_root
        .join(inputs.language)
        .join(format!("slot-{:04}", inputs.slot_number));
    let roots = HistoricalV2MaterializedRoots {
        repository_root: slot_root.join("repository"),
        base_root: slot_root.join("repository"),
        patched_root: slot_root.join("patched"),
    };
    validate_historical_v2_materialization(&materialization, &roots)?;
    validate_historical_v2_semantic_census_commitment(
        &materialization,
        &roots,
        &source_census,
        &semantic_census,
    )?;

    let test_materialization = validate_test_materialization_stage(
        inputs,
        history,
        &payload,
        selected_payload,
        &materialization,
        &roots,
        &slot_root,
    )?;
    let assessment_inputs = HistoricalV2AssessmentIdentityInputs {
        protocol_bytes: inputs.protocol_bytes,
        artifact_root: inputs.artifact_root,
        frame: inputs.frame,
        exclusions: inputs.exclusions,
        selection: inputs.selection,
        payloads: inputs.payloads,
        language: inputs.language,
        slot_number: inputs.slot_number,
        materialization: &materialization,
        materialized_roots: &roots,
        test_materialization: test_materialization
            .as_ref()
            .map(|(artifact, roots)| HistoricalV2TestMaterializationBinding { artifact, roots }),
        source_census: &source_census,
        semantic_census: &semantic_census,
    };
    validate_historical_v2_assessment_identity_commitment(&assessment_inputs, &assessment)?;
    validate_historical_v2_qualification_commitment(
        &assessment_inputs,
        &assessment,
        &qualification,
    )?;
    if !matches!(
        qualification.outcome,
        HistoricalV2QualificationOutcome::Qualified
    ) || !qualification.public_surface.preserved
        || qualification.changed_methods.is_empty()
    {
        return Err("historical-v2 review slot is not a qualified simplification".into());
    }
    validate_historical_v2_test_recipe(&assessment_inputs, &assessment, &qualification, &recipe)?;
    let plan = prepare_historical_v2_identical_test_plan(
        &assessment_inputs,
        &assessment,
        &qualification,
        &recipe,
        inputs.harness_repository_root,
    )?;
    validate_historical_v2_identical_test_execution(&plan, &execution)?;
    if !matches!(execution.outcome, HistoricalV2IdenticalTestOutcome::Passed) {
        return Err("historical-v2 review behavior evidence did not pass".into());
    }

    let repository_url = format!("https://github.com/{}.git", payload.canonical_repository);
    let before_inventory = inventory_intentional_boundary_repository(
        &repository_url,
        &materialization.base_revision,
        &roots.base_root,
    )?;
    let after_inventory = inventory_intentional_boundary_repository(
        &repository_url,
        &materialization.patched_commit_oid,
        &roots.patched_root,
    )?;
    if before_inventory.inventory_sha256 != source_census.base.inventory_sha256
        || after_inventory.inventory_sha256 != source_census.patched.inventory_sha256
    {
        return Err("historical-v2 review Git inventories changed after source census".into());
    }
    Ok(PreparedReviewSlot {
        protocol,
        selection_sha256: &inputs.selection.selection_sha256,
        language: inputs.language,
        terminal_checkpoint_sha256: &history[9].checkpoint.checkpoint_sha256,
        roots,
        materialization,
        source_census,
        assessment,
        qualification,
        plan,
        execution,
        before_inventory,
        after_inventory,
    })
}

fn require_ready_history(
    inputs: &HistoricalV2SourceReviewBundleInputs<'_>,
    history: &[HistoricalV2StoredSlotStage],
) -> Result<(), String> {
    if history.len() != 10
        || history.last().map(|stage| stage.checkpoint.stage)
            != Some(HistoricalV2SlotStage::ReadyForReview)
        || !matches!(
            history.last().map(|stage| &stage.checkpoint.outcome),
            Some(HistoricalV2SlotStageOutcome::ReadyForReview)
        )
    {
        return Err(
            "historical-v2 source review requires a terminal ready-for-review journal".into(),
        );
    }
    let first = &history[0].checkpoint;
    if first.selection_sha256 != inputs.selection.selection_sha256
        || first.language != inputs.language
        || first.slot_number != inputs.slot_number
    {
        return Err("historical-v2 review slot crossed its frozen selection identity".into());
    }
    Ok(())
}

fn validate_payload(
    inputs: &HistoricalV2SourceReviewBundleInputs<'_>,
    first: &HistoricalV2SlotStageCheckpoint,
    history: &[HistoricalV2StoredSlotStage],
    payload: &HistoricalV2SelectedSlotPayloadArtifact,
) -> Result<(), String> {
    let mut committed_payload = payload.clone();
    committed_payload.artifact_sha256.clear();
    if payload.artifact_sha256 != review_hash_json(&committed_payload)?
        || payload.artifact_sha256 != completed_sha256(history, 0)?
        || payload.selection_sha256 != inputs.selection.selection_sha256
        || payload.language != inputs.language
        || payload.slot_number != inputs.slot_number
        || payload.canonical_repository != first.canonical_repository
    {
        return Err("historical-v2 review payload lineage changed".into());
    }
    let selected_payload = selected_payload(inputs)?;
    let selected_slot = inputs
        .selection
        .slots
        .iter()
        .find(|slot| slot.language == inputs.language && slot.slot_number == inputs.slot_number)
        .ok_or_else(|| "historical-v2 review selected slot disappeared".to_string())?;
    let HistoricalV2SlotOutcome::Selected {
        global_row_index,
        instance_id,
        canonical_repository,
        pull_number,
        base_revision,
        patch_sha256,
        rank_sha256,
    } = &selected_slot.outcome
    else {
        return Err("historical-v2 review slot was not selected".into());
    };
    if payload.payload != *selected_payload
        || payload.global_row_index != *global_row_index
        || payload.instance_id != *instance_id
        || payload.canonical_repository != *canonical_repository
        || payload.pull_number != *pull_number
        || payload.base_revision != *base_revision
        || payload.payload.patch_sha256 != *patch_sha256
        || payload.rank_sha256 != *rank_sha256
    {
        return Err("historical-v2 review payload differs from the frozen selected slot".into());
    }
    Ok(())
}

fn selected_payload<'a>(
    inputs: &'a HistoricalV2SourceReviewBundleInputs<'_>,
) -> Result<&'a HistoricalV2SelectedPayload, String> {
    inputs
        .payloads
        .records
        .iter()
        .find(|record| {
            record.language == inputs.language && record.slot_number == inputs.slot_number
        })
        .ok_or_else(|| "historical-v2 review selected payload disappeared".to_string())
}

#[allow(clippy::too_many_arguments)]
fn validate_test_materialization_stage(
    inputs: &HistoricalV2SourceReviewBundleInputs<'_>,
    history: &[HistoricalV2StoredSlotStage],
    payload: &HistoricalV2SelectedSlotPayloadArtifact,
    selected_payload: &HistoricalV2SelectedPayload,
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    slot_root: &std::path::Path,
) -> Result<
    Option<(
        HistoricalV2TestMaterialization,
        HistoricalV2TestMaterializedRoots,
    )>,
    String,
> {
    match history[2].checkpoint.outcome {
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::NoTestPatch,
            ..
        } => {
            let artifact: HistoricalV2NoTestPatchArtifact = artifact_value(&history[2])?;
            let mut committed_artifact = artifact.clone();
            committed_artifact.artifact_sha256.clear();
            if selected_payload.test_patch.is_some()
                || selected_payload.test_patch_sha256.is_some()
                || artifact.schema_version != HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION
                || artifact.artifact_contract != "sniffbench-historical-v2-no-test-patch-v1"
                || artifact.selected_slot_payload_sha256 != payload.artifact_sha256
                || artifact.materialization_sha256 != materialization.materialization_sha256
                || artifact.language != inputs.language
                || artifact.slot_number != inputs.slot_number
                || artifact.canonical_repository != payload.canonical_repository
                || artifact.artifact_sha256 != review_hash_json(&committed_artifact)?
                || artifact.artifact_sha256 != completed_sha256(history, 2)?
            {
                return Err("historical-v2 no-test-patch review artifact changed".into());
            }
            Ok(None)
        }
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::TestMaterialization,
            ..
        } => {
            let artifact: HistoricalV2TestMaterialization = artifact_value(&history[2])?;
            let test_roots = HistoricalV2TestMaterializedRoots {
                base_test_root: slot_root.join("base-tested"),
                patched_test_root: slot_root.join("patched-tested"),
            };
            validate_historical_v2_test_materialization(
                materialization,
                roots,
                selected_payload
                    .test_patch_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        "historical-v2 test materialization has no committed test patch".to_string()
                    })?,
                &artifact,
                &test_roots,
            )?;
            Ok(Some((artifact, test_roots)))
        }
        _ => Err("historical-v2 review test-materialization stage changed".into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_artifact_hashes(
    history: &[HistoricalV2StoredSlotStage],
    materialization: &HistoricalV2Materialization,
    source: &HistoricalV2SourceCensus,
    semantic: &HistoricalV2SemanticCensus,
    assessment: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
    recipe: &HistoricalV2TestRecipe,
    execution: &HistoricalV2IdenticalTestExecution,
) -> Result<(), String> {
    let actual = [
        (1, materialization.materialization_sha256.as_str()),
        (3, source.source_census_sha256.as_str()),
        (4, semantic.semantic_census_sha256.as_str()),
        (5, assessment.assessment_identity_sha256.as_str()),
        (6, qualification.qualification_sha256.as_str()),
        (7, recipe.test_recipe_sha256.as_str()),
        (8, execution.execution_sha256.as_str()),
    ];
    if actual
        .into_iter()
        .any(|(index, sha)| completed_sha256(history, index).as_deref() != Ok(sha))
    {
        return Err("historical-v2 review prerequisite artifact hash changed".into());
    }
    Ok(())
}

fn stage_artifact<T: DeserializeOwned>(
    history: &[HistoricalV2StoredSlotStage],
    index: usize,
    kind: HistoricalV2StageArtifactKind,
) -> Result<T, String> {
    let stored = history
        .get(index)
        .ok_or_else(|| "historical-v2 review prerequisite stage is missing".to_string())?;
    if !matches!(
        stored.checkpoint.outcome,
        HistoricalV2SlotStageOutcome::Completed { artifact_kind, .. } if artifact_kind == kind
    ) {
        return Err("historical-v2 review prerequisite stage kind changed".into());
    }
    artifact_value(stored)
}

fn artifact_value<T: DeserializeOwned>(stored: &HistoricalV2StoredSlotStage) -> Result<T, String> {
    serde_json::from_value(
        stored
            .artifact
            .clone()
            .ok_or_else(|| "historical-v2 review prerequisite artifact is missing".to_string())?,
    )
    .map_err(|error| format!("invalid historical-v2 review prerequisite artifact: {error}"))
}

fn completed_sha256(history: &[HistoricalV2StoredSlotStage], index: usize) -> Result<&str, String> {
    match history.get(index).map(|stage| &stage.checkpoint.outcome) {
        Some(HistoricalV2SlotStageOutcome::Completed {
            artifact_sha256, ..
        }) => Ok(artifact_sha256),
        _ => Err("historical-v2 review prerequisite did not complete".into()),
    }
}

fn validate_review_contract(protocol: &ValidatedHistoricalV2Protocol) -> Result<(), String> {
    let review = &protocol.protocol.review;
    if !review.source_only_review
        || review.independent_reviewers != 2
        || !review.reviewers_must_not_see_sniff_output
        || !review.reviewers_must_not_see_each_other_labels
        || !review.exact_before_slop_mechanism_required
        || !review.exact_after_removal_required
        || !review.historical_patch_must_match_simpler_counterfactual
        || !review.behavior_evidence_required
        || !review.distinct_dispute_resolver
        || !review.rejected_label_closes_slot
        || !review.underfilled_language_fails_release
    {
        return Err("historical-v2 source-review protocol changed".into());
    }
    Ok(())
}

pub(super) fn require_existing_slot(
    inputs: &HistoricalV2SourceReviewBundleInputs<'_>,
) -> Result<(), String> {
    for (path, label) in [
        (inputs.state_root, "state root"),
        (inputs.work_root, "work root"),
        (inputs.harness_repository_root, "harness repository root"),
    ] {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("failed to inspect historical-v2 review {label}: {error}"))?;
        if !path.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "historical-v2 review {label} must be an existing absolute plain directory"
            ));
        }
    }
    let slot = inputs
        .state_root
        .join(inputs.language)
        .join(format!("slot-{:04}", inputs.slot_number));
    let metadata = fs::symlink_metadata(&slot)
        .map_err(|error| format!("historical-v2 review slot journal is missing: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("historical-v2 review slot journal is not a plain directory".into());
    }
    Ok(())
}
