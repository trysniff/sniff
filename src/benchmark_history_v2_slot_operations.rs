use super::history_v2_slot_operations_support::*;
use super::history_v2_stage_adapters::{
    prepare_historical_v2_no_test_patch, prepare_historical_v2_selected_slot_payload,
};
use super::history_v2_test_materialization::recover_historical_v2_test_materialization;
use super::{
    HistoricalV2AssessmentIdentity, HistoricalV2IdenticalTestExecution,
    HistoricalV2IdenticalTestOutcome, HistoricalV2Materialization, HistoricalV2MaterializedRoots,
    HistoricalV2NoTestPatchArtifact, HistoricalV2PayloadStageInputs, HistoricalV2PreparedStage,
    HistoricalV2Qualification, HistoricalV2QualificationOutcome,
    HistoricalV2RecoverableTestExecutor, HistoricalV2SelectedSlotPayloadArtifact,
    HistoricalV2SlotStage, HistoricalV2SlotStageContext, HistoricalV2SlotStageError,
    HistoricalV2SlotStageExecutor, HistoricalV2SlotStageFuture, HistoricalV2SlotStageOutcome,
    HistoricalV2SourceCensus, HistoricalV2StageArtifactKind, HistoricalV2StageResult,
    HistoricalV2TerminalExclusionReason, HistoricalV2TestMaterializedRoots, HistoricalV2TestRecipe,
    HistoricalV2TestRecipeOutcome, bind_historical_v2_assessment_identity,
    census_historical_v2_semantics_typed, census_historical_v2_sources_typed,
    execute_historical_v2_identical_tests, materialize_historical_v2_repository_typed,
    materialize_historical_v2_test_snapshots_typed, prepare_historical_v2_identical_test_plan,
    prepare_historical_v2_test_recipe, qualify_historical_v2_assessment,
    validate_historical_v2_identical_test_execution, validate_historical_v2_materialization,
};
use reqwest::Client;
use std::path::{Path, PathBuf};

pub struct HistoricalV2SlotOperations<'a, E> {
    client: &'a Client,
    payload_inputs: HistoricalV2PayloadStageInputs<'a>,
    selected_payload: HistoricalV2SelectedSlotPayloadArtifact,
    work_root: PathBuf,
    harness_repository_root: &'a Path,
    test_executor: &'a E,
}

impl<'a, E: HistoricalV2RecoverableTestExecutor> HistoricalV2SlotOperations<'a, E> {
    pub fn new(
        client: &'a Client,
        payload_inputs: HistoricalV2PayloadStageInputs<'a>,
        work_root: &Path,
        harness_repository_root: &'a Path,
        test_executor: &'a E,
    ) -> Result<Self, HistoricalV2SlotStageError> {
        let selected_payload = prepare_historical_v2_selected_slot_payload(&payload_inputs)?;
        let work_root = canonical_work_root(
            work_root,
            payload_inputs.language,
            payload_inputs.slot_number,
        )?;
        Ok(Self {
            client,
            payload_inputs,
            selected_payload,
            work_root,
            harness_repository_root,
            test_executor,
        })
    }

    async fn execute_stage(
        &mut self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        self.require_identity(context)?;
        match context.stage {
            HistoricalV2SlotStage::Payload => self.payload_stage(),
            HistoricalV2SlotStage::Materialization => self.materialization_stage(context).await,
            HistoricalV2SlotStage::TestMaterialization => self.test_materialization_stage(context),
            HistoricalV2SlotStage::SourceCensus => self.source_census_stage(context),
            HistoricalV2SlotStage::SemanticCensus => self.semantic_census_stage(context).await,
            HistoricalV2SlotStage::AssessmentIdentity => self.assessment_identity_stage(context),
            HistoricalV2SlotStage::Qualification => self.qualification_stage(context),
            HistoricalV2SlotStage::TestRecipe => self.test_recipe_stage(context),
            HistoricalV2SlotStage::IdenticalTests => self.identical_tests_stage(context),
            HistoricalV2SlotStage::ReadyForReview => self.ready_for_review_stage(context),
        }
    }

    async fn recover_stage(
        &mut self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<(), HistoricalV2SlotStageError> {
        self.require_identity(context)?;
        match context.stage {
            HistoricalV2SlotStage::Materialization => self.recover_materialization(),
            HistoricalV2SlotStage::TestMaterialization => {
                let materialization = artifact(context, 1)?;
                recover_historical_v2_test_materialization(
                    &materialization,
                    &self.materialized_roots(),
                )
                .map(|_| ())
            }
            HistoricalV2SlotStage::SemanticCensus => {
                let materialization: HistoricalV2Materialization = artifact(context, 1)?;
                let roots = self.materialized_roots();
                validate_historical_v2_materialization(&materialization, &roots)
                    .map_err(|detail| invalid(context.stage, detail))?;
                for root in [&roots.base_root, &roots.patched_root] {
                    crate::semantic_indexer_runner::recover_interrupted_semantic_indexing(root)
                        .map_err(|detail| infrastructure(context.stage, detail))?;
                }
                Ok(())
            }
            HistoricalV2SlotStage::IdenticalTests => {
                let state = self.assessment_state(context)?;
                let identity: HistoricalV2AssessmentIdentity = artifact(context, 5)?;
                let qualification: HistoricalV2Qualification = artifact(context, 6)?;
                let recipe: HistoricalV2TestRecipe = artifact(context, 7)?;
                let plan = prepare_historical_v2_identical_test_plan(
                    &state.inputs(&self.payload_inputs),
                    &identity,
                    &qualification,
                    &recipe,
                    self.harness_repository_root,
                )
                .map_err(|detail| invalid(context.stage, detail))?;
                self.test_executor
                    .recover(&plan)
                    .map_err(slot_execution_error)
            }
            _ => Ok(()),
        }
    }

    fn payload_stage(&self) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        completed(
            HistoricalV2StageArtifactKind::SelectedPayload,
            &self.selected_payload.artifact_sha256,
            &self.selected_payload,
            HistoricalV2SlotStage::Payload,
        )
    }

    async fn materialization_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let payload: HistoricalV2SelectedSlotPayloadArtifact = artifact(context, 0)?;
        match materialize_historical_v2_repository_typed(
            self.client,
            &payload.canonical_repository,
            &payload.base_revision,
            &payload.payload.patch,
            &payload.payload.patch_sha256,
            &self.slot_root(),
        )
        .await?
        {
            HistoricalV2StageResult::Completed((value, _)) => completed(
                HistoricalV2StageArtifactKind::Materialization,
                &value.materialization_sha256,
                &value,
                context.stage,
            ),
            HistoricalV2StageResult::Excluded(value) => {
                materialization_excluded(value, context.stage)
            }
        }
    }

    fn test_materialization_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let payload: HistoricalV2SelectedSlotPayloadArtifact = artifact(context, 0)?;
        let materialization: HistoricalV2Materialization = artifact(context, 1)?;
        match (
            payload.payload.test_patch.as_deref(),
            payload.payload.test_patch_sha256.as_deref(),
        ) {
            (Some(patch), Some(sha256)) => match materialize_historical_v2_test_snapshots_typed(
                &materialization,
                &self.materialized_roots(),
                patch,
                sha256,
            )? {
                HistoricalV2StageResult::Completed((value, _)) => completed(
                    HistoricalV2StageArtifactKind::TestMaterialization,
                    &value.test_materialization_sha256,
                    &value,
                    context.stage,
                ),
                HistoricalV2StageResult::Excluded(value) => {
                    test_materialization_excluded(value, context.stage)
                }
            },
            (None, None) => {
                let value = prepare_historical_v2_no_test_patch(&payload, &materialization)?;
                completed(
                    HistoricalV2StageArtifactKind::NoTestPatch,
                    &value.artifact_sha256,
                    &value,
                    context.stage,
                )
            }
            _ => Err(invalid(
                context.stage,
                "historical-v2 test patch payload is internally inconsistent",
            )),
        }
    }

    fn source_census_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let materialization: HistoricalV2Materialization = artifact(context, 1)?;
        match census_historical_v2_sources_typed(&materialization, &self.materialized_roots())? {
            HistoricalV2StageResult::Completed(value) => completed(
                HistoricalV2StageArtifactKind::SourceCensus,
                &value.source_census_sha256,
                &value,
                context.stage,
            ),
            HistoricalV2StageResult::Excluded(value) => {
                source_census_excluded(value, context.stage)
            }
        }
    }

    async fn semantic_census_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let materialization: HistoricalV2Materialization = artifact(context, 1)?;
        let source: HistoricalV2SourceCensus = artifact(context, 3)?;
        match census_historical_v2_semantics_typed(
            &materialization,
            &self.materialized_roots(),
            &source,
        )
        .await?
        {
            HistoricalV2StageResult::Completed(value) => completed(
                HistoricalV2StageArtifactKind::SemanticCensus,
                &value.semantic_census_sha256,
                &value,
                context.stage,
            ),
            HistoricalV2StageResult::Excluded(value) => {
                semantic_census_excluded(value, context.stage)
            }
        }
    }

    fn assessment_identity_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let state = self.assessment_state(context)?;
        let value = bind_historical_v2_assessment_identity(&state.inputs(&self.payload_inputs))
            .map_err(|detail| invalid(context.stage, detail))?;
        completed(
            HistoricalV2StageArtifactKind::AssessmentIdentity,
            &value.assessment_identity_sha256,
            &value,
            context.stage,
        )
    }

    fn qualification_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let state = self.assessment_state(context)?;
        let identity: HistoricalV2AssessmentIdentity = artifact(context, 5)?;
        let value =
            qualify_historical_v2_assessment(&state.inputs(&self.payload_inputs), &identity)
                .map_err(|detail| invalid(context.stage, detail))?;
        match &value.outcome {
            HistoricalV2QualificationOutcome::Qualified => completed(
                HistoricalV2StageArtifactKind::Qualification,
                &value.qualification_sha256,
                &value,
                context.stage,
            ),
            HistoricalV2QualificationOutcome::Excluded { reasons } => excluded(
                HistoricalV2TerminalExclusionReason::Qualification(reasons.clone()),
                HistoricalV2StageArtifactKind::Qualification,
                &value.qualification_sha256,
                &value,
                context.stage,
            ),
        }
    }

    fn test_recipe_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let state = self.assessment_state(context)?;
        let identity: HistoricalV2AssessmentIdentity = artifact(context, 5)?;
        let qualification: HistoricalV2Qualification = artifact(context, 6)?;
        let value = prepare_historical_v2_test_recipe(
            &state.inputs(&self.payload_inputs),
            &identity,
            &qualification,
        )
        .map_err(|detail| invalid(context.stage, detail))?;
        match &value.outcome {
            HistoricalV2TestRecipeOutcome::Selected { .. } => completed(
                HistoricalV2StageArtifactKind::TestRecipe,
                &value.test_recipe_sha256,
                &value,
                context.stage,
            ),
            HistoricalV2TestRecipeOutcome::Excluded { reason } => excluded(
                HistoricalV2TerminalExclusionReason::TestRecipe(*reason),
                HistoricalV2StageArtifactKind::TestRecipe,
                &value.test_recipe_sha256,
                &value,
                context.stage,
            ),
        }
    }

    fn identical_tests_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let (state, identity, qualification, recipe, plan) = self.execution_inputs(context)?;
        let value = execute_historical_v2_identical_tests(
            &state.inputs(&self.payload_inputs),
            &identity,
            &qualification,
            &recipe,
            self.harness_repository_root,
            &plan,
            self.test_executor,
        )
        .map_err(slot_execution_error)?;
        match &value.outcome {
            HistoricalV2IdenticalTestOutcome::Passed => completed(
                HistoricalV2StageArtifactKind::IdenticalTestExecution,
                &value.execution_sha256,
                &value,
                context.stage,
            ),
            HistoricalV2IdenticalTestOutcome::Excluded { reason } => excluded(
                HistoricalV2TerminalExclusionReason::IdenticalTests(reason.clone()),
                HistoricalV2StageArtifactKind::IdenticalTestExecution,
                &value.execution_sha256,
                &value,
                context.stage,
            ),
        }
    }

    fn ready_for_review_stage(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<HistoricalV2PreparedStage, HistoricalV2SlotStageError> {
        let (_, _, _, _, plan) = self.execution_inputs(context)?;
        let execution: HistoricalV2IdenticalTestExecution = artifact(context, 8)?;
        validate_historical_v2_identical_test_execution(&plan, &execution)
            .map_err(|detail| invalid(context.stage, detail))?;
        if !matches!(execution.outcome, HistoricalV2IdenticalTestOutcome::Passed) {
            return Err(invalid(
                context.stage,
                "historical-v2 excluded execution cannot become ready for review",
            ));
        }
        Ok(HistoricalV2PreparedStage {
            outcome: HistoricalV2SlotStageOutcome::ReadyForReview,
            artifact: None,
        })
    }

    fn execution_inputs(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<ExecutionInputs, HistoricalV2SlotStageError> {
        let state = self.assessment_state(context)?;
        let identity = artifact(context, 5)?;
        let qualification = artifact(context, 6)?;
        let recipe = artifact(context, 7)?;
        let plan = prepare_historical_v2_identical_test_plan(
            &state.inputs(&self.payload_inputs),
            &identity,
            &qualification,
            &recipe,
            self.harness_repository_root,
        )
        .map_err(|detail| invalid(context.stage, detail))?;
        Ok((state, identity, qualification, recipe, plan))
    }

    fn assessment_state(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<AssessmentState, HistoricalV2SlotStageError> {
        let payload: HistoricalV2SelectedSlotPayloadArtifact = artifact(context, 0)?;
        let materialization: HistoricalV2Materialization = artifact(context, 1)?;
        let materialized_roots = self.materialized_roots();
        validate_historical_v2_materialization(&materialization, &materialized_roots)
            .map_err(|detail| invalid(context.stage, detail))?;
        let (test_materialization, test_materialized_roots) =
            if payload.payload.test_patch_sha256.is_some() {
                (
                    Some(artifact(context, 2)?),
                    Some(self.test_materialized_roots()),
                )
            } else {
                let stored: HistoricalV2NoTestPatchArtifact = artifact(context, 2)?;
                let expected = prepare_historical_v2_no_test_patch(&payload, &materialization)?;
                if stored != expected {
                    return Err(invalid(
                        context.stage,
                        "historical-v2 no-test-patch artifact changed",
                    ));
                }
                (None, None)
            };
        Ok(AssessmentState {
            materialization,
            materialized_roots,
            test_materialization,
            test_materialized_roots,
            source_census: artifact(context, 3)?,
            semantic_census: artifact(context, 4)?,
        })
    }

    fn require_identity(
        &self,
        context: HistoricalV2SlotStageContext<'_>,
    ) -> Result<(), HistoricalV2SlotStageError> {
        require_operation_identity(
            context,
            &self.payload_inputs.selection.selection_sha256,
            self.payload_inputs.language,
            self.payload_inputs.slot_number,
            &self.selected_payload.canonical_repository,
        )
    }

    fn recover_materialization(&self) -> Result<(), HistoricalV2SlotStageError> {
        remove_interrupted_materialization(
            &self.work_root,
            self.payload_inputs.language,
            self.payload_inputs.slot_number,
        )
    }

    fn slot_root(&self) -> PathBuf {
        self.work_root
            .join(self.payload_inputs.language)
            .join(format!("slot-{:04}", self.payload_inputs.slot_number))
    }

    fn materialized_roots(&self) -> HistoricalV2MaterializedRoots {
        let root = self.slot_root();
        HistoricalV2MaterializedRoots {
            repository_root: root.join("repository"),
            base_root: root.join("repository"),
            patched_root: root.join("patched"),
        }
    }

    fn test_materialized_roots(&self) -> HistoricalV2TestMaterializedRoots {
        let root = self.slot_root();
        HistoricalV2TestMaterializedRoots {
            base_test_root: root.join("base-tested"),
            patched_test_root: root.join("patched-tested"),
        }
    }
}

impl<E: HistoricalV2RecoverableTestExecutor> HistoricalV2SlotStageExecutor
    for HistoricalV2SlotOperations<'_, E>
{
    fn recover<'a>(
        &'a mut self,
        context: HistoricalV2SlotStageContext<'a>,
    ) -> HistoricalV2SlotStageFuture<'a, ()> {
        Box::pin(async move { self.recover_stage(context).await })
    }

    fn execute<'a>(
        &'a mut self,
        context: HistoricalV2SlotStageContext<'a>,
    ) -> HistoricalV2SlotStageFuture<'a, HistoricalV2PreparedStage> {
        Box::pin(async move { self.execute_stage(context).await })
    }
}
