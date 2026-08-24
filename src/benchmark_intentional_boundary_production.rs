use super::{
    IntentionalBoundaryMaterializationOutcome, IntentionalBoundaryProductionSweepInputs,
    IntentionalBoundaryRankStage, IntentionalBoundaryRankStageArtifact,
    IntentionalBoundaryRankStageContext, IntentionalBoundaryRankStageError,
    IntentionalBoundaryRankStageExecutor, IntentionalBoundaryRankStageFuture,
    IntentionalBoundaryRankSweepSummary, IntentionalBoundaryRankTerminalContext,
    ValidatedIntentionalBoundaryProtocol, census_intentional_boundary_evidence_stage,
    census_intentional_boundary_repository_licenses, census_intentional_boundary_repository_stage,
    inventory_intentional_boundary_repository_typed, materialize_intentional_boundary_repository,
    run_intentional_boundary_rank_sweep, run_intentional_boundary_rank_sweep_limit,
    validate_intentional_boundary_rank_sweep_task,
};
use std::num::NonZeroUsize;
use std::path::Path;

#[path = "benchmark_intentional_boundary_production_error.rs"]
mod error;
#[path = "benchmark_intentional_boundary_production_history.rs"]
mod history;
#[path = "benchmark_intentional_boundary_production_roots.rs"]
mod roots;
#[path = "benchmark_intentional_boundary_production_stages.rs"]
mod stages;
#[path = "benchmark_intentional_boundary_production_terminal.rs"]
mod terminal;

use error::IntoRankStageError;
use roots::ProductionRoots;
use stages::ProductionStageInput;

pub struct IntentionalBoundaryProductionRankExecutor<'a> {
    protocol: &'a ValidatedIntentionalBoundaryProtocol,
    roots: ProductionRoots,
    github_token: Option<&'a str>,
}

impl<'a> IntentionalBoundaryProductionRankExecutor<'a> {
    pub fn new(
        protocol: &'a ValidatedIntentionalBoundaryProtocol,
        state_root: &Path,
        work_root: &Path,
        frame_root: &Path,
        github_token: Option<&'a str>,
    ) -> Result<Self, IntentionalBoundaryRankStageError> {
        Ok(Self {
            protocol,
            roots: ProductionRoots::prepare(state_root, work_root, frame_root)?,
            github_token,
        })
    }

    async fn execute_stage(
        &mut self,
        context: IntentionalBoundaryRankStageContext<'_>,
    ) -> Result<IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        let history = context.history;
        if stage == IntentionalBoundaryRankStage::Materialization {
            let checkout = self.roots.checkout(context.repository_task.population_rank);
            return match materialize_intentional_boundary_repository(
                context.task,
                context.repository_task.population_rank,
                &checkout,
                self.github_token,
            )
            .await
            .map_err(|error| error.into_rank_stage_error(stage))?
            {
                IntentionalBoundaryMaterializationOutcome::Completed(completed) => {
                    if completed.checkout_root != checkout {
                        return Err(IntentionalBoundaryRankStageError::invalid(
                            stage,
                            "intentional-boundary materialization changed its checkout root",
                        ));
                    }
                    Ok(IntentionalBoundaryRankStageArtifact::Materialization(
                        completed.artifact,
                    ))
                }
                IntentionalBoundaryMaterializationOutcome::Excluded(excluded) => {
                    Ok(IntentionalBoundaryRankStageArtifact::MaterializationExclusion(excluded))
                }
            };
        }

        let checkout = self
            .roots
            .require_checkout(context.repository_task.population_rank, stage)?;
        let materialization = history::materialization(history, stage)?;
        match stage {
            IntentionalBoundaryRankStage::Materialization => unreachable!(),
            IntentionalBoundaryRankStage::Inventory => {
                inventory_intentional_boundary_repository_typed(
                    &materialization.repository,
                    &materialization.revision,
                    &checkout,
                )
                .map(IntentionalBoundaryRankStageArtifact::Inventory)
                .map_err(|error| error.into_rank_stage_error(stage))
            }
            IntentionalBoundaryRankStage::SourceCensus => {
                let inventory = history::inventory(history, stage)?;
                match census_intentional_boundary_repository_stage(
                    context.task,
                    materialization,
                    &checkout,
                    inventory,
                )
                .map_err(|error| error.into_rank_stage_error(stage))?
                {
                    super::IntentionalBoundarySourceCensusStageOutcome::Completed(value) => {
                        Ok(IntentionalBoundaryRankStageArtifact::SourceCensus(value))
                    }
                    super::IntentionalBoundarySourceCensusStageOutcome::Excluded(value) => Ok(
                        IntentionalBoundaryRankStageArtifact::SourceCensusExclusion(value),
                    ),
                }
            }
            IntentionalBoundaryRankStage::LicenseCensus => {
                let inventory = history::inventory(history, stage)?;
                let source = history::source_census(history, stage)?;
                match census_intentional_boundary_repository_licenses(
                    context.task,
                    materialization,
                    &checkout,
                    inventory,
                    source,
                )
                .map_err(|error| error.into_rank_stage_error(stage))?
                {
                    super::IntentionalBoundaryLicenseCensusStageOutcome::Completed(value) => {
                        Ok(IntentionalBoundaryRankStageArtifact::LicenseCensus(value))
                    }
                    super::IntentionalBoundaryLicenseCensusStageOutcome::Excluded(value) => {
                        Ok(IntentionalBoundaryRankStageArtifact::LicenseCensusExclusion(value))
                    }
                }
            }
            IntentionalBoundaryRankStage::SemanticCensus => {
                self.execute_semantic(context, materialization, &checkout)
                    .await
            }
            IntentionalBoundaryRankStage::AstCensus => {
                self.execute_ast(context, materialization, &checkout).await
            }
            IntentionalBoundaryRankStage::Manifest => {
                self.execute_manifest(context, materialization, &checkout)
                    .await
            }
            IntentionalBoundaryRankStage::BaseEvidence => {
                let input = ProductionStageInput::load(context, materialization)?;
                census_intentional_boundary_evidence_stage(
                    context.task,
                    materialization,
                    &checkout,
                    input.inventory,
                    input.source,
                    input.license,
                    input.semantic,
                    input.ast,
                    input.manifest,
                )
                .await
                .map(|value| IntentionalBoundaryRankStageArtifact::BaseEvidence(Box::new(value)))
                .map_err(|error| error.into_rank_stage_error(stage))
            }
            IntentionalBoundaryRankStage::ProjectModel => {
                self.execute_project_model(context, materialization, &checkout)
                    .await
            }
            IntentionalBoundaryRankStage::Generator => {
                self.execute_generator(context, materialization, &checkout)
            }
            IntentionalBoundaryRankStage::Behavior => {
                self.execute_behavior(context, materialization, &checkout)
            }
            IntentionalBoundaryRankStage::Candidate => {
                self.execute_candidate(context, materialization)
            }
        }
    }
}

impl IntentionalBoundaryRankStageExecutor for IntentionalBoundaryProductionRankExecutor<'_> {
    fn recover<'a>(
        &'a mut self,
        context: IntentionalBoundaryRankStageContext<'a>,
    ) -> IntentionalBoundaryRankStageFuture<'a, ()> {
        Box::pin(async move {
            if context.stage == IntentionalBoundaryRankStage::Materialization {
                self.roots.remove_checkout(
                    context.repository_task.population_rank,
                    IntentionalBoundaryRankStage::Materialization,
                )
            } else {
                self.roots
                    .require_checkout(context.repository_task.population_rank, context.stage)
                    .map(|_| ())
            }
        })
    }

    fn execute<'a>(
        &'a mut self,
        context: IntentionalBoundaryRankStageContext<'a>,
    ) -> IntentionalBoundaryRankStageFuture<'a, IntentionalBoundaryRankStageArtifact> {
        Box::pin(async move { self.execute_stage(context).await })
    }

    fn reconcile_terminal<'a>(
        &'a mut self,
        context: IntentionalBoundaryRankTerminalContext<'a>,
    ) -> IntentionalBoundaryRankStageFuture<'a, ()> {
        Box::pin(async move { terminal::reconcile_terminal(&self.roots, context) })
    }
}

pub async fn run_intentional_boundary_production_sweep(
    inputs: IntentionalBoundaryProductionSweepInputs<'_>,
) -> Result<IntentionalBoundaryRankSweepSummary, IntentionalBoundaryRankStageError> {
    if inputs.protocol.protocol_sha256 != inputs.task.protocol_sha256 {
        return Err(IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary production protocol does not match the frame task",
        ));
    }
    validate_intentional_boundary_rank_sweep_task(inputs.task)?;
    let mut executor = IntentionalBoundaryProductionRankExecutor::new(
        inputs.protocol,
        inputs.state_root,
        inputs.work_root,
        inputs.frame_root,
        inputs.github_token,
    )?;
    let state_root = executor.roots.state.clone();
    run_intentional_boundary_rank_sweep(
        &state_root,
        inputs.task,
        &mut executor,
        inputs.maximum_new_stages_per_rank,
        inputs.through_stage,
    )
    .await
}

pub async fn run_intentional_boundary_production_sweep_slice(
    inputs: IntentionalBoundaryProductionSweepInputs<'_>,
    maximum_new_ranks: NonZeroUsize,
) -> Result<IntentionalBoundaryRankSweepSummary, IntentionalBoundaryRankStageError> {
    if inputs.maximum_new_stages_per_rank.is_some() || inputs.through_stage.is_some() {
        return Err(IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary production rank slices require terminal per-rank execution",
        ));
    }
    if inputs.protocol.protocol_sha256 != inputs.task.protocol_sha256 {
        return Err(IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary production protocol does not match the frame task",
        ));
    }
    validate_intentional_boundary_rank_sweep_task(inputs.task)?;
    let mut executor = IntentionalBoundaryProductionRankExecutor::new(
        inputs.protocol,
        inputs.state_root,
        inputs.work_root,
        inputs.frame_root,
        inputs.github_token,
    )?;
    let state_root = executor.roots.state.clone();
    run_intentional_boundary_rank_sweep_limit(
        &state_root,
        inputs.task,
        &mut executor,
        maximum_new_ranks,
    )
    .await
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_production_tests.rs"]
mod tests;
