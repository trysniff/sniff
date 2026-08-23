use super::super::{
    IntentionalBoundaryAstCensusStage, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryManifestStage, IntentionalBoundaryMaterialization,
    IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageContext,
    IntentionalBoundaryRankStageError, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensusStage,
    census_intentional_boundary_ast_stage, census_intentional_boundary_behavior_stage,
    census_intentional_boundary_generator_stage, census_intentional_boundary_manifest_stage,
    census_intentional_boundary_project_model_stage, census_intentional_boundary_semantics_stage,
    qualify_intentional_boundary_candidate_stage,
};
use super::IntentionalBoundaryProductionRankExecutor;
use super::error::IntoRankStageError;
use super::history;
use std::path::Path;

pub(super) struct ProductionStageInput<'a> {
    pub inventory: &'a IntentionalBoundaryRepositoryInventory,
    pub source: &'a IntentionalBoundarySourceCensusStage,
    pub license: &'a IntentionalBoundaryLicenseCensusStage,
    pub semantic: &'a IntentionalBoundarySemanticCensusStage,
    pub ast: &'a IntentionalBoundaryAstCensusStage,
    pub manifest: &'a IntentionalBoundaryManifestStage,
}

impl<'a> ProductionStageInput<'a> {
    pub fn load(
        context: IntentionalBoundaryRankStageContext<'a>,
        _materialization: &'a IntentionalBoundaryMaterialization,
    ) -> Result<Self, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        Ok(Self {
            inventory: history::inventory(context.history, stage)?,
            source: history::source_census(context.history, stage)?,
            license: history::license_census(context.history, stage)?,
            semantic: history::semantic_census(context.history, stage)?,
            ast: history::ast_census(context.history, stage)?,
            manifest: history::manifest(context.history, stage)?,
        })
    }
}

impl IntentionalBoundaryProductionRankExecutor<'_> {
    pub(super) async fn execute_semantic(
        &self,
        context: IntentionalBoundaryRankStageContext<'_>,
        materialization: &IntentionalBoundaryMaterialization,
        checkout: &Path,
    ) -> Result<IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        let inventory = history::inventory(context.history, stage)?;
        let source = history::source_census(context.history, stage)?;
        let license = history::license_census(context.history, stage)?;
        match census_intentional_boundary_semantics_stage(
            context.task,
            materialization,
            checkout,
            inventory,
            source,
            license,
        )
        .await
        .map_err(|error| error.into_rank_stage_error(stage))?
        {
            super::super::IntentionalBoundarySemanticCensusStageOutcome::Completed(value) => {
                Ok(IntentionalBoundaryRankStageArtifact::SemanticCensus(value))
            }
            super::super::IntentionalBoundarySemanticCensusStageOutcome::Excluded(value) => {
                Ok(IntentionalBoundaryRankStageArtifact::SemanticCensusExclusion(value))
            }
        }
    }

    pub(super) async fn execute_ast(
        &self,
        context: IntentionalBoundaryRankStageContext<'_>,
        materialization: &IntentionalBoundaryMaterialization,
        checkout: &Path,
    ) -> Result<IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        let inventory = history::inventory(context.history, stage)?;
        let source = history::source_census(context.history, stage)?;
        let license = history::license_census(context.history, stage)?;
        let semantic = history::semantic_census(context.history, stage)?;
        match census_intentional_boundary_ast_stage(
            context.task,
            materialization,
            checkout,
            inventory,
            source,
            license,
            semantic,
        )
        .await
        .map_err(|error| error.into_rank_stage_error(stage))?
        {
            super::super::IntentionalBoundaryAstCensusStageOutcome::Completed(value) => {
                Ok(IntentionalBoundaryRankStageArtifact::AstCensus(value))
            }
            super::super::IntentionalBoundaryAstCensusStageOutcome::Excluded(value) => Ok(
                IntentionalBoundaryRankStageArtifact::AstCensusExclusion(value),
            ),
        }
    }

    pub(super) async fn execute_manifest(
        &self,
        context: IntentionalBoundaryRankStageContext<'_>,
        materialization: &IntentionalBoundaryMaterialization,
        checkout: &Path,
    ) -> Result<IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        let inventory = history::inventory(context.history, stage)?;
        let source = history::source_census(context.history, stage)?;
        let license = history::license_census(context.history, stage)?;
        let semantic = history::semantic_census(context.history, stage)?;
        let ast = history::ast_census(context.history, stage)?;
        match census_intentional_boundary_manifest_stage(
            context.task,
            materialization,
            checkout,
            inventory,
            source,
            license,
            semantic,
            ast,
        )
        .await
        .map_err(|error| error.into_rank_stage_error(stage))?
        {
            super::super::IntentionalBoundaryManifestStageOutcome::Completed(value) => {
                Ok(IntentionalBoundaryRankStageArtifact::Manifest(value))
            }
            super::super::IntentionalBoundaryManifestStageOutcome::Excluded(value) => Ok(
                IntentionalBoundaryRankStageArtifact::ManifestExclusion(value),
            ),
        }
    }

    pub(super) async fn execute_project_model(
        &self,
        context: IntentionalBoundaryRankStageContext<'_>,
        materialization: &IntentionalBoundaryMaterialization,
        checkout: &Path,
    ) -> Result<IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        let input = ProductionStageInput::load(context, materialization)?;
        let base = history::base_evidence(context.history, stage)?;
        match census_intentional_boundary_project_model_stage(
            context.task,
            materialization,
            checkout,
            input.inventory,
            input.source,
            input.license,
            input.semantic,
            input.ast,
            input.manifest,
            base,
        )
        .await
        .map_err(|error| error.into_rank_stage_error(stage))?
        {
            super::super::IntentionalBoundaryProjectModelStageOutcome::Completed(value) => {
                Ok(IntentionalBoundaryRankStageArtifact::ProjectModel(value))
            }
            super::super::IntentionalBoundaryProjectModelStageOutcome::Excluded(value) => Ok(
                IntentionalBoundaryRankStageArtifact::ProjectModelExclusion(value),
            ),
        }
    }

    pub(super) fn execute_generator(
        &self,
        context: IntentionalBoundaryRankStageContext<'_>,
        materialization: &IntentionalBoundaryMaterialization,
        checkout: &Path,
    ) -> Result<IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        let input = ProductionStageInput::load(context, materialization)?;
        let base = history::base_evidence(context.history, stage)?;
        let project = history::project_model(context.history, stage)?;
        census_intentional_boundary_generator_stage(
            context.task,
            materialization,
            checkout,
            input.inventory,
            input.source,
            input.license,
            input.semantic,
            input.ast,
            input.manifest,
            base,
            project,
        )
        .map(|value| IntentionalBoundaryRankStageArtifact::Generator(Box::new(value)))
        .map_err(|error| error.into_rank_stage_error(stage))
    }

    pub(super) fn execute_behavior(
        &self,
        context: IntentionalBoundaryRankStageContext<'_>,
        materialization: &IntentionalBoundaryMaterialization,
        checkout: &Path,
    ) -> Result<IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        let input = ProductionStageInput::load(context, materialization)?;
        let base = history::base_evidence(context.history, stage)?;
        let project = history::project_model(context.history, stage)?;
        let generator = history::generator(context.history, stage)?;
        census_intentional_boundary_behavior_stage(
            context.task,
            materialization,
            checkout,
            input.inventory,
            input.source,
            input.license,
            input.semantic,
            input.ast,
            input.manifest,
            base,
            project,
            generator,
        )
        .map(|value| IntentionalBoundaryRankStageArtifact::Behavior(Box::new(value)))
        .map_err(|error| error.into_rank_stage_error(stage))
    }

    pub(super) fn execute_candidate(
        &self,
        context: IntentionalBoundaryRankStageContext<'_>,
        materialization: &IntentionalBoundaryMaterialization,
    ) -> Result<IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
        let stage = context.stage;
        let input = ProductionStageInput::load(context, materialization)?;
        let base = history::base_evidence(context.history, stage)?;
        let project = history::project_model(context.history, stage)?;
        let generator = history::generator(context.history, stage)?;
        let behavior = history::behavior(context.history, stage)?;
        qualify_intentional_boundary_candidate_stage(
            self.protocol,
            context.task,
            materialization,
            input.inventory,
            input.source,
            input.license,
            input.semantic,
            input.ast,
            input.manifest,
            base,
            project,
            generator,
            behavior,
        )
        .map(|value| IntentionalBoundaryRankStageArtifact::Candidate(Box::new(value)))
        .map_err(|error| error.into_rank_stage_error(stage))
    }
}
