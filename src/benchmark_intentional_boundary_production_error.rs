use super::super::{
    IntentionalBoundaryAstCensusStageError, IntentionalBoundaryAstCensusStageErrorKind,
    IntentionalBoundaryBehaviorStageError, IntentionalBoundaryBehaviorStageErrorKind,
    IntentionalBoundaryCandidateStageError, IntentionalBoundaryEvidenceStageError,
    IntentionalBoundaryEvidenceStageErrorKind, IntentionalBoundaryGeneratorStageError,
    IntentionalBoundaryGeneratorStageErrorKind, IntentionalBoundaryInventoryError,
    IntentionalBoundaryInventoryErrorKind, IntentionalBoundaryLicenseCensusStageError,
    IntentionalBoundaryLicenseCensusStageErrorKind, IntentionalBoundaryManifestStageError,
    IntentionalBoundaryManifestStageErrorKind, IntentionalBoundaryMaterializationError,
    IntentionalBoundaryMaterializationErrorKind, IntentionalBoundaryProjectModelStageError,
    IntentionalBoundaryProjectModelStageErrorKind, IntentionalBoundaryRankStage,
    IntentionalBoundaryRankStageError, IntentionalBoundarySemanticCensusStageError,
    IntentionalBoundarySemanticCensusStageErrorKind, IntentionalBoundarySourceCensusStageError,
    IntentionalBoundarySourceCensusStageErrorKind,
};

pub(super) trait IntoRankStageError {
    fn into_rank_stage_error(
        self,
        stage: IntentionalBoundaryRankStage,
    ) -> IntentionalBoundaryRankStageError;
}

macro_rules! impl_rank_stage_error {
    ($error:ty, $kind:ty) => {
        impl IntoRankStageError for $error {
            fn into_rank_stage_error(
                self,
                stage: IntentionalBoundaryRankStage,
            ) -> IntentionalBoundaryRankStageError {
                match self.kind {
                    <$kind>::InvalidInput => {
                        IntentionalBoundaryRankStageError::invalid(stage, self.detail)
                    }
                    <$kind>::InfrastructureUnavailable => {
                        IntentionalBoundaryRankStageError::unavailable(stage, self.detail)
                    }
                    <$kind>::InfrastructureFailed => {
                        IntentionalBoundaryRankStageError::infrastructure(stage, self.detail)
                    }
                }
            }
        }
    };
}

impl_rank_stage_error!(
    IntentionalBoundaryMaterializationError,
    IntentionalBoundaryMaterializationErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundaryInventoryError,
    IntentionalBoundaryInventoryErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundarySourceCensusStageError,
    IntentionalBoundarySourceCensusStageErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundaryLicenseCensusStageError,
    IntentionalBoundaryLicenseCensusStageErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundarySemanticCensusStageError,
    IntentionalBoundarySemanticCensusStageErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundaryAstCensusStageError,
    IntentionalBoundaryAstCensusStageErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundaryManifestStageError,
    IntentionalBoundaryManifestStageErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundaryEvidenceStageError,
    IntentionalBoundaryEvidenceStageErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundaryProjectModelStageError,
    IntentionalBoundaryProjectModelStageErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundaryGeneratorStageError,
    IntentionalBoundaryGeneratorStageErrorKind
);
impl_rank_stage_error!(
    IntentionalBoundaryBehaviorStageError,
    IntentionalBoundaryBehaviorStageErrorKind
);

impl IntoRankStageError for IntentionalBoundaryCandidateStageError {
    fn into_rank_stage_error(
        self,
        stage: IntentionalBoundaryRankStage,
    ) -> IntentionalBoundaryRankStageError {
        IntentionalBoundaryRankStageError::invalid(stage, self.detail)
    }
}
