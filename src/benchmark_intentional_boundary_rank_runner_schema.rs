use super::{
    IntentionalBoundaryFrameTask, IntentionalBoundaryRankStage,
    IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageArtifactKind,
    IntentionalBoundaryRepositoryTask, IntentionalBoundaryStoredRankStage,
};
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentionalBoundaryRankRunDisposition {
    Paused {
        next_stage: IntentionalBoundaryRankStage,
    },
    Excluded {
        stage: IntentionalBoundaryRankStage,
        artifact_kind: IntentionalBoundaryRankStageArtifactKind,
    },
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryRankRunSummary {
    pub population_rank: usize,
    pub repository: String,
    pub resumed_after_sequence: usize,
    pub executed_stages: Vec<IntentionalBoundaryRankStage>,
    pub terminal_checkpoint_sha256: Option<String>,
    pub disposition: IntentionalBoundaryRankRunDisposition,
}

#[derive(Debug, Clone, Copy)]
pub struct IntentionalBoundaryRankStageContext<'a> {
    pub task: &'a IntentionalBoundaryFrameTask,
    pub repository_task: &'a IntentionalBoundaryRepositoryTask,
    pub stage: IntentionalBoundaryRankStage,
    pub history: &'a [IntentionalBoundaryStoredRankStage],
}

pub type IntentionalBoundaryRankStageFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, super::IntentionalBoundaryRankStageError>> + 'a>>;

pub trait IntentionalBoundaryRankStageExecutor {
    fn recover<'a>(
        &'a mut self,
        _context: IntentionalBoundaryRankStageContext<'a>,
    ) -> IntentionalBoundaryRankStageFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn execute<'a>(
        &'a mut self,
        context: IntentionalBoundaryRankStageContext<'a>,
    ) -> IntentionalBoundaryRankStageFuture<'a, IntentionalBoundaryRankStageArtifact>;
}
