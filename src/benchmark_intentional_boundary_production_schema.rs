use super::{
    IntentionalBoundaryFrameTask, IntentionalBoundaryRankStage,
    ValidatedIntentionalBoundaryProtocol,
};
use std::num::NonZeroUsize;
use std::path::Path;

pub struct IntentionalBoundaryProductionSweepInputs<'a> {
    pub protocol: &'a ValidatedIntentionalBoundaryProtocol,
    pub task: &'a IntentionalBoundaryFrameTask,
    pub state_root: &'a Path,
    pub work_root: &'a Path,
    pub frame_root: &'a Path,
    pub github_token: Option<&'a str>,
    pub maximum_new_stages_per_rank: Option<NonZeroUsize>,
    pub through_stage: Option<IntentionalBoundaryRankStage>,
}
