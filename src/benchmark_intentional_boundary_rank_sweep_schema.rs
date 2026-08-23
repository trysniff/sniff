use super::IntentionalBoundaryRankRunSummary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryRankSweepSummary {
    pub rank_count: usize,
    pub completed_count: usize,
    pub excluded_count: usize,
    pub paused_count: usize,
    pub ranks: Vec<IntentionalBoundaryRankRunSummary>,
}
