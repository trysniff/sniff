use super::{
    HistoricalV2SlotStage, HistoricalV2SlotStageOutcome, HistoricalV2StoredSlotStage,
    HistoricalV2TerminalExclusionReason,
};
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone, Copy)]
pub struct HistoricalV2SlotRunIdentity<'a> {
    pub selection_sha256: &'a str,
    pub language: &'a str,
    pub slot_number: usize,
    pub canonical_repository: &'a str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalV2PreparedStage {
    pub outcome: HistoricalV2SlotStageOutcome,
    pub artifact: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV2SlotRunDisposition {
    Paused {
        next_stage: HistoricalV2SlotStage,
    },
    Excluded {
        stage: HistoricalV2SlotStage,
        reason: HistoricalV2TerminalExclusionReason,
    },
    ReadyForReview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2SlotRunSummary {
    pub resumed_after_sequence: usize,
    pub executed_stages: Vec<HistoricalV2SlotStage>,
    pub terminal_checkpoint_sha256: Option<String>,
    pub disposition: HistoricalV2SlotRunDisposition,
}

#[derive(Debug, Clone, Copy)]
pub struct HistoricalV2SlotStageContext<'a> {
    pub identity: HistoricalV2SlotRunIdentity<'a>,
    pub stage: HistoricalV2SlotStage,
    pub history: &'a [HistoricalV2StoredSlotStage],
}

pub type HistoricalV2SlotStageFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, super::HistoricalV2SlotStageError>> + 'a>>;

pub trait HistoricalV2SlotStageExecutor {
    fn recover<'a>(
        &'a mut self,
        _context: HistoricalV2SlotStageContext<'a>,
    ) -> HistoricalV2SlotStageFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn execute<'a>(
        &'a mut self,
        context: HistoricalV2SlotStageContext<'a>,
    ) -> HistoricalV2SlotStageFuture<'a, HistoricalV2PreparedStage>;
}
