use super::{
    HistoricalV2ExclusionManifest, HistoricalV2Frame, HistoricalV2RecoverableTestExecutor,
    HistoricalV2SelectedPayloads, HistoricalV2SlotRunSummary, HistoricalV2SlotSelection,
    HistoricalV2SlotStage,
};
use reqwest::Client;
use std::path::Path;

pub struct HistoricalV2SelectedSlotSweepInputs<'a, E: HistoricalV2RecoverableTestExecutor> {
    pub client: &'a Client,
    pub protocol_bytes: &'a [u8],
    pub artifact_root: &'a Path,
    pub frame: &'a HistoricalV2Frame,
    pub exclusions: &'a HistoricalV2ExclusionManifest,
    pub selection: &'a HistoricalV2SlotSelection,
    pub payloads: &'a HistoricalV2SelectedPayloads,
    pub state_root: &'a Path,
    pub work_root: &'a Path,
    pub harness_repository_root: &'a Path,
    pub test_executor: &'a E,
    pub through_stage: Option<HistoricalV2SlotStage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2SelectedSlotRunSummary {
    pub language: String,
    pub slot_number: usize,
    pub canonical_repository: String,
    pub run: HistoricalV2SlotRunSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2SelectedSlotSweepSummary {
    pub selected_slot_count: usize,
    pub newly_admitted_slot_count: usize,
    pub ready_for_review_count: usize,
    pub excluded_count: usize,
    pub paused_count: usize,
    pub slots: Vec<HistoricalV2SelectedSlotRunSummary>,
}
