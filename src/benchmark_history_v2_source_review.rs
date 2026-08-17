use super::*;
use std::fs;
use std::path::Path;

#[path = "benchmark_history_v2_source_review_bundle.rs"]
mod bundle;
use bundle::*;

#[path = "benchmark_history_v2_source_review_lineage.rs"]
mod lineage;
use lineage::*;

#[path = "benchmark_history_v2_source_review_support.rs"]
mod support;
use support::*;

#[path = "benchmark_history_v2_source_review_validation.rs"]
mod validation;
use validation::*;

pub(super) const BUNDLE_CONTRACT: &str = "sniffbench-historical-v2-source-review-v1";
pub(super) const REVIEW_ITEM_CONTRACT: &str = "sniffbench-historical-v2-review-item-v1";
pub(super) const MANIFEST_NAME: &str = "manifest.json";

pub struct HistoricalV2SourceReviewBundleInputs<'a> {
    pub protocol_bytes: &'a [u8],
    pub artifact_root: &'a Path,
    pub frame: &'a HistoricalV2Frame,
    pub exclusions: &'a HistoricalV2ExclusionManifest,
    pub selection: &'a HistoricalV2SlotSelection,
    pub payloads: &'a HistoricalV2SelectedPayloads,
    pub state_root: &'a Path,
    pub work_root: &'a Path,
    pub harness_repository_root: &'a Path,
    pub language: &'a str,
    pub slot_number: usize,
}

pub fn create_historical_v2_source_review_bundle(
    inputs: &HistoricalV2SourceReviewBundleInputs<'_>,
    output_root: &Path,
) -> Result<HistoricalV2SourceReviewBundle, String> {
    if output_root.exists() {
        return Err(format!(
            "historical-v2 source review bundle already exists: {}",
            output_root.display()
        ));
    }
    require_existing_slot(inputs)?;
    let journal =
        HistoricalV2SlotStageJournal::open(inputs.state_root, inputs.language, inputs.slot_number)
            .map_err(|error| error.detail)?;
    let prepared = validate_ready_slot(inputs, journal.history())?;
    let bundle = build_bundle(&prepared)?;
    let temporary_root = review_temporary_root(output_root)?;
    fs::create_dir(&temporary_root).map_err(|error| {
        format!("failed to create temporary historical-v2 review bundle: {error}")
    })?;
    let publish = materialize_bundle(&temporary_root, &bundle, &prepared).and_then(|()| {
        fs::rename(&temporary_root, output_root).map_err(|error| {
            format!("failed to publish historical-v2 source review bundle: {error}")
        })
    });
    if publish.is_err() {
        let _ = fs::remove_dir_all(&temporary_root);
    }
    publish?;
    validate_historical_v2_source_review_bundle(output_root, &bundle)?;
    Ok(bundle)
}

pub fn validate_historical_v2_source_review_bundle(
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
) -> Result<(), String> {
    validate_persisted_bundle(bundle_root, bundle)
}

pub(super) struct PreparedReviewSlot<'a> {
    pub(super) protocol: ValidatedHistoricalV2Protocol,
    pub(super) selection_sha256: &'a str,
    pub(super) language: &'a str,
    pub(super) terminal_checkpoint_sha256: &'a str,
    pub(super) roots: HistoricalV2MaterializedRoots,
    pub(super) materialization: HistoricalV2Materialization,
    pub(super) source_census: HistoricalV2SourceCensus,
    pub(super) assessment: HistoricalV2AssessmentIdentity,
    pub(super) qualification: HistoricalV2Qualification,
    pub(super) plan: HistoricalV2IdenticalTestPlan,
    pub(super) execution: HistoricalV2IdenticalTestExecution,
    pub(super) before_inventory: IntentionalBoundaryRepositoryInventory,
    pub(super) after_inventory: IntentionalBoundaryRepositoryInventory,
}

#[cfg(test)]
#[path = "benchmark_history_v2_source_review_tests.rs"]
mod tests;
