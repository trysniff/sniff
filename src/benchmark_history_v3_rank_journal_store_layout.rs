use super::super::super::history_v2_slot_store_support::{
    canonical_directory, require_plain_directory, sync_directory,
};
use super::super::{HistoricalV3RankIdentity, HistoricalV3RankJournalError, HistoricalV3RankStage};
use std::fs;
use std::path::Path;

pub(super) fn create_plain_child(
    parent: &Path,
    child: &Path,
    label: &str,
) -> Result<(), HistoricalV3RankJournalError> {
    if child.exists() {
        require_plain_directory(child, label)
            .map_err(|detail| HistoricalV3RankJournalError::invalid(stage(), detail))?;
    } else {
        fs::create_dir(child).map_err(|error| {
            HistoricalV3RankJournalError::infrastructure(
                stage(),
                format!("failed to create {label}: {error}"),
            )
        })?;
        sync_directory(parent)
            .map_err(|detail| HistoricalV3RankJournalError::infrastructure(stage(), detail))?;
    }
    let resolved = canonical_directory(child, label)
        .map_err(|detail| HistoricalV3RankJournalError::infrastructure(stage(), detail))?;
    if resolved.parent() != Some(parent) {
        return Err(HistoricalV3RankJournalError::invalid(
            stage(),
            format!("{label} escaped its parent"),
        ));
    }
    Ok(())
}

pub(super) fn remove_incomplete(
    parent: &Path,
    staging_root: &Path,
) -> Result<(), HistoricalV3RankJournalError> {
    if !staging_root.exists() {
        return Ok(());
    }
    require_plain_directory(staging_root, "incomplete historical-v3 rank transaction")
        .map_err(|detail| HistoricalV3RankJournalError::invalid(stage(), detail))?;
    if staging_root.parent() != Some(parent) {
        return Err(HistoricalV3RankJournalError::invalid(
            stage(),
            "incomplete historical-v3 transaction escaped its parent",
        ));
    }
    fs::remove_dir_all(staging_root).map_err(|error| {
        HistoricalV3RankJournalError::infrastructure(
            stage(),
            format!("failed to remove incomplete historical-v3 transaction: {error}"),
        )
    })?;
    sync_directory(parent)
        .map_err(|detail| HistoricalV3RankJournalError::infrastructure(stage(), detail))
}

pub(super) fn language_name(identity: &HistoricalV3RankIdentity) -> &'static str {
    use super::super::super::HistoricalV3Language as Language;
    match identity.language() {
        Language::Go => "go",
        Language::JavaScript => "javascript",
        Language::Kotlin => "kotlin",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::TypeScript => "typescript",
    }
}

pub(super) fn rank_name(stream_rank: usize) -> String {
    format!("rank-{stream_rank:08}")
}

fn stage() -> HistoricalV3RankStage {
    HistoricalV3RankStage::Materialization
}
