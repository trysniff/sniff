use super::super::history_v2_slot_store_support::{
    SlotFileLock, canonical_directory, read_committed_json_limited,
};
use super::commitment::{expected_historical_v3_rank_stage, validate_historical_v3_rank_identity};
use super::{
    HistoricalV3RankCheckpoint, HistoricalV3RankIdentity, HistoricalV3RankJournalError,
    HistoricalV3RankStage, HistoricalV3RankStageOutcome, append_historical_v3_rank_checkpoint,
};
use serde::{Serialize, de::DeserializeOwned};
use std::fs;
use std::path::{Path, PathBuf};

#[path = "benchmark_history_v3_rank_journal_store_layout.rs"]
mod layout;

use layout::{create_plain_child, language_name, rank_name, remove_incomplete};

#[path = "benchmark_history_v3_rank_journal_store_transaction.rs"]
mod transaction;

use transaction::{
    CommittedFile, MAX_ARTIFACT_BYTES, load_history, publish_stage, transaction_directory_name,
};

#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalV3StoredRankStage {
    pub checkpoint: HistoricalV3RankCheckpoint,
    artifact_path: Option<PathBuf>,
    artifact_commitment: Option<CommittedFile>,
}

impl HistoricalV3StoredRankStage {
    pub fn read_artifact<T: DeserializeOwned>(&self) -> Result<Option<T>, String> {
        match (&self.artifact_path, &self.artifact_commitment) {
            (Some(path), Some(commitment)) => read_committed_json_limited(
                path,
                MAX_ARTIFACT_BYTES,
                "historical-v3 rank artifact",
                commitment.byte_count,
                &commitment.sha256,
            )
            .map(Some),
            (None, None) => Ok(None),
            _ => Err("historical-v3 rank artifact storage is inconsistent".to_string()),
        }
    }
}

#[derive(Debug)]
pub struct HistoricalV3RankJournal {
    identity: HistoricalV3RankIdentity,
    rank_root: PathBuf,
    staging_root: PathBuf,
    history: Vec<HistoricalV3StoredRankStage>,
    _lock: SlotFileLock,
}

impl HistoricalV3RankJournal {
    pub fn open(
        root: &Path,
        identity: &HistoricalV3RankIdentity,
    ) -> Result<Self, HistoricalV3RankJournalError> {
        validate_historical_v3_rank_identity(identity)
            .map_err(|detail| HistoricalV3RankJournalError::invalid(stage_for_open(), detail))?;
        fs::create_dir_all(root).map_err(|error| {
            HistoricalV3RankJournalError::infrastructure(
                stage_for_open(),
                format!("failed to create historical-v3 journal root: {error}"),
            )
        })?;
        let root = canonical_directory(root, "historical-v3 journal root").map_err(|detail| {
            HistoricalV3RankJournalError::infrastructure(stage_for_open(), detail)
        })?;
        let task_root = root.join(&identity.stream_task_sha256);
        create_plain_child(&root, &task_root, "historical-v3 task journal")?;
        let language_root = task_root.join(language_name(identity));
        create_plain_child(&task_root, &language_root, "historical-v3 language journal")?;
        let rank_name = rank_name(identity.stream_rank);
        let lock = SlotFileLock::acquire(&language_root.join(format!("{rank_name}.lock")))
            .map_err(|detail| {
                HistoricalV3RankJournalError::infrastructure(
                    stage_for_open(),
                    detail.replace("historical-v2 slot", "historical-v3 rank"),
                )
            })?;
        let rank_root = language_root.join(&rank_name);
        create_plain_child(&language_root, &rank_root, "historical-v3 rank journal")?;
        let staging_root = language_root.join(format!(".{rank_name}.incomplete"));
        remove_incomplete(&language_root, &staging_root)?;
        let history = load_history(&rank_root)
            .map_err(|detail| HistoricalV3RankJournalError::invalid(stage_for_open(), detail))?;
        if history
            .first()
            .is_some_and(|stored| stored.checkpoint.identity != *identity)
        {
            return Err(HistoricalV3RankJournalError::invalid(
                stage_for_open(),
                "historical-v3 journal path belongs to a different rank identity",
            ));
        }
        Ok(Self {
            identity: identity.clone(),
            rank_root,
            staging_root,
            history,
            _lock: lock,
        })
    }

    pub fn history(&self) -> &[HistoricalV3StoredRankStage] {
        &self.history
    }

    pub fn next_stage(&self) -> Option<HistoricalV3RankStage> {
        if self.history.last().is_some_and(|stored| {
            matches!(
                stored.checkpoint.outcome,
                HistoricalV3RankStageOutcome::Excluded { .. }
                    | HistoricalV3RankStageOutcome::ReadyForSourceReview { .. }
            )
        }) {
            None
        } else {
            expected_historical_v3_rank_stage(self.history.len())
        }
    }

    pub fn append<T: Serialize>(
        &mut self,
        stage: HistoricalV3RankStage,
        outcome: HistoricalV3RankStageOutcome,
        artifact: Option<&T>,
    ) -> Result<HistoricalV3RankCheckpoint, HistoricalV3RankJournalError> {
        require_artifact_shape(artifact.is_some())
            .map_err(|detail| HistoricalV3RankJournalError::invalid(stage, detail))?;
        let checkpoints = self
            .history
            .iter()
            .map(|stored| stored.checkpoint.clone())
            .collect::<Vec<_>>();
        let checkpoint =
            append_historical_v3_rank_checkpoint(&checkpoints, &self.identity, stage, outcome)
                .map_err(|detail| HistoricalV3RankJournalError::invalid(stage, detail))?;
        if self.staging_root.exists() {
            return Err(HistoricalV3RankJournalError::invalid(
                stage,
                "historical-v3 rank staging transaction already exists",
            ));
        }
        let final_root = self.rank_root.join(transaction_directory_name(
            checkpoint.sequence,
            checkpoint.stage,
        ));
        if final_root.exists() {
            return Err(HistoricalV3RankJournalError::invalid(
                stage,
                "historical-v3 rank transaction already exists",
            ));
        }
        fs::create_dir(&self.staging_root).map_err(|error| {
            HistoricalV3RankJournalError::infrastructure(
                stage,
                format!("failed to create historical-v3 stage transaction: {error}"),
            )
        })?;
        publish_stage(
            &self.staging_root,
            &self.rank_root,
            &final_root,
            &checkpoint,
            artifact,
        )
        .map_err(|detail| HistoricalV3RankJournalError::infrastructure(stage, detail))?;
        let reloaded = load_history(&self.rank_root)
            .map_err(|detail| HistoricalV3RankJournalError::invalid(stage, detail))?;
        if reloaded.len() != self.history.len() + 1
            || reloaded.last().map(|stored| &stored.checkpoint) != Some(&checkpoint)
        {
            return Err(HistoricalV3RankJournalError::invalid(
                stage,
                "published historical-v3 rank checkpoint changed",
            ));
        }
        self.history = reloaded;
        Ok(checkpoint)
    }
}

fn require_artifact_shape(has_artifact: bool) -> Result<(), String> {
    if has_artifact {
        Ok(())
    } else {
        Err("historical-v3 rank stage requires a committed artifact".to_string())
    }
}

fn stage_for_open() -> HistoricalV3RankStage {
    HistoricalV3RankStage::Materialization
}
