use super::super::history_v2_slot_store_support::{
    SlotFileLock, canonical_directory, read_limited, require_plain_directory, sha256,
    sync_directory, validate_slot_path, write_compact_json_new, write_json_new,
};
use super::{
    HistoricalV2SlotStage, HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageCheckpointInput,
    HistoricalV2SlotStageError, HistoricalV2SlotStageOutcome,
    append_historical_v2_slot_stage_checkpoint, expected_historical_v2_slot_stage,
    validate_historical_v2_slot_stage_history,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const TRANSACTION_SCHEMA_VERSION: u32 = 1;
const TRANSACTION_CONTRACT: &str = "sniffbench-historical-v2-slot-stage-transaction-v1";
const TRANSACTION_FILE: &str = "_transaction.json";
const CHECKPOINT_FILE: &str = "checkpoint.json";
const ARTIFACT_FILE: &str = "artifact.json";
const MAX_TRANSACTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SEMANTIC_CENSUS_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedFile {
    name: String,
    sha256: String,
    byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageTransaction {
    schema_version: u32,
    transaction_contract: String,
    sequence: usize,
    checkpoint_sha256: String,
    files: Vec<CommittedFile>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalV2StoredSlotStage {
    pub checkpoint: HistoricalV2SlotStageCheckpoint,
    pub artifact: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2SlotStageJournalInspection {
    pub committed_checkpoints: Vec<HistoricalV2SlotStageCheckpoint>,
    pub incomplete_stage_transaction: bool,
    pub incomplete_rewind_transaction: bool,
}

struct ExistingJournalParts {
    language_root: PathBuf,
    slot_root: PathBuf,
    staging_root: PathBuf,
    rewind_root: PathBuf,
    lock: SlotFileLock,
}

#[derive(Debug)]
pub struct HistoricalV2SlotStageJournal {
    language: String,
    slot_number: usize,
    language_root: PathBuf,
    slot_root: PathBuf,
    staging_root: PathBuf,
    rewind_root: PathBuf,
    history: Vec<HistoricalV2StoredSlotStage>,
    _lock: SlotFileLock,
}

impl HistoricalV2SlotStageJournal {
    pub fn inspect_existing(
        root: &Path,
        language: &str,
        slot_number: usize,
    ) -> Result<HistoricalV2SlotStageJournalInspection, HistoricalV2SlotStageError> {
        let stage = HistoricalV2SlotStage::Payload;
        let parts = existing_journal_parts(root, language, slot_number)?;
        let incomplete_stage_transaction = optional_plain_directory(
            &parts.staging_root,
            "incomplete historical-v2 stage transaction",
        )
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        let incomplete_rewind_transaction = optional_plain_directory(
            &parts.rewind_root,
            "incomplete historical-v2 rewind transaction",
        )
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        let committed_checkpoints = load_checkpoint_history(&parts.slot_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        drop(parts.lock);
        Ok(HistoricalV2SlotStageJournalInspection {
            committed_checkpoints,
            incomplete_stage_transaction,
            incomplete_rewind_transaction,
        })
    }

    pub fn open_existing(
        root: &Path,
        language: &str,
        slot_number: usize,
    ) -> Result<Self, HistoricalV2SlotStageError> {
        let stage = HistoricalV2SlotStage::Payload;
        let parts = existing_journal_parts(root, language, slot_number)?;
        if parts.staging_root.exists() {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 existing slot has an incomplete transaction",
            ));
        }
        reject_incomplete_rewind(&parts.rewind_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        let history = load_history(&parts.slot_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        Ok(Self {
            language: language.to_string(),
            slot_number,
            language_root: parts.language_root,
            slot_root: parts.slot_root,
            staging_root: parts.staging_root,
            rewind_root: parts.rewind_root,
            history,
            _lock: parts.lock,
        })
    }

    pub fn open(
        root: &Path,
        language: &str,
        slot_number: usize,
    ) -> Result<Self, HistoricalV2SlotStageError> {
        let stage = HistoricalV2SlotStage::Payload;
        validate_slot_path(language, slot_number)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        fs::create_dir_all(root).map_err(|error| {
            HistoricalV2SlotStageError::infrastructure(
                stage,
                format!("failed to create historical-v2 state root: {error}"),
            )
        })?;
        let root = canonical_directory(root, "historical-v2 state root")
            .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
        let language_root = root.join(language);
        fs::create_dir_all(&language_root).map_err(|error| {
            HistoricalV2SlotStageError::infrastructure(
                stage,
                format!("failed to create historical-v2 language state: {error}"),
            )
        })?;
        require_plain_directory(&language_root, "historical-v2 language state")
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        let language_root = canonical_directory(&language_root, "historical-v2 language state")
            .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
        if language_root.parent() != Some(root.as_path()) {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 language state escaped its root",
            ));
        }
        let slot_name = format!("slot-{slot_number:04}");
        let lock = SlotFileLock::acquire(&language_root.join(format!("{slot_name}.lock")))
            .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
        let slot_root = language_root.join(&slot_name);
        if slot_root.exists() {
            require_plain_directory(&slot_root, "historical-v2 slot journal")
                .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        } else {
            fs::create_dir(&slot_root).map_err(|error| {
                HistoricalV2SlotStageError::infrastructure(
                    stage,
                    format!("failed to create historical-v2 slot journal: {error}"),
                )
            })?;
            sync_directory(&language_root)
                .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
        }
        let staging_root = language_root.join(format!(".{slot_name}.incomplete"));
        remove_incomplete(&language_root, &staging_root)
            .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
        let rewind_root = language_root.join(format!(".{slot_name}.rewinding"));
        reject_incomplete_rewind(&rewind_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        let history = load_history(&slot_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        Ok(Self {
            language: language.to_string(),
            slot_number,
            language_root,
            slot_root,
            staging_root,
            rewind_root,
            history,
            _lock: lock,
        })
    }

    pub fn history(&self) -> &[HistoricalV2StoredSlotStage] {
        &self.history
    }

    pub fn rewind_completed_after(
        &mut self,
        retained_stage: HistoricalV2SlotStage,
    ) -> Result<usize, HistoricalV2SlotStageError> {
        let current = load_history(&self.slot_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(retained_stage, detail))?;
        if current != self.history {
            return Err(HistoricalV2SlotStageError::invalid(
                retained_stage,
                "historical-v2 slot journal changed after it was opened",
            ));
        }
        let retained_index = current
            .iter()
            .position(|stored| stored.checkpoint.stage == retained_stage)
            .ok_or_else(|| {
                HistoricalV2SlotStageError::invalid(
                    retained_stage,
                    "historical-v2 rewind stage is not committed",
                )
            })?;
        let removed = current.len().saturating_sub(retained_index + 1);
        if removed == 0 {
            return Err(HistoricalV2SlotStageError::invalid(
                retained_stage,
                "historical-v2 rewind has no completed suffix",
            ));
        }
        if current.iter().any(|stored| {
            !matches!(
                stored.checkpoint.outcome,
                HistoricalV2SlotStageOutcome::Completed { .. }
            )
        }) {
            return Err(HistoricalV2SlotStageError::invalid(
                retained_stage,
                "historical-v2 rewind requires an entirely completed history",
            ));
        }
        reject_incomplete_rewind(&self.rewind_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(retained_stage, detail))?;
        fs::create_dir(&self.rewind_root).map_err(|error| {
            HistoricalV2SlotStageError::infrastructure(
                retained_stage,
                format!("failed to create historical-v2 rewind quarantine: {error}"),
            )
        })?;
        sync_directory(&self.language_root)
            .map_err(|detail| HistoricalV2SlotStageError::infrastructure(retained_stage, detail))?;

        for stored in current.iter().skip(retained_index + 1).rev() {
            let name =
                transaction_directory_name(stored.checkpoint.sequence, stored.checkpoint.stage);
            fs::rename(self.slot_root.join(&name), self.rewind_root.join(&name)).map_err(
                |error| {
                    HistoricalV2SlotStageError::infrastructure(
                        retained_stage,
                        format!("failed to quarantine historical-v2 stage {name}: {error}"),
                    )
                },
            )?;
            sync_directory(&self.slot_root).map_err(|detail| {
                HistoricalV2SlotStageError::infrastructure(retained_stage, detail)
            })?;
            sync_directory(&self.rewind_root).map_err(|detail| {
                HistoricalV2SlotStageError::infrastructure(retained_stage, detail)
            })?;
        }

        let retained = load_history(&self.slot_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(retained_stage, detail))?;
        if retained != current[..=retained_index] {
            return Err(HistoricalV2SlotStageError::invalid(
                retained_stage,
                "historical-v2 retained journal prefix changed during rewind",
            ));
        }
        fs::remove_dir_all(&self.rewind_root).map_err(|error| {
            HistoricalV2SlotStageError::infrastructure(
                retained_stage,
                format!("failed to remove historical-v2 rewind quarantine: {error}"),
            )
        })?;
        sync_directory(&self.language_root)
            .map_err(|detail| HistoricalV2SlotStageError::infrastructure(retained_stage, detail))?;
        self.history = retained;
        Ok(removed)
    }

    pub fn append<T: Serialize>(
        &mut self,
        input: HistoricalV2SlotStageCheckpointInput<'_>,
        artifact: Option<&T>,
    ) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
        let stage = input.stage;
        if input.language != self.language || input.slot_number != self.slot_number {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 checkpoint identity does not match its journal path",
            ));
        }
        require_artifact_shape(&input.outcome, artifact.is_some())
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        let checkpoints = self
            .history
            .iter()
            .map(|stored| stored.checkpoint.clone())
            .collect::<Vec<_>>();
        let checkpoint = append_historical_v2_slot_stage_checkpoint(&checkpoints, input)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        if self.staging_root.exists() {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 slot staging transaction already exists",
            ));
        }
        let final_root = self.slot_root.join(transaction_directory_name(
            checkpoint.sequence,
            checkpoint.stage,
        ));
        if final_root.exists() {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "historical-v2 slot stage transaction already exists",
            ));
        }
        fs::create_dir(&self.staging_root).map_err(|error| {
            HistoricalV2SlotStageError::infrastructure(
                stage,
                format!("failed to create historical-v2 stage transaction: {error}"),
            )
        })?;
        let publish = publish_stage(
            &self.staging_root,
            &self.slot_root,
            &final_root,
            &checkpoint,
            artifact,
        );
        if let Err(detail) = publish {
            return Err(HistoricalV2SlotStageError::infrastructure(stage, detail));
        }
        let reloaded = load_history(&self.slot_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        if reloaded.len() != self.history.len() + 1
            || reloaded.last().map(|stored| &stored.checkpoint) != Some(&checkpoint)
        {
            return Err(HistoricalV2SlotStageError::invalid(
                stage,
                "published historical-v2 stage checkpoint changed",
            ));
        }
        self.history = reloaded;
        Ok(checkpoint)
    }
}

fn existing_journal_parts(
    root: &Path,
    language: &str,
    slot_number: usize,
) -> Result<ExistingJournalParts, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::Payload;
    validate_slot_path(language, slot_number)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    require_plain_directory(root, "historical-v2 state root")
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    let root = canonical_directory(root, "historical-v2 state root")
        .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
    let language_root = root.join(language);
    require_plain_directory(&language_root, "historical-v2 language state")
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    let language_root = canonical_directory(&language_root, "historical-v2 language state")
        .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
    if language_root.parent() != Some(root.as_path()) {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 language state escaped its root",
        ));
    }
    let slot_name = format!("slot-{slot_number:04}");
    let lock_path = language_root.join(format!("{slot_name}.lock"));
    let lock_metadata = fs::symlink_metadata(&lock_path).map_err(|error| {
        HistoricalV2SlotStageError::invalid(
            stage,
            format!("historical-v2 existing slot lock is missing: {error}"),
        )
    })?;
    if !lock_metadata.is_file() || lock_metadata.file_type().is_symlink() {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 existing slot lock is not a plain file",
        ));
    }
    let lock = SlotFileLock::acquire(&lock_path)
        .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
    let slot_root = language_root.join(&slot_name);
    require_plain_directory(&slot_root, "historical-v2 slot journal")
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    let slot_root = canonical_directory(&slot_root, "historical-v2 slot journal")
        .map_err(|detail| HistoricalV2SlotStageError::infrastructure(stage, detail))?;
    if slot_root.parent() != Some(language_root.as_path()) {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 slot journal escaped its language root",
        ));
    }
    Ok(ExistingJournalParts {
        staging_root: language_root.join(format!(".{slot_name}.incomplete")),
        rewind_root: language_root.join(format!(".{slot_name}.rewinding")),
        language_root,
        slot_root,
        lock,
    })
}

fn optional_plain_directory(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(format!("{label} is not a plain directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect {label}: {error}")),
    }
}

fn publish_stage<T: Serialize>(
    staging_root: &Path,
    slot_root: &Path,
    final_root: &Path,
    checkpoint: &HistoricalV2SlotStageCheckpoint,
    artifact: Option<&T>,
) -> Result<(), String> {
    write_json_new(
        &staging_root.join(CHECKPOINT_FILE),
        checkpoint,
        MAX_CHECKPOINT_BYTES,
    )?;
    if let Some(artifact) = artifact {
        write_compact_json_new(
            &staging_root.join(ARTIFACT_FILE),
            artifact,
            artifact_limit(checkpoint.stage),
        )?;
    }
    let files = committed_files(staging_root, artifact.is_some(), checkpoint.stage)?;
    let transaction = StageTransaction {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_contract: TRANSACTION_CONTRACT.to_string(),
        sequence: checkpoint.sequence,
        checkpoint_sha256: checkpoint.checkpoint_sha256.clone(),
        files,
    };
    write_json_new(
        &staging_root.join(TRANSACTION_FILE),
        &transaction,
        MAX_TRANSACTION_BYTES,
    )?;
    sync_directory(staging_root)?;
    fs::rename(staging_root, final_root)
        .map_err(|error| format!("failed to publish historical-v2 stage transaction: {error}"))?;
    sync_directory(slot_root)
}

fn load_history(root: &Path) -> Result<Vec<HistoricalV2StoredSlotStage>, String> {
    let directories = transaction_directories(root)?;
    let mut stored = Vec::with_capacity(directories.len());
    for (sequence, path) in directories {
        stored.push(load_stage(&path, sequence)?);
    }
    let checkpoints = stored
        .iter()
        .map(|value| value.checkpoint.clone())
        .collect::<Vec<_>>();
    validate_historical_v2_slot_stage_history(&checkpoints)?;
    Ok(stored)
}

fn load_checkpoint_history(root: &Path) -> Result<Vec<HistoricalV2SlotStageCheckpoint>, String> {
    let checkpoints = transaction_directories(root)?
        .into_iter()
        .map(|(sequence, path)| load_stage_checkpoint(&path, sequence))
        .collect::<Result<Vec<_>, _>>()?;
    validate_historical_v2_slot_stage_history(&checkpoints)?;
    Ok(checkpoints)
}

fn transaction_directories(root: &Path) -> Result<Vec<(usize, PathBuf)>, String> {
    let mut directories = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical-v2 slot journal: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("failed to inspect historical-v2 slot journal: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to inspect historical-v2 slot journal: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("historical-v2 slot journal contains a non-directory".to_string());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "historical-v2 stage directory name is not UTF-8".to_string())?;
        directories.push((name, path));
    }
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    let mut transactions = Vec::with_capacity(directories.len());
    for (index, (name, path)) in directories.into_iter().enumerate() {
        let stage = expected_historical_v2_slot_stage(index)
            .ok_or_else(|| "historical-v2 slot journal has too many stages".to_string())?;
        let sequence = index + 1;
        if name != transaction_directory_name(sequence, stage) {
            return Err("historical-v2 slot journal stage sequence changed".to_string());
        }
        transactions.push((sequence, path));
    }
    Ok(transactions)
}

fn load_stage_checkpoint(
    root: &Path,
    sequence: usize,
) -> Result<HistoricalV2SlotStageCheckpoint, String> {
    require_plain_directory(root, "historical-v2 stage transaction")?;
    let checkpoint = serde_json::from_slice::<HistoricalV2SlotStageCheckpoint>(&read_limited(
        &root.join(CHECKPOINT_FILE),
        MAX_CHECKPOINT_BYTES,
        "stage checkpoint",
    )?)
    .map_err(|error| format!("invalid historical-v2 stage checkpoint: {error}"))?;
    let has_artifact = !matches!(
        checkpoint.outcome,
        HistoricalV2SlotStageOutcome::ReadyForReview
    );
    let names = transaction_file_names(root)?;
    let expected_names = if has_artifact {
        vec![TRANSACTION_FILE, ARTIFACT_FILE, CHECKPOINT_FILE]
    } else {
        vec![TRANSACTION_FILE, CHECKPOINT_FILE]
    };
    if names != expected_names {
        return Err("historical-v2 stage transaction file set changed".to_string());
    }
    let transaction = serde_json::from_slice::<StageTransaction>(&read_limited(
        &root.join(TRANSACTION_FILE),
        MAX_TRANSACTION_BYTES,
        "stage transaction",
    )?)
    .map_err(|error| format!("invalid historical-v2 stage transaction: {error}"))?;
    if transaction.schema_version != TRANSACTION_SCHEMA_VERSION
        || transaction.transaction_contract != TRANSACTION_CONTRACT
        || transaction.sequence != sequence
        || transaction.checkpoint_sha256 != checkpoint.checkpoint_sha256
        || transaction.files != committed_files_streaming(root, has_artifact, checkpoint.stage)?
    {
        return Err("historical-v2 stage transaction commitment changed".to_string());
    }
    Ok(checkpoint)
}

fn load_stage(root: &Path, sequence: usize) -> Result<HistoricalV2StoredSlotStage, String> {
    require_plain_directory(root, "historical-v2 stage transaction")?;
    let checkpoint = serde_json::from_slice::<HistoricalV2SlotStageCheckpoint>(&read_limited(
        &root.join(CHECKPOINT_FILE),
        MAX_CHECKPOINT_BYTES,
        "stage checkpoint",
    )?)
    .map_err(|error| format!("invalid historical-v2 stage checkpoint: {error}"))?;
    let has_artifact = !matches!(
        checkpoint.outcome,
        HistoricalV2SlotStageOutcome::ReadyForReview
    );
    let names = transaction_file_names(root)?;
    let expected_names = if has_artifact {
        vec![TRANSACTION_FILE, ARTIFACT_FILE, CHECKPOINT_FILE]
    } else {
        vec![TRANSACTION_FILE, CHECKPOINT_FILE]
    };
    if names != expected_names {
        return Err("historical-v2 stage transaction file set changed".to_string());
    }
    let transaction = serde_json::from_slice::<StageTransaction>(&read_limited(
        &root.join(TRANSACTION_FILE),
        MAX_TRANSACTION_BYTES,
        "stage transaction",
    )?)
    .map_err(|error| format!("invalid historical-v2 stage transaction: {error}"))?;
    if transaction.schema_version != TRANSACTION_SCHEMA_VERSION
        || transaction.transaction_contract != TRANSACTION_CONTRACT
        || transaction.sequence != sequence
        || transaction.checkpoint_sha256 != checkpoint.checkpoint_sha256
        || transaction.files != committed_files(root, has_artifact, checkpoint.stage)?
    {
        return Err("historical-v2 stage transaction commitment changed".to_string());
    }
    let artifact = has_artifact
        .then(|| {
            serde_json::from_slice::<Value>(&read_limited(
                &root.join(ARTIFACT_FILE),
                artifact_limit(checkpoint.stage),
                "stage artifact",
            )?)
            .map_err(|error| format!("invalid historical-v2 stage artifact: {error}"))
        })
        .transpose()?;
    Ok(HistoricalV2StoredSlotStage {
        checkpoint,
        artifact,
    })
}

fn committed_files(
    root: &Path,
    has_artifact: bool,
    stage: HistoricalV2SlotStage,
) -> Result<Vec<CommittedFile>, String> {
    let mut inputs = vec![(CHECKPOINT_FILE, MAX_CHECKPOINT_BYTES)];
    if has_artifact {
        inputs.insert(0, (ARTIFACT_FILE, artifact_limit(stage)));
    }
    inputs
        .into_iter()
        .map(|(name, limit)| {
            let bytes = read_limited(&root.join(name), limit, name)?;
            Ok(CommittedFile {
                name: name.to_string(),
                sha256: sha256(&bytes),
                byte_count: u64::try_from(bytes.len())
                    .map_err(|_| "historical-v2 stage artifact size overflowed".to_string())?,
            })
        })
        .collect()
}

fn committed_files_streaming(
    root: &Path,
    has_artifact: bool,
    stage: HistoricalV2SlotStage,
) -> Result<Vec<CommittedFile>, String> {
    let mut inputs = vec![(CHECKPOINT_FILE, MAX_CHECKPOINT_BYTES)];
    if has_artifact {
        inputs.insert(0, (ARTIFACT_FILE, artifact_limit(stage)));
    }
    inputs
        .into_iter()
        .map(|(name, limit)| committed_file_streaming(&root.join(name), name, limit))
        .collect()
}

fn committed_file_streaming(path: &Path, name: &str, limit: u64) -> Result<CommittedFile, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("failed to inspect {name}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{name} is not a plain file"));
    }
    if metadata.len() > limit {
        return Err(format!(
            "{name} exceeds its size limit: {} bytes observed, {limit} bytes allowed",
            metadata.len()
        ));
    }
    let mut file = File::open(path).map_err(|error| format!("failed to read {name}: {error}"))?;
    let mut hasher = Sha256::new();
    let mut byte_count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {name}: {error}"))?;
        if read == 0 {
            break;
        }
        let read_bytes = u64::try_from(read).map_err(|_| format!("{name} size overflowed"))?;
        byte_count = byte_count
            .checked_add(read_bytes)
            .ok_or_else(|| format!("{name} size overflowed"))?;
        if byte_count > limit {
            return Err(format!(
                "{name} exceeds its size limit: more than {limit} bytes observed"
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(CommittedFile {
        name: name.to_string(),
        sha256: format!("{:x}", hasher.finalize()),
        byte_count,
    })
}

fn artifact_limit(stage: HistoricalV2SlotStage) -> u64 {
    match stage {
        HistoricalV2SlotStage::SemanticCensus => MAX_SEMANTIC_CENSUS_ARTIFACT_BYTES,
        HistoricalV2SlotStage::Payload
        | HistoricalV2SlotStage::Materialization
        | HistoricalV2SlotStage::TestMaterialization
        | HistoricalV2SlotStage::SourceCensus
        | HistoricalV2SlotStage::AssessmentIdentity
        | HistoricalV2SlotStage::Qualification
        | HistoricalV2SlotStage::TestRecipe
        | HistoricalV2SlotStage::IdenticalTests
        | HistoricalV2SlotStage::ReadyForReview => MAX_ARTIFACT_BYTES,
    }
}

fn transaction_file_names(root: &Path) -> Result<Vec<&'static str>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical-v2 stage transaction: {error}"))?
    {
        let entry = entry.map_err(|error| {
            format!("failed to inspect historical-v2 stage transaction: {error}")
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            format!("failed to inspect historical-v2 stage transaction: {error}")
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("historical-v2 stage transaction contains a non-file".to_string());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "historical-v2 stage filename is not UTF-8".to_string())?;
        names.push(match name.as_str() {
            ARTIFACT_FILE => ARTIFACT_FILE,
            CHECKPOINT_FILE => CHECKPOINT_FILE,
            TRANSACTION_FILE => TRANSACTION_FILE,
            _ => return Err(format!("unexpected historical-v2 stage file: {name}")),
        });
    }
    names.sort_unstable();
    Ok(names)
}

fn require_artifact_shape(
    outcome: &HistoricalV2SlotStageOutcome,
    has_artifact: bool,
) -> Result<(), String> {
    let requires_artifact = !matches!(outcome, HistoricalV2SlotStageOutcome::ReadyForReview);
    if requires_artifact == has_artifact {
        Ok(())
    } else {
        Err("historical-v2 completed and excluded stages require exactly one artifact".to_string())
    }
}

fn transaction_directory_name(sequence: usize, stage: HistoricalV2SlotStage) -> String {
    format!("{sequence:04}-{}", stage_name(stage))
}

fn stage_name(stage: HistoricalV2SlotStage) -> &'static str {
    match stage {
        HistoricalV2SlotStage::Payload => "payload",
        HistoricalV2SlotStage::Materialization => "materialization",
        HistoricalV2SlotStage::TestMaterialization => "test-materialization",
        HistoricalV2SlotStage::SourceCensus => "source-census",
        HistoricalV2SlotStage::SemanticCensus => "semantic-census",
        HistoricalV2SlotStage::AssessmentIdentity => "assessment-identity",
        HistoricalV2SlotStage::Qualification => "qualification",
        HistoricalV2SlotStage::TestRecipe => "test-recipe",
        HistoricalV2SlotStage::IdenticalTests => "identical-tests",
        HistoricalV2SlotStage::ReadyForReview => "ready-for-review",
    }
}

fn remove_incomplete(language_root: &Path, staging_root: &Path) -> Result<(), String> {
    if !staging_root.exists() {
        return Ok(());
    }
    require_plain_directory(staging_root, "incomplete historical-v2 stage transaction")?;
    fs::remove_dir_all(staging_root).map_err(|error| {
        format!("failed to remove incomplete historical-v2 stage transaction: {error}")
    })?;
    sync_directory(language_root)
}

fn reject_incomplete_rewind(rewind_root: &Path) -> Result<(), String> {
    match fs::symlink_metadata(rewind_root) {
        Ok(_) => Err("historical-v2 slot has an incomplete rewind transaction".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect historical-v2 rewind transaction: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_census_has_the_only_expanded_artifact_bound() {
        assert_eq!(
            artifact_limit(HistoricalV2SlotStage::SemanticCensus),
            512 * 1024 * 1024
        );
        for stage in [
            HistoricalV2SlotStage::Payload,
            HistoricalV2SlotStage::Materialization,
            HistoricalV2SlotStage::TestMaterialization,
            HistoricalV2SlotStage::SourceCensus,
            HistoricalV2SlotStage::AssessmentIdentity,
            HistoricalV2SlotStage::Qualification,
            HistoricalV2SlotStage::TestRecipe,
            HistoricalV2SlotStage::IdenticalTests,
            HistoricalV2SlotStage::ReadyForReview,
        ] {
            assert_eq!(artifact_limit(stage), 128 * 1024 * 1024, "{stage:?}");
        }
    }
}
