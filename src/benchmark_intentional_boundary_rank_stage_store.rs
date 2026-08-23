use super::super::history_v2_slot_store_support::{
    SlotFileLock, canonical_directory, read_limited, require_plain_directory, sha256,
    sync_directory, write_json_new,
};
use super::{
    IntentionalBoundaryFrameTask, IntentionalBoundaryRankStage,
    IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageCheckpoint,
    IntentionalBoundaryRankStageCheckpointInput, IntentionalBoundaryRankStageError,
    IntentionalBoundaryRankStageOutcome, append_intentional_boundary_rank_stage_checkpoint,
    expected_intentional_boundary_rank_stage, next_intentional_boundary_rank_stage,
    validate_artifact_identity, validate_intentional_boundary_rank_stage_history,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[path = "benchmark_intentional_boundary_rank_stage_store_support.rs"]
mod support;
use support::*;

const TRANSACTION_SCHEMA_VERSION: u32 = 1;
const TRANSACTION_CONTRACT: &str = "sniffbench-intentional-boundary-rank-stage-transaction-v1";
const TRANSACTION_FILE: &str = "_transaction.json";
const CHECKPOINT_FILE: &str = "checkpoint.json";
const ARTIFACT_FILE: &str = "artifact.json";
const MAX_TRANSACTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryStoredRankStage {
    pub checkpoint: IntentionalBoundaryRankStageCheckpoint,
    pub artifact: IntentionalBoundaryRankStageArtifact,
}

#[derive(Debug)]
pub struct IntentionalBoundaryRankStageJournal {
    frame_task_sha256: String,
    population_rank: usize,
    population_rank_sha256: String,
    repository: String,
    rank_root: PathBuf,
    staging_root: PathBuf,
    history: Vec<IntentionalBoundaryStoredRankStage>,
    _lock: SlotFileLock,
}

impl IntentionalBoundaryRankStageJournal {
    pub fn open(
        root: &Path,
        task: &IntentionalBoundaryFrameTask,
        population_rank: usize,
    ) -> Result<Self, IntentionalBoundaryRankStageError> {
        let stage = IntentionalBoundaryRankStage::Materialization;
        let repository = expected_repository(task, population_rank)
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        fs::create_dir_all(root).map_err(|error| {
            IntentionalBoundaryRankStageError::infrastructure(
                stage,
                format!("failed to create intentional-boundary rank state: {error}"),
            )
        })?;
        require_plain_directory(root, "intentional-boundary rank state")
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        let root = canonical_directory(root, "intentional-boundary rank state")
            .map_err(|detail| IntentionalBoundaryRankStageError::infrastructure(stage, detail))?;
        let rank_name = rank_name(population_rank);
        let lock = SlotFileLock::acquire(&root.join(format!("{rank_name}.lock")))
            .map_err(|detail| IntentionalBoundaryRankStageError::infrastructure(stage, detail))?;
        let rank_root = root.join(&rank_name);
        if rank_root.exists() {
            require_plain_directory(&rank_root, "intentional-boundary rank journal")
                .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        } else {
            fs::create_dir(&rank_root).map_err(|error| {
                IntentionalBoundaryRankStageError::infrastructure(
                    stage,
                    format!("failed to create intentional-boundary rank journal: {error}"),
                )
            })?;
            sync_directory(&root).map_err(|detail| {
                IntentionalBoundaryRankStageError::infrastructure(stage, detail)
            })?;
        }
        let rank_root = canonical_directory(&rank_root, "intentional-boundary rank journal")
            .map_err(|detail| IntentionalBoundaryRankStageError::infrastructure(stage, detail))?;
        if rank_root.parent() != Some(root.as_path()) {
            return Err(IntentionalBoundaryRankStageError::invalid(
                stage,
                "intentional-boundary rank journal escaped its state root",
            ));
        }
        let staging_root = root.join(format!(".{rank_name}.incomplete"));
        remove_incomplete(&root, &staging_root)
            .map_err(|detail| IntentionalBoundaryRankStageError::infrastructure(stage, detail))?;
        let history = load_history(&rank_root)
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        validate_journal_identity(task, population_rank, &history)
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        Ok(Self {
            frame_task_sha256: task.task_sha256.clone(),
            population_rank,
            population_rank_sha256: repository.population_rank_sha256.clone(),
            repository: repository.repository.clone(),
            rank_root,
            staging_root,
            history,
            _lock: lock,
        })
    }

    pub fn history(&self) -> &[IntentionalBoundaryStoredRankStage] {
        &self.history
    }

    pub fn next_stage(
        &self,
    ) -> Result<Option<IntentionalBoundaryRankStage>, IntentionalBoundaryRankStageError> {
        let checkpoints = checkpoints(&self.history);
        next_intentional_boundary_rank_stage(&checkpoints).map_err(|detail| {
            IntentionalBoundaryRankStageError::invalid(current_stage(&checkpoints), detail)
        })
    }

    pub fn append(
        &mut self,
        task: &IntentionalBoundaryFrameTask,
        artifact: &IntentionalBoundaryRankStageArtifact,
    ) -> Result<IntentionalBoundaryRankStageCheckpoint, IntentionalBoundaryRankStageError> {
        let stage = artifact.stage();
        self.validate_task(task, stage)?;
        validate_artifact_identity(task, self.population_rank, artifact)
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        validate_inventory_lineage(&self.history, artifact)
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        let artifact_bytes = pretty_json(artifact)
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        if u64::try_from(artifact_bytes.len()).unwrap_or(u64::MAX) > MAX_ARTIFACT_BYTES {
            return Err(IntentionalBoundaryRankStageError::invalid(
                stage,
                "intentional-boundary rank artifact exceeds its size limit",
            ));
        }
        let checkpoint = append_intentional_boundary_rank_stage_checkpoint(
            &checkpoints(&self.history),
            IntentionalBoundaryRankStageCheckpointInput {
                frame_task_sha256: &self.frame_task_sha256,
                population_rank: self.population_rank,
                population_rank_sha256: &self.population_rank_sha256,
                repository: &self.repository,
                stage,
                artifact_kind: artifact.kind(),
                artifact_sha256: &sha256(&artifact_bytes),
                excluded: artifact.is_exclusion(),
            },
        )
        .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        if self.staging_root.exists() {
            return Err(IntentionalBoundaryRankStageError::invalid(
                stage,
                "intentional-boundary rank staging transaction already exists",
            ));
        }
        let final_root = self
            .rank_root
            .join(transaction_directory_name(checkpoint.sequence, stage));
        if final_root.exists() {
            return Err(IntentionalBoundaryRankStageError::invalid(
                stage,
                "intentional-boundary rank stage transaction already exists",
            ));
        }
        fs::create_dir(&self.staging_root).map_err(|error| {
            IntentionalBoundaryRankStageError::infrastructure(
                stage,
                format!("failed to create intentional-boundary stage transaction: {error}"),
            )
        })?;
        publish_stage(
            &self.staging_root,
            &self.rank_root,
            &final_root,
            &checkpoint,
            artifact,
        )
        .map_err(|detail| IntentionalBoundaryRankStageError::infrastructure(stage, detail))?;
        let reloaded = load_history(&self.rank_root)
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        if reloaded.len() != self.history.len() + 1
            || reloaded.last().map(|stored| &stored.checkpoint) != Some(&checkpoint)
        {
            return Err(IntentionalBoundaryRankStageError::invalid(
                stage,
                "published intentional-boundary rank checkpoint changed",
            ));
        }
        self.history = reloaded;
        Ok(checkpoint)
    }

    fn validate_task(
        &self,
        task: &IntentionalBoundaryFrameTask,
        stage: IntentionalBoundaryRankStage,
    ) -> Result<(), IntentionalBoundaryRankStageError> {
        let repository = expected_repository(task, self.population_rank)
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        if task.task_sha256 != self.frame_task_sha256
            || repository.population_rank_sha256 != self.population_rank_sha256
            || repository.repository != self.repository
        {
            return Err(IntentionalBoundaryRankStageError::invalid(
                stage,
                "intentional-boundary frame task changed while rank journal was open",
            ));
        }
        Ok(())
    }
}

fn publish_stage(
    staging_root: &Path,
    rank_root: &Path,
    final_root: &Path,
    checkpoint: &IntentionalBoundaryRankStageCheckpoint,
    artifact: &IntentionalBoundaryRankStageArtifact,
) -> Result<(), String> {
    write_json_new(
        &staging_root.join(CHECKPOINT_FILE),
        checkpoint,
        MAX_CHECKPOINT_BYTES,
    )?;
    write_json_new(
        &staging_root.join(ARTIFACT_FILE),
        artifact,
        MAX_ARTIFACT_BYTES,
    )?;
    let transaction = StageTransaction {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        transaction_contract: TRANSACTION_CONTRACT.to_string(),
        sequence: checkpoint.sequence,
        checkpoint_sha256: checkpoint.checkpoint_sha256.clone(),
        files: committed_files(staging_root)?,
    };
    write_json_new(
        &staging_root.join(TRANSACTION_FILE),
        &transaction,
        MAX_TRANSACTION_BYTES,
    )?;
    sync_directory(staging_root)?;
    fs::rename(staging_root, final_root)
        .map_err(|error| format!("failed to publish intentional-boundary rank stage: {error}"))?;
    sync_directory(rank_root)
}

fn load_history(root: &Path) -> Result<Vec<IntentionalBoundaryStoredRankStage>, String> {
    let mut directories = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect intentional-boundary rank journal: {error}"))?
    {
        let entry = entry.map_err(|error| {
            format!("failed to inspect intentional-boundary rank journal: {error}")
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            format!("failed to inspect intentional-boundary rank journal: {error}")
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("intentional-boundary rank journal contains a non-directory".to_string());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "intentional-boundary stage directory name is not UTF-8".to_string())?;
        directories.push((name, entry.path()));
    }
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    let mut stored = Vec::with_capacity(directories.len());
    for (index, (name, path)) in directories.into_iter().enumerate() {
        let stage = expected_intentional_boundary_rank_stage(index)
            .ok_or_else(|| "intentional-boundary rank journal has too many stages".to_string())?;
        let sequence = index + 1;
        if name != transaction_directory_name(sequence, stage) {
            return Err("intentional-boundary rank journal stage sequence changed".to_string());
        }
        stored.push(load_stage(&path, sequence)?);
    }
    validate_intentional_boundary_rank_stage_history(&checkpoints(&stored))?;
    for pair in stored.windows(2) {
        validate_inventory_lineage(&pair[..1], &pair[1].artifact)?;
    }
    Ok(stored)
}

fn load_stage(root: &Path, sequence: usize) -> Result<IntentionalBoundaryStoredRankStage, String> {
    require_plain_directory(root, "intentional-boundary rank stage transaction")?;
    let names = transaction_file_names(root)?;
    if names != [TRANSACTION_FILE, ARTIFACT_FILE, CHECKPOINT_FILE] {
        return Err("intentional-boundary rank transaction file set changed".to_string());
    }
    let checkpoint_bytes = read_limited(
        &root.join(CHECKPOINT_FILE),
        MAX_CHECKPOINT_BYTES,
        "rank stage checkpoint",
    )?;
    let checkpoint =
        serde_json::from_slice::<IntentionalBoundaryRankStageCheckpoint>(&checkpoint_bytes)
            .map_err(|error| format!("invalid intentional-boundary rank checkpoint: {error}"))?;
    let artifact_bytes = read_limited(
        &root.join(ARTIFACT_FILE),
        MAX_ARTIFACT_BYTES,
        "rank stage artifact",
    )?;
    let artifact = serde_json::from_slice::<IntentionalBoundaryRankStageArtifact>(&artifact_bytes)
        .map_err(|error| format!("invalid intentional-boundary rank artifact: {error}"))?;
    let transaction = serde_json::from_slice::<StageTransaction>(&read_limited(
        &root.join(TRANSACTION_FILE),
        MAX_TRANSACTION_BYTES,
        "rank stage transaction",
    )?)
    .map_err(|error| format!("invalid intentional-boundary rank transaction: {error}"))?;
    if transaction.schema_version != TRANSACTION_SCHEMA_VERSION
        || transaction.transaction_contract != TRANSACTION_CONTRACT
        || transaction.sequence != sequence
        || transaction.checkpoint_sha256 != checkpoint.checkpoint_sha256
        || transaction.files != committed_files(root)?
        || artifact.stage() != checkpoint.stage
        || artifact.kind() != outcome_kind(&checkpoint.outcome)
        || artifact.is_exclusion()
            != matches!(
                checkpoint.outcome,
                IntentionalBoundaryRankStageOutcome::Excluded { .. }
            )
        || sha256(&artifact_bytes) != outcome_hash(&checkpoint.outcome)
    {
        return Err("intentional-boundary rank transaction commitment changed".to_string());
    }
    Ok(IntentionalBoundaryStoredRankStage {
        checkpoint,
        artifact,
    })
}

fn validate_journal_identity(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    history: &[IntentionalBoundaryStoredRankStage],
) -> Result<(), String> {
    let repository = expected_repository(task, population_rank)?;
    for stored in history {
        let checkpoint = &stored.checkpoint;
        if checkpoint.frame_task_sha256 != task.task_sha256
            || checkpoint.population_rank != population_rank
            || checkpoint.population_rank_sha256 != repository.population_rank_sha256
            || checkpoint.repository != repository.repository
        {
            return Err("intentional-boundary rank journal identity changed".to_string());
        }
        validate_artifact_identity(task, population_rank, &stored.artifact)?;
    }
    Ok(())
}

fn validate_inventory_lineage(
    history: &[IntentionalBoundaryStoredRankStage],
    artifact: &IntentionalBoundaryRankStageArtifact,
) -> Result<(), String> {
    let IntentionalBoundaryRankStageArtifact::Inventory(inventory) = artifact else {
        return Ok(());
    };
    let Some(IntentionalBoundaryStoredRankStage {
        artifact: IntentionalBoundaryRankStageArtifact::Materialization(materialization),
        ..
    }) = history.last()
    else {
        return Err(
            "intentional-boundary inventory requires a completed materialization".to_string(),
        );
    };
    if inventory.repository != materialization.repository
        || inventory.revision != materialization.revision
    {
        return Err("intentional-boundary inventory changed materialized identity".to_string());
    }
    Ok(())
}

fn committed_files(root: &Path) -> Result<Vec<CommittedFile>, String> {
    [
        (ARTIFACT_FILE, MAX_ARTIFACT_BYTES),
        (CHECKPOINT_FILE, MAX_CHECKPOINT_BYTES),
    ]
    .into_iter()
    .map(|(name, limit)| {
        let bytes = read_limited(&root.join(name), limit, name)?;
        Ok(CommittedFile {
            name: name.to_string(),
            sha256: sha256(&bytes),
            byte_count: u64::try_from(bytes.len())
                .map_err(|_| "intentional-boundary rank artifact size overflowed".to_string())?,
        })
    })
    .collect()
}

fn transaction_file_names(root: &Path) -> Result<Vec<&'static str>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| {
        format!("failed to inspect intentional-boundary rank transaction: {error}")
    })? {
        let entry = entry.map_err(|error| {
            format!("failed to inspect intentional-boundary rank transaction: {error}")
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            format!("failed to inspect intentional-boundary rank transaction: {error}")
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("intentional-boundary rank transaction contains a non-file".to_string());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "intentional-boundary rank filename is not UTF-8".to_string())?;
        names.push(match name.as_str() {
            ARTIFACT_FILE => ARTIFACT_FILE,
            CHECKPOINT_FILE => CHECKPOINT_FILE,
            TRANSACTION_FILE => TRANSACTION_FILE,
            _ => return Err(format!("unexpected intentional-boundary rank file: {name}")),
        });
    }
    names.sort_unstable();
    Ok(names)
}

fn checkpoints(
    history: &[IntentionalBoundaryStoredRankStage],
) -> Vec<IntentionalBoundaryRankStageCheckpoint> {
    history
        .iter()
        .map(|stored| stored.checkpoint.clone())
        .collect()
}
