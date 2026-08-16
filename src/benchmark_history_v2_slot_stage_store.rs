use super::super::history_v2_slot_store_support::{
    SlotFileLock, canonical_directory, read_limited, require_plain_directory, sha256,
    sync_directory, validate_slot_path, write_json_new,
};
use super::{
    HistoricalV2SlotStage, HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageCheckpointInput,
    HistoricalV2SlotStageError, HistoricalV2SlotStageOutcome,
    append_historical_v2_slot_stage_checkpoint, expected_historical_v2_slot_stage,
    validate_historical_v2_slot_stage_history,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const TRANSACTION_SCHEMA_VERSION: u32 = 1;
const TRANSACTION_CONTRACT: &str = "sniffbench-historical-v2-slot-stage-transaction-v1";
const TRANSACTION_FILE: &str = "_transaction.json";
const CHECKPOINT_FILE: &str = "checkpoint.json";
const ARTIFACT_FILE: &str = "artifact.json";
const MAX_TRANSACTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

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

#[derive(Debug)]
pub struct HistoricalV2SlotStageJournal {
    slot_root: PathBuf,
    staging_root: PathBuf,
    history: Vec<HistoricalV2StoredSlotStage>,
    _lock: SlotFileLock,
}

impl HistoricalV2SlotStageJournal {
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
        let history = load_history(&slot_root)
            .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
        Ok(Self {
            slot_root,
            staging_root,
            history,
            _lock: lock,
        })
    }

    pub fn history(&self) -> &[HistoricalV2StoredSlotStage] {
        &self.history
    }

    pub fn append<T: Serialize>(
        &mut self,
        input: HistoricalV2SlotStageCheckpointInput<'_>,
        artifact: Option<&T>,
    ) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
        let stage = input.stage;
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
        write_json_new(
            &staging_root.join(ARTIFACT_FILE),
            artifact,
            MAX_ARTIFACT_BYTES,
        )?;
    }
    let files = committed_files(staging_root, artifact.is_some())?;
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
    let mut stored = Vec::with_capacity(directories.len());
    for (index, (name, path)) in directories.into_iter().enumerate() {
        let stage = expected_historical_v2_slot_stage(index)
            .ok_or_else(|| "historical-v2 slot journal has too many stages".to_string())?;
        let sequence = index + 1;
        if name != transaction_directory_name(sequence, stage) {
            return Err("historical-v2 slot journal stage sequence changed".to_string());
        }
        stored.push(load_stage(&path, sequence)?);
    }
    let checkpoints = stored
        .iter()
        .map(|value| value.checkpoint.clone())
        .collect::<Vec<_>>();
    validate_historical_v2_slot_stage_history(&checkpoints)?;
    Ok(stored)
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
        || transaction.files != committed_files(root, has_artifact)?
    {
        return Err("historical-v2 stage transaction commitment changed".to_string());
    }
    let artifact = has_artifact
        .then(|| {
            serde_json::from_slice::<Value>(&read_limited(
                &root.join(ARTIFACT_FILE),
                MAX_ARTIFACT_BYTES,
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

fn committed_files(root: &Path, has_artifact: bool) -> Result<Vec<CommittedFile>, String> {
    let mut inputs = vec![(CHECKPOINT_FILE, MAX_CHECKPOINT_BYTES)];
    if has_artifact {
        inputs.insert(0, (ARTIFACT_FILE, MAX_ARTIFACT_BYTES));
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
    if !matches!(outcome, HistoricalV2SlotStageOutcome::ReadyForReview) == has_artifact {
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
