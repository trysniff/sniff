use super::super::super::history_v2_slot_store_support::{
    read_limited, require_plain_directory, sync_directory, write_compact_json_new, write_json_new,
};
use super::super::{
    HistoricalV3RankCheckpoint, HistoricalV3RankStage, HistoricalV3RankStageOutcome,
    validate_historical_v3_rank_history,
};
use super::HistoricalV3StoredRankStage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const TRANSACTION_SCHEMA_VERSION: u32 = 1;
const TRANSACTION_CONTRACT: &str = "sniffbench-historical-v3-rank-stage-transaction-v1";
const TRANSACTION_FILE: &str = "_transaction.json";
const CHECKPOINT_FILE: &str = "checkpoint.json";
const ARTIFACT_FILE: &str = "artifact.json";
const MAX_TRANSACTION_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 2 * 1024 * 1024;
pub(super) const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommittedFile {
    pub(super) name: String,
    pub(super) sha256: String,
    pub(super) byte_count: u64,
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

pub(super) fn publish_stage<T: Serialize>(
    staging_root: &Path,
    rank_root: &Path,
    final_root: &Path,
    checkpoint: &HistoricalV3RankCheckpoint,
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
        .map_err(|error| format!("failed to publish historical-v3 stage transaction: {error}"))?;
    sync_directory(rank_root)
}

pub(super) fn load_history(root: &Path) -> Result<Vec<HistoricalV3StoredRankStage>, String> {
    let mut transactions = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical-v3 rank journal: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("failed to inspect historical-v3 rank journal: {error}"))?;
        let metadata = entry.metadata().map_err(|error| {
            format!("failed to inspect historical-v3 rank transaction: {error}")
        })?;
        if !metadata.is_dir()
            || entry
                .file_type()
                .map(|kind| kind.is_symlink())
                .unwrap_or(true)
        {
            return Err("historical-v3 rank journal contains a non-directory".to_string());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "historical-v3 rank transaction name is not UTF-8".to_string())?;
        let (sequence, stage) = parse_transaction_directory_name(&name)?;
        if name != transaction_directory_name(sequence, stage) {
            return Err("historical-v3 rank transaction name is not canonical".to_string());
        }
        transactions.push((sequence, entry.path()));
    }
    transactions.sort_by_key(|(sequence, _)| *sequence);
    if transactions
        .iter()
        .enumerate()
        .any(|(index, (sequence, _))| *sequence != index + 1)
    {
        return Err("historical-v3 rank transaction sequence is not contiguous".to_string());
    }
    let stored = transactions
        .into_iter()
        .map(|(sequence, path)| load_stage(&path, sequence))
        .collect::<Result<Vec<_>, _>>()?;
    let checkpoints = stored
        .iter()
        .map(|stage| stage.checkpoint.clone())
        .collect::<Vec<_>>();
    validate_historical_v3_rank_history(&checkpoints)?;
    Ok(stored)
}

fn load_stage(root: &Path, sequence: usize) -> Result<HistoricalV3StoredRankStage, String> {
    require_plain_directory(root, "historical-v3 rank transaction")?;
    let checkpoint = serde_json::from_slice::<HistoricalV3RankCheckpoint>(&read_limited(
        &root.join(CHECKPOINT_FILE),
        MAX_CHECKPOINT_BYTES,
        "historical-v3 rank checkpoint",
    )?)
    .map_err(|error| format!("invalid historical-v3 rank checkpoint: {error}"))?;
    let has_artifact = !matches!(
        checkpoint.outcome,
        HistoricalV3RankStageOutcome::ReadyForSourceReview
    );
    let mut expected_names = if has_artifact {
        vec![ARTIFACT_FILE, CHECKPOINT_FILE, TRANSACTION_FILE]
    } else {
        vec![CHECKPOINT_FILE, TRANSACTION_FILE]
    };
    expected_names.sort_unstable();
    if transaction_file_names(root)? != expected_names {
        return Err("historical-v3 rank transaction file set changed".to_string());
    }
    let transaction = serde_json::from_slice::<StageTransaction>(&read_limited(
        &root.join(TRANSACTION_FILE),
        MAX_TRANSACTION_BYTES,
        "historical-v3 rank transaction",
    )?)
    .map_err(|error| format!("invalid historical-v3 rank transaction: {error}"))?;
    if transaction.schema_version != TRANSACTION_SCHEMA_VERSION
        || transaction.transaction_contract != TRANSACTION_CONTRACT
        || transaction.sequence != sequence
        || transaction.checkpoint_sha256 != checkpoint.checkpoint_sha256
        || transaction.files != committed_files(root, has_artifact)?
    {
        return Err("historical-v3 rank transaction commitment changed".to_string());
    }
    let artifact_commitment = transaction
        .files
        .iter()
        .find(|file| file.name == ARTIFACT_FILE)
        .cloned();
    Ok(HistoricalV3StoredRankStage {
        checkpoint,
        artifact_path: artifact_commitment
            .as_ref()
            .map(|_| root.join(ARTIFACT_FILE)),
        artifact_commitment,
    })
}

fn committed_files(root: &Path, has_artifact: bool) -> Result<Vec<CommittedFile>, String> {
    [CHECKPOINT_FILE]
        .into_iter()
        .chain(has_artifact.then_some(ARTIFACT_FILE))
        .map(|name| committed_file(root, name))
        .collect()
}

fn committed_file(root: &Path, name: &str) -> Result<CommittedFile, String> {
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("failed to inspect historical-v3 committed file: {error}"))?;
    let limit = if name == ARTIFACT_FILE {
        MAX_ARTIFACT_BYTES
    } else {
        MAX_CHECKPOINT_BYTES
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err("historical-v3 committed artifact is unsafe or exceeds its limit".to_string());
    }
    let mut file = File::open(&path)
        .map_err(|error| format!("failed to read historical-v3 committed file: {error}"))?;
    let mut hasher = Sha256::new();
    let mut byte_count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read historical-v3 committed file: {error}"))?;
        if read == 0 {
            break;
        }
        byte_count = byte_count
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| "historical-v3 artifact length exceeds u64".to_string())?;
        if byte_count > limit {
            return Err("historical-v3 committed artifact exceeds its size limit".to_string());
        }
        hasher.update(&buffer[..read]);
    }
    if byte_count != metadata.len() {
        return Err("historical-v3 committed artifact changed while hashing".to_string());
    }
    Ok(CommittedFile {
        name: name.to_string(),
        sha256: format!("{:x}", hasher.finalize()),
        byte_count,
    })
}

fn transaction_file_names(root: &Path) -> Result<Vec<&'static str>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical-v3 transaction: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("failed to inspect historical-v3 transaction: {error}"))?;
        if !entry
            .file_type()
            .map_err(|error| format!("failed to inspect historical-v3 transaction: {error}"))?
            .is_file()
        {
            return Err("historical-v3 transaction contains a non-file".to_string());
        }
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| "historical-v3 transaction filename is not UTF-8".to_string())?;
        let known = match name {
            ARTIFACT_FILE => ARTIFACT_FILE,
            CHECKPOINT_FILE => CHECKPOINT_FILE,
            TRANSACTION_FILE => TRANSACTION_FILE,
            _ => return Err("historical-v3 transaction contains an unknown file".to_string()),
        };
        names.push(known);
    }
    names.sort_unstable();
    Ok(names)
}

pub(super) fn transaction_directory_name(sequence: usize, stage: HistoricalV3RankStage) -> String {
    format!("{sequence:02}-{}", stage_name(stage))
}

fn parse_transaction_directory_name(name: &str) -> Result<(usize, HistoricalV3RankStage), String> {
    let (sequence, stage) = name
        .split_once('-')
        .ok_or_else(|| "historical-v3 rank transaction name is invalid".to_string())?;
    let sequence = sequence
        .parse::<usize>()
        .map_err(|_| "historical-v3 rank transaction sequence is invalid".to_string())?;
    let stage = match stage {
        "materialization" => HistoricalV3RankStage::Materialization,
        "source-census" => HistoricalV3RankStage::SourceCensus,
        "semantic-census" => HistoricalV3RankStage::SemanticCensus,
        "mechanical-qualification" => HistoricalV3RankStage::MechanicalQualification,
        "test-recipe" => HistoricalV3RankStage::TestRecipe,
        "identical-tests" => HistoricalV3RankStage::IdenticalTests,
        "ready-for-source-review" => HistoricalV3RankStage::ReadyForSourceReview,
        _ => return Err("historical-v3 rank transaction stage is invalid".to_string()),
    };
    Ok((sequence, stage))
}

fn stage_name(stage: HistoricalV3RankStage) -> &'static str {
    match stage {
        HistoricalV3RankStage::Materialization => "materialization",
        HistoricalV3RankStage::SourceCensus => "source-census",
        HistoricalV3RankStage::SemanticCensus => "semantic-census",
        HistoricalV3RankStage::MechanicalQualification => "mechanical-qualification",
        HistoricalV3RankStage::TestRecipe => "test-recipe",
        HistoricalV3RankStage::IdenticalTests => "identical-tests",
        HistoricalV3RankStage::ReadyForSourceReview => "ready-for-source-review",
    }
}
