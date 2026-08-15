use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RankCheckpoint {
    schema_version: u32,
    frame_task_sha256: String,
    population_rank: usize,
    artifact_sha256: String,
}

pub(super) fn publish_checkpoint(
    root: &Path,
    task_sha256: &str,
    rank: usize,
    artifact_sha256: &str,
) -> Result<(), String> {
    let checkpoint = RankCheckpoint {
        schema_version: 1,
        frame_task_sha256: task_sha256.to_string(),
        population_rank: rank,
        artifact_sha256: artifact_sha256.to_string(),
    };
    let bytes = pretty_json(&checkpoint, "intentional-boundary checkpoint")?;
    persist_create_new(
        &rank_path(root, rank),
        &bytes,
        "intentional-boundary checkpoint",
    )
}

pub(super) fn validate_checkpoint(
    path: &Path,
    task_sha256: &str,
    rank: usize,
    artifact_sha256: &str,
) -> Result<(), String> {
    let checkpoint: RankCheckpoint = serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("failed to read boundary checkpoint: {error}"))?,
    )
    .map_err(|error| format!("invalid boundary checkpoint: {error}"))?;
    if checkpoint.schema_version != 1
        || checkpoint.frame_task_sha256 != task_sha256
        || checkpoint.population_rank != rank
        || checkpoint.artifact_sha256 != artifact_sha256
    {
        return Err(format!(
            "intentional-boundary rank {rank} checkpoint commitment changed"
        ));
    }
    Ok(())
}

pub(super) fn persist_create_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{label} already exists: {}", path.display()));
    }
    let temp = temporary_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| format!("failed to create temporary {label}: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write temporary {label}: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("failed to persist temporary {label}: {error}"))?;
    drop(file);
    fs::hard_link(&temp, path).map_err(|error| format!("failed to publish {label}: {error}"))?;
    fs::remove_file(&temp)
        .map_err(|error| format!("failed to remove published {label} temp: {error}"))
}

pub(super) fn reject_unexpected_entries(root: &Path, completed: usize) -> Result<(), String> {
    let expected = (1..=completed).map(rank_file_name).collect::<BTreeSet<_>>();
    let actual = fs::read_dir(root)
        .map_err(|error| format!("failed to inspect boundary frame state: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("failed to inspect boundary frame entry: {error}"))
                .and_then(|entry| {
                    entry.file_name().into_string().map_err(|_| {
                        "intentional-boundary frame contains a non-UTF-8 entry".to_string()
                    })
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected {
        return Err(
            "intentional-boundary frame state is not one contiguous ranked prefix".to_string(),
        );
    }
    Ok(())
}

pub(super) fn remove_temps(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect boundary frame state: {error}"))?
    {
        let entry = entry.map_err(|error| format!("failed to inspect boundary entry: {error}"))?;
        if entry.file_name().to_string_lossy().contains(".tmp-") {
            fs::remove_file(entry.path())
                .map_err(|error| format!("failed to remove stale boundary temp: {error}"))?;
        }
    }
    Ok(())
}

pub(super) fn rank_path(root: &Path, rank: usize) -> PathBuf {
    root.join(rank_file_name(rank))
}

fn rank_file_name(rank: usize) -> String {
    format!("rank-{rank:04}.json")
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension(format!("json.tmp-{}", std::process::id()))
}

pub(super) fn pretty_json(value: &impl Serialize, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize {label}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
