use super::{HistoricalRepositoryAssessment, NonBlindHistoryAssessment};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const CHECKPOINT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalAssessmentCheckpoint {
    schema_version: u32,
    task_sha256: String,
    assessment: HistoricalRepositoryAssessment,
}

pub(super) fn load_checkpoints(
    template: &NonBlindHistoryAssessment,
    root: &Path,
) -> Result<Vec<HistoricalRepositoryAssessment>, String> {
    fs::create_dir_all(root)
        .map_err(|error| format!("failed to create historical checkpoint root: {error}"))?;
    remove_temporary_files(root)?;
    let mut completed = Vec::new();
    for expected in &template.assessments {
        let path = checkpoint_path(root, expected.candidate.rank);
        if !path.exists() {
            break;
        }
        let checkpoint: HistoricalAssessmentCheckpoint =
            serde_json::from_slice(&fs::read(&path).map_err(|error| {
                format!(
                    "failed to read historical checkpoint {}: {error}",
                    path.display()
                )
            })?)
            .map_err(|error| {
                format!("invalid historical checkpoint {}: {error}", path.display())
            })?;
        if checkpoint.schema_version != CHECKPOINT_SCHEMA_VERSION
            || checkpoint.task_sha256 != template.task_sha256
            || checkpoint.assessment.candidate != expected.candidate
            || checkpoint.assessment.disposition.is_none()
        {
            return Err(format!(
                "historical checkpoint changed immutable rank {}",
                expected.candidate.rank
            ));
        }
        completed.push(checkpoint.assessment);
    }
    let files = fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical checkpoints: {error}"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
        .count();
    if files != completed.len() {
        return Err("historical checkpoints are not one contiguous ranked prefix".to_string());
    }
    Ok(completed)
}

pub(super) fn write_checkpoint(
    root: &Path,
    task_sha256: &str,
    assessment: &HistoricalRepositoryAssessment,
) -> Result<(), String> {
    fs::create_dir_all(root)
        .map_err(|error| format!("failed to create historical checkpoint root: {error}"))?;
    let path = checkpoint_path(root, assessment.candidate.rank);
    if path.exists() {
        return Err(format!(
            "historical checkpoint already exists: {}",
            path.display()
        ));
    }
    let checkpoint = HistoricalAssessmentCheckpoint {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        task_sha256: task_sha256.to_string(),
        assessment: assessment.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&checkpoint)
        .map_err(|error| format!("failed to serialize historical checkpoint: {error}"))?;
    let temporary = root.join(format!(
        "rank-{:04}.json.tmp-{}",
        assessment.candidate.rank,
        std::process::id()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            format!(
                "failed to create historical checkpoint {}: {error}",
                temporary.display()
            )
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to persist historical checkpoint: {error}"))?;
    drop(file);
    fs::rename(&temporary, &path)
        .map_err(|error| format!("failed to publish historical checkpoint: {error}"))
}

fn remove_temporary_files(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical checkpoints: {error}"))?
    {
        let path = entry
            .map_err(|error| format!("failed to inspect historical checkpoint: {error}"))?
            .path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name.starts_with("rank-") && name.contains(".json.tmp-") && path.is_file() {
            fs::remove_file(&path).map_err(|error| {
                format!(
                    "failed to remove stale historical checkpoint {}: {error}",
                    path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn checkpoint_path(root: &Path, rank: usize) -> PathBuf {
    root.join(format!("rank-{rank:04}.json"))
}
