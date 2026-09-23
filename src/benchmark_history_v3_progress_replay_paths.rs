use super::super::history_v3_rank_journal::historical_v3_rank_identity_in_validated_collection;
use super::super::history_v3_rank_journal::historical_v3_rank_journal_path;
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3CandidateTask, HistoricalV3Protocol,
    HistoricalV3ReviewRecordPaths,
};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

pub(super) fn ensure_no_later_state(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    later: &[&HistoricalV3CandidateTask],
    journal_root: &Path,
    review_root: &Path,
) -> Result<(), String> {
    for candidate in later {
        let rank = historical_v3_rank_identity_in_validated_collection(
            protocol,
            collection,
            candidate.stream_rank,
        )?;
        let journal_path = historical_v3_rank_journal_path(journal_root, &rank);
        let paths = HistoricalV3ReviewRecordPaths::new(review_root, &rank);
        if rank_directory_exists(journal_root, &journal_path)?
            || review_directory_exists(review_root, &paths)?
        {
            return Err("historical-v3 later rank has out-of-order state".to_string());
        }
    }
    Ok(())
}

pub(super) fn rank_directory_exists(root: &Path, path: &Path) -> Result<bool, String> {
    let language = path
        .parent()
        .ok_or("historical-v3 rank path has no language")?;
    let task = language
        .parent()
        .ok_or("historical-v3 rank path has no task")?;
    plain_directory_chain(&[root, task, language, path], "historical-v3 rank journal")
}

pub(super) fn review_directory_exists(
    root: &Path,
    paths: &HistoricalV3ReviewRecordPaths,
) -> Result<bool, String> {
    let rank = paths
        .audit
        .parent()
        .ok_or("historical-v3 review path has no rank")?;
    let task = rank
        .parent()
        .ok_or("historical-v3 review path has no task")?;
    plain_directory_chain(&[root, task, rank], "historical-v3 review records")
}

fn plain_directory_chain(paths: &[&Path], label: &str) -> Result<bool, String> {
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(format!("{label} contains a non-plain directory")),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(format!("failed to inspect {label}: {error}")),
        }
    }
    Ok(true)
}

pub(super) fn plain_file_exists(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(format!("{label} is not a plain file")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect {label}: {error}")),
    }
}

pub(super) fn human_files_exist(paths: &HistoricalV3ReviewRecordPaths) -> Result<bool, String> {
    Ok(
        plain_file_exists(&paths.reviewer_one, "historical-v3 first review")?
            || plain_file_exists(&paths.reviewer_two, "historical-v3 second review")?
            || plain_file_exists(&paths.audit, "historical-v3 audit")?
            || plain_file_exists(&paths.resolution, "historical-v3 resolution")?
            || plain_file_exists(&paths.final_label, "historical-v3 final label")?,
    )
}
