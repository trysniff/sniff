use super::history_v2_slot_store_support::{
    SlotFileLock, canonical_directory, require_plain_directory, sync_directory,
};
use super::history_v3_progress_replay::replay_historical_v3_ordered_progress_verified;
use super::{
    HistoricalV3CandidateCollection, HistoricalV3IdenticalTestExecutor, HistoricalV3Language,
    HistoricalV3NextStep, HistoricalV3Protocol, HistoricalV3RankStage, HistoricalV3ReplayProgress,
    HistoricalV3ReviewRecordPaths, prepare_historical_v3_review_cap,
    run_historical_v3_identical_tests_stage, run_historical_v3_materialization_stage,
    run_historical_v3_mechanical_qualification_stage, run_historical_v3_semantic_census_stage,
    run_historical_v3_source_census_stage, run_historical_v3_source_review_stage,
    run_historical_v3_test_recipe_stage, validate_historical_v3_candidate_collection_commitment,
    verify_historical_v3_qualified_rank, write_historical_v3_review_cap_new,
    write_historical_v3_stop_artifact_new,
};
use std::fs;
use std::path::Path;

pub struct HistoricalV3RunPaths<'a> {
    pub journal_root: &'a Path,
    pub workspace_root: &'a Path,
    pub review_root: &'a Path,
    pub stop_path: &'a Path,
}

pub async fn advance_historical_v3_ordered_step<E: HistoricalV3IdenticalTestExecutor>(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    language: HistoricalV3Language,
    paths: HistoricalV3RunPaths<'_>,
    executor: &E,
) -> Result<HistoricalV3ReplayProgress, String> {
    validate_historical_v3_candidate_collection_commitment(protocol, collection)?;
    if !protocol.languages.contains(&language) {
        return Err("historical-v3 runner language is outside the protocol".to_string());
    }
    let HistoricalV3RunPaths {
        journal_root,
        workspace_root,
        review_root,
        stop_path,
    } = paths;
    let _lock = lock_language_run(journal_root, collection, language)?;
    let before = replay_historical_v3_ordered_progress_verified(
        protocol,
        collection,
        language,
        journal_root,
        review_root,
        stop_path,
    )?;
    match &before.progress {
        HistoricalV3ReplayProgress::PendingRank { rank, next, .. } => match next {
            HistoricalV3NextStep::HumanReview => {
                return Err("historical-v3 rank requires independent human review".to_string());
            }
            HistoricalV3NextStep::RepositoryReviewCap => {
                let qualification = verify_historical_v3_qualified_rank(
                    protocol,
                    collection,
                    rank.stream_rank,
                    journal_root,
                )
                .map_err(|error| error.to_string())?;
                let artifact = prepare_historical_v3_review_cap(
                    protocol,
                    collection,
                    &qualification,
                    &before.outcomes,
                )?;
                let paths = HistoricalV3ReviewRecordPaths::new(review_root, rank);
                ensure_review_record_directory(review_root, &paths.cap)?;
                write_historical_v3_review_cap_new(&paths.cap, &artifact)?;
            }
            HistoricalV3NextStep::RankStage(stage) => {
                run_rank_stage(
                    protocol,
                    collection,
                    rank.stream_rank,
                    *stage,
                    journal_root,
                    workspace_root,
                    executor,
                )
                .await?;
            }
        },
        HistoricalV3ReplayProgress::AwaitingStopPublication { artifact } => {
            write_historical_v3_stop_artifact_new(stop_path, artifact)?;
        }
        HistoricalV3ReplayProgress::Terminal { .. } => return Ok(before.progress),
    }
    let after = replay_historical_v3_ordered_progress_verified(
        protocol,
        collection,
        language,
        journal_root,
        review_root,
        stop_path,
    )?;
    if after.progress == before.progress {
        return Err("historical-v3 stage did not advance the verified prefix".to_string());
    }
    Ok(after.progress)
}

async fn run_rank_stage<E: HistoricalV3IdenticalTestExecutor>(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    stage: HistoricalV3RankStage,
    journal_root: &Path,
    workspace_root: &Path,
    executor: &E,
) -> Result<(), String> {
    match stage {
        HistoricalV3RankStage::Materialization => {
            run_historical_v3_materialization_stage(
                protocol,
                collection,
                stream_rank,
                journal_root,
                workspace_root,
            )
            .map_err(|error| error.to_string())?;
        }
        HistoricalV3RankStage::SourceCensus => {
            run_historical_v3_source_census_stage(
                protocol,
                collection,
                stream_rank,
                journal_root,
                workspace_root,
            )
            .map_err(|error| error.to_string())?;
        }
        HistoricalV3RankStage::SemanticCensus => {
            run_historical_v3_semantic_census_stage(
                protocol,
                collection,
                stream_rank,
                journal_root,
                workspace_root,
            )
            .await
            .map_err(|error| error.to_string())?;
        }
        HistoricalV3RankStage::MechanicalQualification => {
            run_historical_v3_mechanical_qualification_stage(
                protocol,
                collection,
                stream_rank,
                journal_root,
            )
            .map_err(|error| error.to_string())?;
        }
        HistoricalV3RankStage::TestRecipe => {
            run_historical_v3_test_recipe_stage(protocol, collection, stream_rank, journal_root)
                .map_err(|error| error.to_string())?;
        }
        HistoricalV3RankStage::IdenticalTests => {
            run_historical_v3_identical_tests_stage(
                protocol,
                collection,
                stream_rank,
                journal_root,
                workspace_root,
                executor,
            )
            .map_err(|error| error.to_string())?;
        }
        HistoricalV3RankStage::ReadyForSourceReview => {
            run_historical_v3_source_review_stage(
                protocol,
                collection,
                stream_rank,
                journal_root,
                workspace_root,
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn lock_language_run(
    journal_root: &Path,
    collection: &HistoricalV3CandidateCollection,
    language: HistoricalV3Language,
) -> Result<SlotFileLock, String> {
    fs::create_dir_all(journal_root)
        .map_err(|error| format!("failed to create historical-v3 journal root: {error}"))?;
    let root = canonical_directory(journal_root, "historical-v3 runner journal root")?;
    let language = match language {
        HistoricalV3Language::Go => "go",
        HistoricalV3Language::JavaScript => "javascript",
        HistoricalV3Language::Kotlin => "kotlin",
        HistoricalV3Language::Python => "python",
        HistoricalV3Language::Rust => "rust",
        HistoricalV3Language::TypeScript => "typescript",
    };
    let path = root.join(format!(
        ".{}-{language}.runner.lock",
        collection.manifest.stream_task.task_sha256
    ));
    SlotFileLock::acquire(&path)
        .map_err(|error| error.replace("historical-v2 slot", "historical-v3 language runner"))
}

fn ensure_review_record_directory(root: &Path, file: &Path) -> Result<(), String> {
    require_plain_directory(root, "historical-v3 review root")?;
    let rank = file
        .parent()
        .ok_or_else(|| "historical-v3 cap path has no rank directory".to_string())?;
    let task = rank
        .parent()
        .ok_or_else(|| "historical-v3 cap path has no task directory".to_string())?;
    ensure_plain_child(root, task)?;
    ensure_plain_child(task, rank)
}

fn ensure_plain_child(parent: &Path, child: &Path) -> Result<(), String> {
    require_plain_directory(parent, "historical-v3 review parent")?;
    if child.parent() != Some(parent) {
        return Err("historical-v3 review directory escaped its parent".to_string());
    }
    match fs::symlink_metadata(child) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err("historical-v3 review directory is not plain".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(child).map_err(|error| {
                format!("failed to create historical-v3 review directory: {error}")
            })?;
            sync_directory(parent)?;
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect historical-v3 review directory: {error}"
            ));
        }
    }
    let resolved_parent = canonical_directory(parent, "historical-v3 review parent")?;
    let resolved_child = canonical_directory(child, "historical-v3 review directory")?;
    if resolved_child.parent() != Some(resolved_parent.as_path()) {
        return Err("historical-v3 review directory escaped its parent".to_string());
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_history_v3_stage_runner_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "benchmark_history_v3_stage_cap_tests.rs"]
mod cap_tests;

#[cfg(test)]
#[path = "benchmark_history_v3_interleaved_tests.rs"]
mod interleaved_tests;
