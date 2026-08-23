use super::*;

pub(super) fn expected_repository(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
) -> Result<&super::super::super::IntentionalBoundaryRepositoryTask, String> {
    task.repositories
        .get(population_rank.saturating_sub(1))
        .filter(|repository| repository.population_rank == population_rank)
        .ok_or_else(|| {
            format!("intentional-boundary rank {population_rank} is outside its immutable task")
        })
}

pub(super) fn outcome_kind(
    outcome: &IntentionalBoundaryRankStageOutcome,
) -> super::super::IntentionalBoundaryRankStageArtifactKind {
    match outcome {
        IntentionalBoundaryRankStageOutcome::Completed { artifact_kind, .. }
        | IntentionalBoundaryRankStageOutcome::Excluded { artifact_kind, .. } => *artifact_kind,
    }
}

pub(super) fn outcome_hash(outcome: &IntentionalBoundaryRankStageOutcome) -> &str {
    match outcome {
        IntentionalBoundaryRankStageOutcome::Completed {
            artifact_sha256, ..
        }
        | IntentionalBoundaryRankStageOutcome::Excluded {
            artifact_sha256, ..
        } => artifact_sha256,
    }
}

pub(super) fn current_stage(
    checkpoints: &[IntentionalBoundaryRankStageCheckpoint],
) -> IntentionalBoundaryRankStage {
    expected_intentional_boundary_rank_stage(checkpoints.len())
        .or_else(|| checkpoints.last().map(|value| value.stage))
        .unwrap_or(IntentionalBoundaryRankStage::Materialization)
}

pub(super) fn rank_name(population_rank: usize) -> String {
    format!("rank-{population_rank:04}")
}

pub(super) fn transaction_directory_name(
    sequence: usize,
    stage: IntentionalBoundaryRankStage,
) -> String {
    format!("{sequence:04}-{}", stage_name(stage))
}

fn stage_name(stage: IntentionalBoundaryRankStage) -> &'static str {
    match stage {
        IntentionalBoundaryRankStage::Materialization => "materialization",
        IntentionalBoundaryRankStage::Inventory => "inventory",
        IntentionalBoundaryRankStage::SourceCensus => "source-census",
        IntentionalBoundaryRankStage::LicenseCensus => "license-census",
        IntentionalBoundaryRankStage::SemanticCensus => "semantic-census",
        IntentionalBoundaryRankStage::AstCensus => "ast-census",
        IntentionalBoundaryRankStage::Manifest => "manifest",
        IntentionalBoundaryRankStage::BaseEvidence => "base-evidence",
        IntentionalBoundaryRankStage::ProjectModel => "project-model",
        IntentionalBoundaryRankStage::Generator => "generator",
        IntentionalBoundaryRankStage::Behavior => "behavior",
        IntentionalBoundaryRankStage::Candidate => "candidate",
    }
}

pub(super) fn remove_incomplete(root: &Path, staging_root: &Path) -> Result<(), String> {
    if !staging_root.exists() {
        return Ok(());
    }
    require_plain_directory(
        staging_root,
        "incomplete intentional-boundary rank transaction",
    )?;
    if staging_root.parent() != Some(root) {
        return Err("intentional-boundary staging transaction escaped its state root".to_string());
    }
    fs::remove_dir_all(staging_root).map_err(|error| {
        format!("failed to remove incomplete intentional-boundary rank transaction: {error}")
    })?;
    sync_directory(root)
}

pub(super) fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        format!("failed to serialize intentional-boundary rank artifact: {error}")
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}
