use super::{
    INTENTIONAL_BOUNDARY_RANK_STAGE_CHECKPOINT_SCHEMA_VERSION, IntentionalBoundaryFrameTask,
    IntentionalBoundaryRankStage, IntentionalBoundaryRankStageArtifact,
    IntentionalBoundaryRankStageArtifactKind, IntentionalBoundaryRankStageCheckpoint,
    IntentionalBoundaryRankStageError, IntentionalBoundaryRankStageErrorKind,
    IntentionalBoundaryRankStageOutcome,
};
use sha2::{Digest, Sha256};
use std::fmt;

const CHECKPOINT_CONTRACT: &str = "sniffbench-intentional-boundary-rank-stage-checkpoint-v1";
const STAGES: [IntentionalBoundaryRankStage; 12] = [
    IntentionalBoundaryRankStage::Materialization,
    IntentionalBoundaryRankStage::Inventory,
    IntentionalBoundaryRankStage::SourceCensus,
    IntentionalBoundaryRankStage::LicenseCensus,
    IntentionalBoundaryRankStage::SemanticCensus,
    IntentionalBoundaryRankStage::AstCensus,
    IntentionalBoundaryRankStage::Manifest,
    IntentionalBoundaryRankStage::BaseEvidence,
    IntentionalBoundaryRankStage::ProjectModel,
    IntentionalBoundaryRankStage::Generator,
    IntentionalBoundaryRankStage::Behavior,
    IntentionalBoundaryRankStage::Candidate,
];

#[path = "benchmark_intentional_boundary_rank_stage_store.rs"]
mod store;

pub use store::{IntentionalBoundaryRankStageJournal, IntentionalBoundaryStoredRankStage};

pub(super) struct IntentionalBoundaryRankStageCheckpointInput<'a> {
    pub frame_task_sha256: &'a str,
    pub population_rank: usize,
    pub population_rank_sha256: &'a str,
    pub repository: &'a str,
    pub stage: IntentionalBoundaryRankStage,
    pub artifact_kind: IntentionalBoundaryRankStageArtifactKind,
    pub artifact_sha256: &'a str,
    pub excluded: bool,
}

pub fn validate_intentional_boundary_rank_stage_history(
    history: &[IntentionalBoundaryRankStageCheckpoint],
) -> Result<(), String> {
    for (index, checkpoint) in history.iter().enumerate() {
        let expected_stage = expected_intentional_boundary_rank_stage(index)
            .ok_or_else(|| "intentional-boundary rank history has too many stages".to_string())?;
        if checkpoint.schema_version != INTENTIONAL_BOUNDARY_RANK_STAGE_CHECKPOINT_SCHEMA_VERSION
            || checkpoint.checkpoint_contract != CHECKPOINT_CONTRACT
            || checkpoint.sequence != index + 1
            || checkpoint.stage != expected_stage
            || checkpoint.checkpoint_sha256 != checkpoint_sha256(checkpoint)?
        {
            return Err("intentional-boundary rank stage checkpoint changed".to_string());
        }
        validate_identity(checkpoint)?;
        validate_outcome(checkpoint.stage, &checkpoint.outcome)?;
        let expected_previous = index
            .checked_sub(1)
            .map(|previous| history[previous].checkpoint_sha256.as_str());
        if checkpoint.previous_checkpoint_sha256.as_deref() != expected_previous {
            return Err("intentional-boundary rank checkpoint chain changed".to_string());
        }
        if let Some(first) = history.first()
            && (checkpoint.frame_task_sha256 != first.frame_task_sha256
                || checkpoint.population_rank != first.population_rank
                || checkpoint.population_rank_sha256 != first.population_rank_sha256
                || checkpoint.repository != first.repository)
        {
            return Err(
                "intentional-boundary rank identity changed across checkpoints".to_string(),
            );
        }
        if index + 1 < history.len() && is_terminal_outcome(checkpoint) {
            return Err(
                "intentional-boundary terminal rank checkpoint has a successor".to_string(),
            );
        }
    }
    Ok(())
}

pub fn next_intentional_boundary_rank_stage(
    history: &[IntentionalBoundaryRankStageCheckpoint],
) -> Result<Option<IntentionalBoundaryRankStage>, String> {
    validate_intentional_boundary_rank_stage_history(history)?;
    if history.last().is_some_and(is_terminal_outcome) {
        return Ok(None);
    }
    Ok(expected_intentional_boundary_rank_stage(history.len()))
}

pub(super) fn append_intentional_boundary_rank_stage_checkpoint(
    history: &[IntentionalBoundaryRankStageCheckpoint],
    input: IntentionalBoundaryRankStageCheckpointInput<'_>,
) -> Result<IntentionalBoundaryRankStageCheckpoint, String> {
    validate_intentional_boundary_rank_stage_history(history)?;
    let expected_stage = next_intentional_boundary_rank_stage(history)?
        .ok_or_else(|| "intentional-boundary rank already has a terminal checkpoint".to_string())?;
    if input.stage != expected_stage {
        return Err(format!(
            "intentional-boundary rank stage is out of order: expected {expected_stage:?}, got {:?}",
            input.stage
        ));
    }
    let outcome = if input.excluded {
        IntentionalBoundaryRankStageOutcome::Excluded {
            artifact_kind: input.artifact_kind,
            artifact_sha256: input.artifact_sha256.to_string(),
        }
    } else {
        IntentionalBoundaryRankStageOutcome::Completed {
            artifact_kind: input.artifact_kind,
            artifact_sha256: input.artifact_sha256.to_string(),
        }
    };
    validate_outcome(input.stage, &outcome)?;
    let mut checkpoint = IntentionalBoundaryRankStageCheckpoint {
        schema_version: INTENTIONAL_BOUNDARY_RANK_STAGE_CHECKPOINT_SCHEMA_VERSION,
        checkpoint_contract: CHECKPOINT_CONTRACT.to_string(),
        frame_task_sha256: input.frame_task_sha256.to_string(),
        population_rank: input.population_rank,
        population_rank_sha256: input.population_rank_sha256.to_string(),
        repository: input.repository.to_string(),
        sequence: history.len() + 1,
        previous_checkpoint_sha256: history.last().map(|value| value.checkpoint_sha256.clone()),
        stage: input.stage,
        outcome,
        checkpoint_sha256: String::new(),
    };
    validate_identity(&checkpoint)?;
    if let Some(previous) = history.last()
        && (previous.frame_task_sha256 != checkpoint.frame_task_sha256
            || previous.population_rank != checkpoint.population_rank
            || previous.population_rank_sha256 != checkpoint.population_rank_sha256
            || previous.repository != checkpoint.repository)
    {
        return Err("intentional-boundary rank identity changed while appending".to_string());
    }
    checkpoint.checkpoint_sha256 = checkpoint_sha256(&checkpoint)?;
    Ok(checkpoint)
}

pub(super) fn expected_intentional_boundary_rank_stage(
    index: usize,
) -> Option<IntentionalBoundaryRankStage> {
    STAGES.get(index).copied()
}

pub(super) fn validate_artifact_identity(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    artifact: &IntentionalBoundaryRankStageArtifact,
) -> Result<(), String> {
    let repository = task
        .repositories
        .get(population_rank.saturating_sub(1))
        .filter(|value| value.population_rank == population_rank)
        .ok_or_else(|| {
            format!("intentional-boundary rank {population_rank} is outside its frame task")
        })?;
    let identity = artifact.frame_identity();
    if let Some((task_sha256, rank)) = identity
        && (task_sha256 != task.task_sha256 || rank != population_rank)
    {
        return Err("intentional-boundary stage artifact has another rank identity".to_string());
    }
    if artifact
        .repository()
        .is_some_and(|value| value != repository.repository)
    {
        return Err("intentional-boundary stage artifact has another repository".to_string());
    }
    Ok(())
}

impl IntentionalBoundaryRankStageArtifact {
    pub fn stage(&self) -> IntentionalBoundaryRankStage {
        artifact_stage(self.kind())
    }

    pub fn kind(&self) -> IntentionalBoundaryRankStageArtifactKind {
        use IntentionalBoundaryRankStageArtifact as Artifact;
        match self {
            Artifact::Materialization(_) => {
                IntentionalBoundaryRankStageArtifactKind::Materialization
            }
            Artifact::MaterializationExclusion(_) => {
                IntentionalBoundaryRankStageArtifactKind::MaterializationExclusion
            }
            Artifact::Inventory(_) => IntentionalBoundaryRankStageArtifactKind::Inventory,
            Artifact::SourceCensus(_) => IntentionalBoundaryRankStageArtifactKind::SourceCensus,
            Artifact::SourceCensusExclusion(_) => {
                IntentionalBoundaryRankStageArtifactKind::SourceCensusExclusion
            }
            Artifact::LicenseCensus(_) => IntentionalBoundaryRankStageArtifactKind::LicenseCensus,
            Artifact::LicenseCensusExclusion(_) => {
                IntentionalBoundaryRankStageArtifactKind::LicenseCensusExclusion
            }
            Artifact::SemanticCensus(_) => IntentionalBoundaryRankStageArtifactKind::SemanticCensus,
            Artifact::SemanticCensusExclusion(_) => {
                IntentionalBoundaryRankStageArtifactKind::SemanticCensusExclusion
            }
            Artifact::AstCensus(_) => IntentionalBoundaryRankStageArtifactKind::AstCensus,
            Artifact::AstCensusExclusion(_) => {
                IntentionalBoundaryRankStageArtifactKind::AstCensusExclusion
            }
            Artifact::Manifest(_) => IntentionalBoundaryRankStageArtifactKind::Manifest,
            Artifact::ManifestExclusion(_) => {
                IntentionalBoundaryRankStageArtifactKind::ManifestExclusion
            }
            Artifact::BaseEvidence(_) => IntentionalBoundaryRankStageArtifactKind::BaseEvidence,
            Artifact::ProjectModel(_) => IntentionalBoundaryRankStageArtifactKind::ProjectModel,
            Artifact::ProjectModelExclusion(_) => {
                IntentionalBoundaryRankStageArtifactKind::ProjectModelExclusion
            }
            Artifact::Generator(_) => IntentionalBoundaryRankStageArtifactKind::Generator,
            Artifact::Behavior(_) => IntentionalBoundaryRankStageArtifactKind::Behavior,
            Artifact::Candidate(_) => IntentionalBoundaryRankStageArtifactKind::Candidate,
        }
    }

    pub fn is_exclusion(&self) -> bool {
        is_exclusion_kind(self.kind())
    }

    fn frame_identity(&self) -> Option<(&str, usize)> {
        use IntentionalBoundaryRankStageArtifact as Artifact;
        match self {
            Artifact::Inventory(_) => None,
            Artifact::Materialization(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::MaterializationExclusion(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::SourceCensus(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::SourceCensusExclusion(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::LicenseCensus(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::LicenseCensusExclusion(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::SemanticCensus(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::SemanticCensusExclusion(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::AstCensus(value) => Some((&value.frame_task_sha256, value.population_rank)),
            Artifact::AstCensusExclusion(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::Manifest(value) => Some((&value.frame_task_sha256, value.population_rank)),
            Artifact::ManifestExclusion(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::BaseEvidence(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::ProjectModel(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::ProjectModelExclusion(value) => {
                Some((&value.frame_task_sha256, value.population_rank))
            }
            Artifact::Generator(value) => Some((&value.frame_task_sha256, value.population_rank)),
            Artifact::Behavior(value) => Some((&value.frame_task_sha256, value.population_rank)),
            Artifact::Candidate(value) => Some((&value.frame_task_sha256, value.population_rank)),
        }
    }

    fn repository(&self) -> Option<&str> {
        use IntentionalBoundaryRankStageArtifact as Artifact;
        match self {
            Artifact::Materialization(value) => Some(&value.repository),
            Artifact::MaterializationExclusion(value) => Some(&value.repository),
            Artifact::Inventory(value) => Some(&value.repository),
            Artifact::SourceCensusExclusion(value) => Some(&value.repository),
            Artifact::LicenseCensusExclusion(value) => Some(&value.repository),
            Artifact::SemanticCensusExclusion(value) => Some(&value.repository),
            Artifact::AstCensusExclusion(value) => Some(&value.repository),
            Artifact::ManifestExclusion(value) => Some(&value.repository),
            Artifact::ProjectModelExclusion(value) => Some(&value.repository),
            Artifact::SourceCensus(_)
            | Artifact::LicenseCensus(_)
            | Artifact::SemanticCensus(_)
            | Artifact::AstCensus(_)
            | Artifact::Manifest(_)
            | Artifact::BaseEvidence(_)
            | Artifact::ProjectModel(_)
            | Artifact::Generator(_)
            | Artifact::Behavior(_)
            | Artifact::Candidate(_) => None,
        }
    }
}

fn validate_identity(checkpoint: &IntentionalBoundaryRankStageCheckpoint) -> Result<(), String> {
    if !valid_sha256(&checkpoint.frame_task_sha256)
        || !valid_sha256(&checkpoint.population_rank_sha256)
        || checkpoint.population_rank == 0
        || checkpoint.repository.trim().is_empty()
    {
        return Err("intentional-boundary rank checkpoint identity is invalid".to_string());
    }
    Ok(())
}

fn validate_outcome(
    stage: IntentionalBoundaryRankStage,
    outcome: &IntentionalBoundaryRankStageOutcome,
) -> Result<(), String> {
    let (kind, hash, excluded) = match outcome {
        IntentionalBoundaryRankStageOutcome::Completed {
            artifact_kind,
            artifact_sha256,
        } => (*artifact_kind, artifact_sha256, false),
        IntentionalBoundaryRankStageOutcome::Excluded {
            artifact_kind,
            artifact_sha256,
        } => (*artifact_kind, artifact_sha256, true),
    };
    if artifact_stage(kind) != stage || is_exclusion_kind(kind) != excluded || !valid_sha256(hash) {
        return Err("intentional-boundary rank stage outcome is invalid".to_string());
    }
    Ok(())
}

fn artifact_stage(kind: IntentionalBoundaryRankStageArtifactKind) -> IntentionalBoundaryRankStage {
    use IntentionalBoundaryRankStage as Stage;
    use IntentionalBoundaryRankStageArtifactKind as Artifact;
    match kind {
        Artifact::Materialization | Artifact::MaterializationExclusion => Stage::Materialization,
        Artifact::Inventory => Stage::Inventory,
        Artifact::SourceCensus | Artifact::SourceCensusExclusion => Stage::SourceCensus,
        Artifact::LicenseCensus | Artifact::LicenseCensusExclusion => Stage::LicenseCensus,
        Artifact::SemanticCensus | Artifact::SemanticCensusExclusion => Stage::SemanticCensus,
        Artifact::AstCensus | Artifact::AstCensusExclusion => Stage::AstCensus,
        Artifact::Manifest | Artifact::ManifestExclusion => Stage::Manifest,
        Artifact::BaseEvidence => Stage::BaseEvidence,
        Artifact::ProjectModel | Artifact::ProjectModelExclusion => Stage::ProjectModel,
        Artifact::Generator => Stage::Generator,
        Artifact::Behavior => Stage::Behavior,
        Artifact::Candidate => Stage::Candidate,
    }
}

fn is_exclusion_kind(kind: IntentionalBoundaryRankStageArtifactKind) -> bool {
    matches!(
        kind,
        IntentionalBoundaryRankStageArtifactKind::MaterializationExclusion
            | IntentionalBoundaryRankStageArtifactKind::SourceCensusExclusion
            | IntentionalBoundaryRankStageArtifactKind::LicenseCensusExclusion
            | IntentionalBoundaryRankStageArtifactKind::SemanticCensusExclusion
            | IntentionalBoundaryRankStageArtifactKind::AstCensusExclusion
            | IntentionalBoundaryRankStageArtifactKind::ManifestExclusion
            | IntentionalBoundaryRankStageArtifactKind::ProjectModelExclusion
    )
}

fn is_terminal_outcome(checkpoint: &IntentionalBoundaryRankStageCheckpoint) -> bool {
    matches!(
        checkpoint.outcome,
        IntentionalBoundaryRankStageOutcome::Excluded { .. }
    ) || checkpoint.stage == IntentionalBoundaryRankStage::Candidate
}

fn checkpoint_sha256(
    checkpoint: &IntentionalBoundaryRankStageCheckpoint,
) -> Result<String, String> {
    let mut committed = checkpoint.clone();
    committed.checkpoint_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit intentional-boundary rank checkpoint: {error}"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

impl IntentionalBoundaryRankStageError {
    pub fn invalid(stage: IntentionalBoundaryRankStage, detail: impl Into<String>) -> Self {
        Self::new(
            stage,
            IntentionalBoundaryRankStageErrorKind::InvalidInput,
            detail,
        )
    }

    pub fn unavailable(stage: IntentionalBoundaryRankStage, detail: impl Into<String>) -> Self {
        Self::new(
            stage,
            IntentionalBoundaryRankStageErrorKind::InfrastructureUnavailable,
            detail,
        )
    }

    pub fn infrastructure(stage: IntentionalBoundaryRankStage, detail: impl Into<String>) -> Self {
        Self::new(
            stage,
            IntentionalBoundaryRankStageErrorKind::InfrastructureFailed,
            detail,
        )
    }

    fn new(
        stage: IntentionalBoundaryRankStage,
        kind: IntentionalBoundaryRankStageErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for IntentionalBoundaryRankStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for IntentionalBoundaryRankStageError {}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_rank_stage_tests.rs"]
mod tests;
