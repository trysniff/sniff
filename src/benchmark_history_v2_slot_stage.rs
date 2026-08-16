use super::{
    HISTORICAL_V2_SLOT_STAGE_CHECKPOINT_SCHEMA_VERSION, HistoricalV2SlotStage,
    HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind,
    HistoricalV2SlotStageOutcome, HistoricalV2StageArtifactKind,
    HistoricalV2TerminalExclusionReason,
};
use sha2::{Digest, Sha256};
use std::fmt;

const CHECKPOINT_CONTRACT: &str = "sniffbench-historical-v2-slot-stage-checkpoint-v1";
const STAGES: [HistoricalV2SlotStage; 10] = [
    HistoricalV2SlotStage::Payload,
    HistoricalV2SlotStage::Materialization,
    HistoricalV2SlotStage::TestMaterialization,
    HistoricalV2SlotStage::SourceCensus,
    HistoricalV2SlotStage::SemanticCensus,
    HistoricalV2SlotStage::AssessmentIdentity,
    HistoricalV2SlotStage::Qualification,
    HistoricalV2SlotStage::TestRecipe,
    HistoricalV2SlotStage::IdenticalTests,
    HistoricalV2SlotStage::ReadyForReview,
];

#[path = "benchmark_history_v2_slot_stage_store.rs"]
mod store;

pub use store::{HistoricalV2SlotStageJournal, HistoricalV2StoredSlotStage};

pub struct HistoricalV2SlotStageCheckpointInput<'a> {
    pub selection_sha256: &'a str,
    pub language: &'a str,
    pub slot_number: usize,
    pub canonical_repository: &'a str,
    pub stage: HistoricalV2SlotStage,
    pub outcome: HistoricalV2SlotStageOutcome,
}

pub fn append_historical_v2_slot_stage_checkpoint(
    history: &[HistoricalV2SlotStageCheckpoint],
    input: HistoricalV2SlotStageCheckpointInput<'_>,
) -> Result<HistoricalV2SlotStageCheckpoint, String> {
    validate_historical_v2_slot_stage_history(history)?;
    let sequence = history.len() + 1;
    let previous = history.last();
    let expected_stage = STAGES
        .get(history.len())
        .ok_or_else(|| "historical-v2 slot already has a terminal checkpoint".to_string())?;
    if input.stage != *expected_stage {
        return Err(format!(
            "historical-v2 slot stage is out of order: expected {expected_stage:?}, got {:?}",
            input.stage
        ));
    }
    if let Some(previous) = previous {
        require_same_slot(previous, &input)?;
        if terminal_outcome(&previous.outcome) {
            return Err("historical-v2 terminal slot checkpoint cannot be extended".to_string());
        }
    }
    validate_outcome(input.stage, &input.outcome)?;
    let mut checkpoint = HistoricalV2SlotStageCheckpoint {
        schema_version: HISTORICAL_V2_SLOT_STAGE_CHECKPOINT_SCHEMA_VERSION,
        checkpoint_contract: CHECKPOINT_CONTRACT.to_string(),
        selection_sha256: input.selection_sha256.to_string(),
        language: input.language.to_string(),
        slot_number: input.slot_number,
        canonical_repository: input.canonical_repository.to_string(),
        sequence,
        previous_checkpoint_sha256: previous.map(|value| value.checkpoint_sha256.clone()),
        stage: input.stage,
        outcome: input.outcome,
        checkpoint_sha256: String::new(),
    };
    validate_identity(&checkpoint)?;
    checkpoint.checkpoint_sha256 = checkpoint_sha256(&checkpoint)?;
    Ok(checkpoint)
}

pub fn validate_historical_v2_slot_stage_history(
    history: &[HistoricalV2SlotStageCheckpoint],
) -> Result<(), String> {
    for (index, checkpoint) in history.iter().enumerate() {
        let expected_sequence = index + 1;
        let expected_stage = STAGES.get(index).ok_or_else(|| {
            "historical-v2 slot history extends past its terminal stage".to_string()
        })?;
        if checkpoint.schema_version != HISTORICAL_V2_SLOT_STAGE_CHECKPOINT_SCHEMA_VERSION
            || checkpoint.checkpoint_contract != CHECKPOINT_CONTRACT
            || checkpoint.sequence != expected_sequence
            || checkpoint.stage != *expected_stage
            || checkpoint.checkpoint_sha256 != checkpoint_sha256(checkpoint)?
        {
            return Err("historical-v2 slot stage checkpoint changed".to_string());
        }
        validate_identity(checkpoint)?;
        validate_outcome(checkpoint.stage, &checkpoint.outcome)?;
        let expected_previous = index
            .checked_sub(1)
            .map(|previous| history[previous].checkpoint_sha256.as_str());
        if checkpoint.previous_checkpoint_sha256.as_deref() != expected_previous {
            return Err("historical-v2 slot checkpoint chain changed".to_string());
        }
        if let Some(first) = history.first()
            && (checkpoint.selection_sha256 != first.selection_sha256
                || checkpoint.language != first.language
                || checkpoint.slot_number != first.slot_number
                || checkpoint.canonical_repository != first.canonical_repository)
        {
            return Err("historical-v2 slot identity changed across checkpoints".to_string());
        }
        if index + 1 < history.len() && terminal_outcome(&checkpoint.outcome) {
            return Err("historical-v2 terminal slot checkpoint has a successor".to_string());
        }
    }
    Ok(())
}

pub(super) fn expected_historical_v2_slot_stage(index: usize) -> Option<HistoricalV2SlotStage> {
    STAGES.get(index).copied()
}

fn validate_identity(checkpoint: &HistoricalV2SlotStageCheckpoint) -> Result<(), String> {
    if !valid_sha256(&checkpoint.selection_sha256)
        || checkpoint.slot_number == 0
        || checkpoint.language.is_empty()
        || !checkpoint
            .language
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        || !valid_repository(&checkpoint.canonical_repository)
    {
        return Err("historical-v2 slot checkpoint identity is invalid".to_string());
    }
    Ok(())
}

fn require_same_slot(
    previous: &HistoricalV2SlotStageCheckpoint,
    input: &HistoricalV2SlotStageCheckpointInput<'_>,
) -> Result<(), String> {
    if previous.selection_sha256 != input.selection_sha256
        || previous.language != input.language
        || previous.slot_number != input.slot_number
        || previous.canonical_repository != input.canonical_repository
    {
        Err("historical-v2 slot identity changed while appending".to_string())
    } else {
        Ok(())
    }
}

fn validate_outcome(
    stage: HistoricalV2SlotStage,
    outcome: &HistoricalV2SlotStageOutcome,
) -> Result<(), String> {
    match outcome {
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind,
            artifact_sha256,
        } => {
            let expected = expected_artifacts(stage);
            if !expected.contains(artifact_kind) || !valid_sha256(artifact_sha256) {
                return Err("historical-v2 completed stage artifact is invalid".to_string());
            }
        }
        HistoricalV2SlotStageOutcome::Excluded {
            reason,
            artifact_kind,
            artifact_sha256,
        } => {
            if exclusion_stage(reason) != stage {
                return Err("historical-v2 exclusion is attached to the wrong stage".to_string());
            }
            if expected_exclusion_artifact(stage) != Some(*artifact_kind)
                || !valid_sha256(artifact_sha256)
            {
                return Err("historical-v2 exclusion artifact is invalid".to_string());
            }
            if let HistoricalV2TerminalExclusionReason::Qualification(reasons) = reason
                && (reasons.is_empty() || !strictly_sorted_unique(reasons))
            {
                return Err("historical-v2 qualification exclusions are not canonical".to_string());
            }
        }
        HistoricalV2SlotStageOutcome::ReadyForReview => {
            if stage != HistoricalV2SlotStage::ReadyForReview {
                return Err(
                    "historical-v2 ready disposition is attached to the wrong stage".to_string(),
                );
            }
        }
    }
    if stage == HistoricalV2SlotStage::ReadyForReview
        && !matches!(outcome, HistoricalV2SlotStageOutcome::ReadyForReview)
    {
        return Err("historical-v2 final slot stage must be ready for review".to_string());
    }
    Ok(())
}

fn expected_artifacts(stage: HistoricalV2SlotStage) -> &'static [HistoricalV2StageArtifactKind] {
    use HistoricalV2SlotStage as Stage;
    use HistoricalV2StageArtifactKind as Artifact;
    match stage {
        Stage::Payload => &[Artifact::SelectedPayload],
        Stage::Materialization => &[Artifact::Materialization],
        Stage::TestMaterialization => &[Artifact::TestMaterialization, Artifact::NoTestPatch],
        Stage::SourceCensus => &[Artifact::SourceCensus],
        Stage::SemanticCensus => &[Artifact::SemanticCensus],
        Stage::AssessmentIdentity => &[Artifact::AssessmentIdentity],
        Stage::Qualification => &[Artifact::Qualification],
        Stage::TestRecipe => &[Artifact::TestRecipe],
        Stage::IdenticalTests => &[Artifact::IdenticalTestExecution],
        Stage::ReadyForReview => &[],
    }
}

fn expected_exclusion_artifact(
    stage: HistoricalV2SlotStage,
) -> Option<HistoricalV2StageArtifactKind> {
    use HistoricalV2SlotStage as Stage;
    use HistoricalV2StageArtifactKind as Artifact;
    match stage {
        Stage::Materialization => Some(Artifact::MaterializationExclusion),
        Stage::TestMaterialization => Some(Artifact::TestMaterializationExclusion),
        Stage::SourceCensus => Some(Artifact::SourceCensusExclusion),
        Stage::SemanticCensus => Some(Artifact::SemanticCensusExclusion),
        Stage::Qualification => Some(Artifact::Qualification),
        Stage::TestRecipe => Some(Artifact::TestRecipe),
        Stage::IdenticalTests => Some(Artifact::IdenticalTestExecution),
        Stage::Payload | Stage::AssessmentIdentity | Stage::ReadyForReview => None,
    }
}

fn exclusion_stage(reason: &HistoricalV2TerminalExclusionReason) -> HistoricalV2SlotStage {
    match reason {
        HistoricalV2TerminalExclusionReason::Materialization(_) => {
            HistoricalV2SlotStage::Materialization
        }
        HistoricalV2TerminalExclusionReason::TestMaterialization(_) => {
            HistoricalV2SlotStage::TestMaterialization
        }
        HistoricalV2TerminalExclusionReason::SourceCensus(_) => HistoricalV2SlotStage::SourceCensus,
        HistoricalV2TerminalExclusionReason::SemanticCensus(_) => {
            HistoricalV2SlotStage::SemanticCensus
        }
        HistoricalV2TerminalExclusionReason::Qualification(_) => {
            HistoricalV2SlotStage::Qualification
        }
        HistoricalV2TerminalExclusionReason::TestRecipe(_) => HistoricalV2SlotStage::TestRecipe,
        HistoricalV2TerminalExclusionReason::IdenticalTests(_) => {
            HistoricalV2SlotStage::IdenticalTests
        }
    }
}

fn terminal_outcome(outcome: &HistoricalV2SlotStageOutcome) -> bool {
    matches!(
        outcome,
        HistoricalV2SlotStageOutcome::Excluded { .. }
            | HistoricalV2SlotStageOutcome::ReadyForReview
    )
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn checkpoint_sha256(checkpoint: &HistoricalV2SlotStageCheckpoint) -> Result<String, String> {
    let mut committed = checkpoint.clone();
    committed.checkpoint_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 slot checkpoint: {error}"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_repository(value: &str) -> bool {
    let parts = value.split('/').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0] == "github.com"
        && parts[1..].iter().all(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && !part.ends_with(".git")
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

impl HistoricalV2SlotStageError {
    pub fn invalid(stage: HistoricalV2SlotStage, detail: impl Into<String>) -> Self {
        Self::new(stage, HistoricalV2SlotStageErrorKind::InvalidInput, detail)
    }

    pub fn unavailable(stage: HistoricalV2SlotStage, detail: impl Into<String>) -> Self {
        Self::new(
            stage,
            HistoricalV2SlotStageErrorKind::InfrastructureUnavailable,
            detail,
        )
    }

    pub fn infrastructure(stage: HistoricalV2SlotStage, detail: impl Into<String>) -> Self {
        Self::new(
            stage,
            HistoricalV2SlotStageErrorKind::InfrastructureFailed,
            detail,
        )
    }

    fn new(
        stage: HistoricalV2SlotStage,
        kind: HistoricalV2SlotStageErrorKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for HistoricalV2SlotStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for HistoricalV2SlotStageError {}

#[cfg(test)]
#[path = "benchmark_history_v2_slot_stage_tests.rs"]
mod tests;
