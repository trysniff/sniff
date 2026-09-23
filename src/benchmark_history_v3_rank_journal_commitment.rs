use super::super::validate_historical_v3_candidate_collection_commitment;
use super::{
    HISTORICAL_V3_RANK_CHECKPOINT_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3Protocol, HistoricalV3RankArtifactKind, HistoricalV3RankCheckpoint,
    HistoricalV3RankIdentity, HistoricalV3RankStage, HistoricalV3RankStageOutcome,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(super) const CHECKPOINT_CONTRACT: &str = "sniffbench-historical-v3-rank-stage-checkpoint-v2";

const STAGES: [HistoricalV3RankStage; 7] = [
    HistoricalV3RankStage::Materialization,
    HistoricalV3RankStage::SourceCensus,
    HistoricalV3RankStage::SemanticCensus,
    HistoricalV3RankStage::MechanicalQualification,
    HistoricalV3RankStage::TestRecipe,
    HistoricalV3RankStage::IdenticalTests,
    HistoricalV3RankStage::ReadyForSourceReview,
];

pub fn historical_v3_rank_identity(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
) -> Result<HistoricalV3RankIdentity, String> {
    validate_historical_v3_candidate_collection_commitment(protocol, collection)?;
    historical_v3_rank_identity_in_validated_collection(protocol, collection, stream_rank)
}

pub(crate) fn historical_v3_rank_identity_in_validated_collection(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
) -> Result<HistoricalV3RankIdentity, String> {
    let task = collection
        .manifest
        .stream_task
        .candidates
        .get(stream_rank.saturating_sub(1))
        .filter(|task| task.stream_rank == stream_rank)
        .ok_or_else(|| "historical-v3 stream rank is absent".to_string())?;
    let repository = collection
        .manifest
        .repositories
        .iter()
        .find(|repository| {
            repository.language == task.identity.language
                && repository.repository_id == task.identity.repository_id
        })
        .ok_or_else(|| "historical-v3 candidate repository is absent".to_string())?;
    if repository.name_with_owner.split('/').count() != 2
        || repository.name_with_owner.contains('\\')
        || repository.name_with_owner.contains(':')
    {
        return Err("historical-v3 candidate repository is not canonical GitHub".to_string());
    }
    let identity = HistoricalV3RankIdentity {
        protocol_sha256: protocol.protocol_sha256.clone(),
        candidate_manifest_sha256: collection.manifest.manifest_sha256.clone(),
        stream_task_sha256: collection.manifest.stream_task.task_sha256.clone(),
        stream_rank: task.stream_rank,
        rank_sha256: task.rank_sha256.clone(),
        candidate: task.identity.clone(),
        name_with_owner: repository.name_with_owner.clone(),
    };
    validate_historical_v3_rank_identity(&identity)?;
    Ok(identity)
}

pub fn append_historical_v3_rank_checkpoint(
    history: &[HistoricalV3RankCheckpoint],
    identity: &HistoricalV3RankIdentity,
    stage: HistoricalV3RankStage,
    outcome: HistoricalV3RankStageOutcome,
) -> Result<HistoricalV3RankCheckpoint, String> {
    validate_historical_v3_rank_history(history)?;
    validate_historical_v3_rank_identity(identity)?;
    let expected = expected_historical_v3_rank_stage(history.len())
        .ok_or_else(|| "historical-v3 rank already has a terminal checkpoint".to_string())?;
    if stage != expected {
        return Err(format!(
            "historical-v3 rank stage is out of order: expected {expected:?}, got {stage:?}"
        ));
    }
    if let Some(previous) = history.last() {
        if &previous.identity != identity {
            return Err("historical-v3 rank identity changed while appending".to_string());
        }
        if terminal_outcome(&previous.outcome) {
            return Err("historical-v3 terminal rank checkpoint cannot be extended".to_string());
        }
    }
    validate_outcome(stage, &outcome)?;
    let mut checkpoint = HistoricalV3RankCheckpoint {
        schema_version: HISTORICAL_V3_RANK_CHECKPOINT_SCHEMA_VERSION,
        checkpoint_contract: CHECKPOINT_CONTRACT.to_string(),
        identity: identity.clone(),
        sequence: history.len() + 1,
        previous_checkpoint_sha256: history
            .last()
            .map(|checkpoint| checkpoint.checkpoint_sha256.clone()),
        stage,
        outcome,
        checkpoint_sha256: String::new(),
    };
    checkpoint.checkpoint_sha256 = checkpoint_sha256(&checkpoint)?;
    Ok(checkpoint)
}

pub fn validate_historical_v3_rank_history(
    history: &[HistoricalV3RankCheckpoint],
) -> Result<(), String> {
    for (index, checkpoint) in history.iter().enumerate() {
        let expected_stage = expected_historical_v3_rank_stage(index).ok_or_else(|| {
            "historical-v3 rank history extends past its terminal stage".to_string()
        })?;
        if checkpoint.schema_version != HISTORICAL_V3_RANK_CHECKPOINT_SCHEMA_VERSION
            || checkpoint.checkpoint_contract != CHECKPOINT_CONTRACT
            || checkpoint.sequence != index + 1
            || checkpoint.stage != expected_stage
            || checkpoint.checkpoint_sha256 != checkpoint_sha256(checkpoint)?
        {
            return Err("historical-v3 rank checkpoint changed".to_string());
        }
        validate_historical_v3_rank_identity(&checkpoint.identity)?;
        validate_outcome(checkpoint.stage, &checkpoint.outcome)?;
        let expected_previous = index
            .checked_sub(1)
            .map(|previous| history[previous].checkpoint_sha256.as_str());
        if checkpoint.previous_checkpoint_sha256.as_deref() != expected_previous {
            return Err("historical-v3 rank checkpoint chain changed".to_string());
        }
        if let Some(first) = history.first()
            && checkpoint.identity != first.identity
        {
            return Err("historical-v3 rank identity changed across checkpoints".to_string());
        }
        if index + 1 < history.len() && terminal_outcome(&checkpoint.outcome) {
            return Err("historical-v3 terminal rank checkpoint has a successor".to_string());
        }
    }
    Ok(())
}

pub(super) fn validate_historical_v3_rank_identity(
    identity: &HistoricalV3RankIdentity,
) -> Result<(), String> {
    if !valid_sha256(&identity.protocol_sha256)
        || !valid_sha256(&identity.candidate_manifest_sha256)
        || !valid_sha256(&identity.stream_task_sha256)
        || identity.stream_rank == 0
        || !valid_sha256(&identity.rank_sha256)
        || identity.candidate.repository_id == 0
        || identity.candidate.pull_request_number == 0
        || !valid_oid(&identity.candidate.base_commit)
        || !valid_oid(&identity.candidate.head_commit)
        || !valid_oid(&identity.candidate.merge_commit)
        || !valid_repository(&identity.name_with_owner)
    {
        return Err("historical-v3 rank identity is invalid".to_string());
    }
    Ok(())
}

pub(super) fn expected_historical_v3_rank_stage(index: usize) -> Option<HistoricalV3RankStage> {
    STAGES.get(index).copied()
}

fn validate_outcome(
    stage: HistoricalV3RankStage,
    outcome: &HistoricalV3RankStageOutcome,
) -> Result<(), String> {
    match outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind,
            artifact_sha256,
        } => {
            if expected_completed_artifact(stage) != Some(*artifact_kind)
                || !valid_sha256(artifact_sha256)
            {
                return Err("historical-v3 completed rank artifact is invalid".to_string());
            }
        }
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind,
            artifact_sha256,
        } => {
            if expected_exclusion_artifact(stage) != Some(*artifact_kind)
                || !valid_sha256(artifact_sha256)
            {
                return Err("historical-v3 rank exclusion artifact is invalid".to_string());
            }
        }
        HistoricalV3RankStageOutcome::ReadyForSourceReview { bundle_sha256 } => {
            if stage != HistoricalV3RankStage::ReadyForSourceReview || !valid_sha256(bundle_sha256)
            {
                return Err(
                    "historical-v3 review readiness has an invalid bundle commitment".to_string(),
                );
            }
        }
    }
    if stage == HistoricalV3RankStage::ReadyForSourceReview
        && !matches!(
            outcome,
            HistoricalV3RankStageOutcome::ReadyForSourceReview { .. }
        )
    {
        return Err("historical-v3 final rank stage must be ready for source review".to_string());
    }
    Ok(())
}

fn expected_completed_artifact(
    stage: HistoricalV3RankStage,
) -> Option<HistoricalV3RankArtifactKind> {
    use HistoricalV3RankArtifactKind as Artifact;
    use HistoricalV3RankStage as Stage;
    match stage {
        Stage::Materialization => Some(Artifact::Materialization),
        Stage::SourceCensus => Some(Artifact::SourceCensus),
        Stage::SemanticCensus => Some(Artifact::SemanticCensus),
        Stage::MechanicalQualification => Some(Artifact::MechanicalQualification),
        Stage::TestRecipe => Some(Artifact::TestRecipe),
        Stage::IdenticalTests => Some(Artifact::IdenticalTests),
        Stage::ReadyForSourceReview => None,
    }
}

fn expected_exclusion_artifact(
    stage: HistoricalV3RankStage,
) -> Option<HistoricalV3RankArtifactKind> {
    use HistoricalV3RankArtifactKind as Artifact;
    use HistoricalV3RankStage as Stage;
    match stage {
        Stage::Materialization => Some(Artifact::MaterializationExclusion),
        Stage::SourceCensus => Some(Artifact::SourceCensusExclusion),
        Stage::SemanticCensus => Some(Artifact::SemanticCensusExclusion),
        Stage::MechanicalQualification => Some(Artifact::MechanicalQualificationExclusion),
        Stage::TestRecipe => Some(Artifact::TestRecipeExclusion),
        Stage::IdenticalTests => Some(Artifact::IdenticalTestsExclusion),
        Stage::ReadyForSourceReview => None,
    }
}

fn checkpoint_sha256(checkpoint: &HistoricalV3RankCheckpoint) -> Result<String, String> {
    let mut committed = checkpoint.clone();
    committed.checkpoint_sha256.clear();
    json_sha256(&committed)
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 rank checkpoint: {error}"))
}

fn terminal_outcome(outcome: &HistoricalV3RankStageOutcome) -> bool {
    matches!(
        outcome,
        HistoricalV3RankStageOutcome::Excluded { .. }
            | HistoricalV3RankStageOutcome::ReadyForSourceReview { .. }
    )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex)
}

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(lower_hex)
}

fn valid_repository(value: &str) -> bool {
    let mut parts = value.split('/');
    matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(repository), None)
        if !owner.is_empty()
            && !repository.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')))
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}
