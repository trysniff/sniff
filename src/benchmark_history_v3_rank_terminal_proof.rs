use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3IdenticalTestOutcome, HistoricalV3IdenticalTests,
    HistoricalV3Materialization, HistoricalV3MaterializationExclusion,
    HistoricalV3MechanicalQualification, HistoricalV3MechanicalQualificationExclusion,
    HistoricalV3Protocol, HistoricalV3SemanticCensus, HistoricalV3SemanticCensusExclusion,
    HistoricalV3SourceCensus, HistoricalV3SourceCensusExclusion, HistoricalV3TestRecipe,
    HistoricalV3TestRecipeExclusion, validate_historical_v3_identical_tests,
    validate_historical_v3_materialization_commitment,
    validate_historical_v3_materialization_exclusion,
    validate_historical_v3_mechanical_qualification,
    validate_historical_v3_mechanical_qualification_exclusion,
    validate_historical_v3_semantic_census_commitment,
    validate_historical_v3_semantic_census_exclusion,
    validate_historical_v3_source_census_commitment,
    validate_historical_v3_source_census_exclusion, validate_historical_v3_test_recipe,
    validate_historical_v3_test_recipe_exclusion,
};
use super::{
    HistoricalV3RankArtifactKind as ArtifactKind, HistoricalV3RankIdentity,
    HistoricalV3RankJournal, HistoricalV3RankJournalError, HistoricalV3RankStage as Stage,
    HistoricalV3RankStageOutcome, HistoricalV3StoredRankStage, historical_v3_rank_identity,
};
use serde::de::DeserializeOwned;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3VerifiedTerminalExclusion {
    rank: HistoricalV3RankIdentity,
    stage: Stage,
    artifact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3VerifiedQualification {
    rank: HistoricalV3RankIdentity,
    qualification_sha256: String,
}

impl HistoricalV3VerifiedQualification {
    pub fn rank(&self) -> &HistoricalV3RankIdentity {
        &self.rank
    }

    pub fn qualification_sha256(&self) -> &str {
        &self.qualification_sha256
    }
}

#[cfg(test)]
impl HistoricalV3VerifiedQualification {
    pub(crate) fn synthetic(rank: HistoricalV3RankIdentity) -> Self {
        Self {
            rank,
            qualification_sha256: "c".repeat(64),
        }
    }
}

pub fn verify_historical_v3_qualified_rank(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
) -> Result<HistoricalV3VerifiedQualification, HistoricalV3RankJournalError> {
    let stage = Stage::MechanicalQualification;
    let rank = historical_v3_rank_identity(protocol, collection, stream_rank)
        .map_err(|detail| HistoricalV3RankJournalError::invalid(stage, detail))?;
    let journal = HistoricalV3RankJournal::open(journal_root, &rank)?;
    let history = journal.history();
    if history.len() != 4 {
        return Err(HistoricalV3RankJournalError::invalid(
            stage,
            "historical-v3 review-cap rank is not stopped immediately after qualification",
        ));
    }
    let qualification_sha256 = verify_qualified_prefix(protocol, collection, history)
        .map_err(|detail| HistoricalV3RankJournalError::invalid(stage, detail))?;
    Ok(HistoricalV3VerifiedQualification {
        rank,
        qualification_sha256,
    })
}

impl HistoricalV3VerifiedTerminalExclusion {
    pub fn rank(&self) -> &HistoricalV3RankIdentity {
        &self.rank
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }
}

pub fn verify_historical_v3_terminal_exclusion(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
) -> Result<HistoricalV3VerifiedTerminalExclusion, HistoricalV3RankJournalError> {
    let rank = historical_v3_rank_identity(protocol, collection, stream_rank)
        .map_err(|detail| HistoricalV3RankJournalError::invalid(Stage::Materialization, detail))?;
    let journal = HistoricalV3RankJournal::open(journal_root, &rank)?;
    let history = journal.history();
    let terminal = history.last().ok_or_else(|| {
        HistoricalV3RankJournalError::invalid(
            Stage::Materialization,
            "historical-v3 rank has no terminal checkpoint",
        )
    })?;
    let stage = terminal.checkpoint.stage;
    let HistoricalV3RankStageOutcome::Excluded {
        artifact_sha256, ..
    } = &terminal.checkpoint.outcome
    else {
        return Err(HistoricalV3RankJournalError::invalid(
            stage,
            "historical-v3 rank has no terminal exclusion",
        ));
    };
    verify_exclusion_chain(protocol, collection, history, stage)
        .map_err(|detail| HistoricalV3RankJournalError::invalid(stage, detail))?;
    Ok(HistoricalV3VerifiedTerminalExclusion {
        rank,
        stage,
        artifact_sha256: artifact_sha256.clone(),
    })
}

fn verify_exclusion_chain(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    history: &[HistoricalV3StoredRankStage],
    stage: Stage,
) -> Result<(), String> {
    let materialization = if stage > Stage::Materialization {
        let (artifact, hash) = read_stage::<HistoricalV3Materialization>(
            history,
            0,
            ArtifactKind::Materialization,
            false,
        )?;
        require_hash(&artifact.materialization_sha256, &hash)?;
        validate_historical_v3_materialization_commitment(protocol, collection, &artifact)
            .map_err(|error| error.detail)?;
        Some(artifact)
    } else {
        None
    };
    let source_census = if stage > Stage::SourceCensus {
        let (artifact, hash) =
            read_stage::<HistoricalV3SourceCensus>(history, 1, ArtifactKind::SourceCensus, false)?;
        require_hash(&artifact.source_census_sha256, &hash)?;
        validate_historical_v3_source_census_commitment(
            protocol,
            collection,
            required(&materialization)?,
            &artifact,
        )?;
        Some(artifact)
    } else {
        None
    };
    let semantic_census = if stage > Stage::SemanticCensus {
        let (artifact, hash) = read_stage::<HistoricalV3SemanticCensus>(
            history,
            2,
            ArtifactKind::SemanticCensus,
            false,
        )?;
        require_hash(&artifact.semantic_census_sha256, &hash)?;
        validate_historical_v3_semantic_census_commitment(
            protocol,
            collection,
            required(&materialization)?,
            required(&source_census)?,
            &artifact,
        )?;
        Some(artifact)
    } else {
        None
    };
    let qualification = if stage > Stage::MechanicalQualification {
        let (artifact, hash) = read_stage::<HistoricalV3MechanicalQualification>(
            history,
            3,
            ArtifactKind::MechanicalQualification,
            false,
        )?;
        require_hash(&artifact.qualification_sha256, &hash)?;
        validate_historical_v3_mechanical_qualification(
            protocol,
            collection,
            required(&materialization)?,
            required(&source_census)?,
            required(&semantic_census)?,
            &artifact,
        )?;
        Some(artifact)
    } else {
        None
    };
    let recipe = if stage > Stage::TestRecipe {
        let (artifact, hash) =
            read_stage::<HistoricalV3TestRecipe>(history, 4, ArtifactKind::TestRecipe, false)?;
        require_hash(&artifact.recipe_sha256, &hash)?;
        validate_historical_v3_test_recipe(
            protocol,
            collection,
            required(&materialization)?,
            required(&source_census)?,
            required(&semantic_census)?,
            required(&qualification)?,
            &artifact,
        )?;
        Some(artifact)
    } else {
        None
    };

    let terminal_index = history.len() - 1;
    match stage {
        Stage::Materialization => {
            let (artifact, hash) = read_stage::<HistoricalV3MaterializationExclusion>(
                history,
                terminal_index,
                ArtifactKind::MaterializationExclusion,
                true,
            )?;
            require_hash(&artifact.exclusion_sha256, &hash)?;
            validate_historical_v3_materialization_exclusion(protocol, collection, &artifact)
                .map_err(|error| error.detail)?;
        }
        Stage::SourceCensus => {
            let (artifact, hash) = read_stage::<HistoricalV3SourceCensusExclusion>(
                history,
                terminal_index,
                ArtifactKind::SourceCensusExclusion,
                true,
            )?;
            require_hash(&artifact.exclusion_sha256, &hash)?;
            validate_historical_v3_source_census_exclusion(
                protocol,
                collection,
                required(&materialization)?,
                &artifact,
            )?;
        }
        Stage::SemanticCensus => {
            let (artifact, hash) = read_stage::<HistoricalV3SemanticCensusExclusion>(
                history,
                terminal_index,
                ArtifactKind::SemanticCensusExclusion,
                true,
            )?;
            require_hash(&artifact.exclusion_sha256, &hash)?;
            validate_historical_v3_semantic_census_exclusion(
                protocol,
                collection,
                required(&materialization)?,
                required(&source_census)?,
                &artifact,
            )?;
        }
        Stage::MechanicalQualification => {
            let (artifact, hash) = read_stage::<HistoricalV3MechanicalQualificationExclusion>(
                history,
                terminal_index,
                ArtifactKind::MechanicalQualificationExclusion,
                true,
            )?;
            require_hash(&artifact.exclusion_sha256, &hash)?;
            validate_historical_v3_mechanical_qualification_exclusion(
                protocol,
                collection,
                required(&materialization)?,
                required(&source_census)?,
                required(&semantic_census)?,
                &artifact,
            )?;
        }
        Stage::TestRecipe => {
            let (artifact, hash) = read_stage::<HistoricalV3TestRecipeExclusion>(
                history,
                terminal_index,
                ArtifactKind::TestRecipeExclusion,
                true,
            )?;
            require_hash(&artifact.exclusion_sha256, &hash)?;
            validate_historical_v3_test_recipe_exclusion(
                protocol,
                collection,
                required(&materialization)?,
                required(&source_census)?,
                required(&semantic_census)?,
                required(&qualification)?,
                &artifact,
            )?;
        }
        Stage::IdenticalTests => {
            let (artifact, hash) = read_stage::<HistoricalV3IdenticalTests>(
                history,
                terminal_index,
                ArtifactKind::IdenticalTestsExclusion,
                true,
            )?;
            require_hash(&artifact.execution_sha256, &hash)?;
            if !matches!(
                artifact.outcome,
                HistoricalV3IdenticalTestOutcome::Excluded { .. }
            ) {
                return Err("historical-v3 terminal execution did not exclude the rank".to_string());
            }
            validate_historical_v3_identical_tests(protocol, required(&recipe)?, &artifact)?;
        }
        Stage::ReadyForSourceReview => {
            return Err("historical-v3 source review cannot be a terminal exclusion".to_string());
        }
    }
    Ok(())
}

fn verify_qualified_prefix(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    history: &[HistoricalV3StoredRankStage],
) -> Result<String, String> {
    let (materialization, hash) = read_stage::<HistoricalV3Materialization>(
        history,
        0,
        ArtifactKind::Materialization,
        false,
    )?;
    require_hash(&materialization.materialization_sha256, &hash)?;
    validate_historical_v3_materialization_commitment(protocol, collection, &materialization)
        .map_err(|error| error.detail)?;
    let (source_census, hash) =
        read_stage::<HistoricalV3SourceCensus>(history, 1, ArtifactKind::SourceCensus, false)?;
    require_hash(&source_census.source_census_sha256, &hash)?;
    validate_historical_v3_source_census_commitment(
        protocol,
        collection,
        &materialization,
        &source_census,
    )?;
    let (semantic_census, hash) =
        read_stage::<HistoricalV3SemanticCensus>(history, 2, ArtifactKind::SemanticCensus, false)?;
    require_hash(&semantic_census.semantic_census_sha256, &hash)?;
    validate_historical_v3_semantic_census_commitment(
        protocol,
        collection,
        &materialization,
        &source_census,
        &semantic_census,
    )?;
    let (qualification, hash) = read_stage::<HistoricalV3MechanicalQualification>(
        history,
        3,
        ArtifactKind::MechanicalQualification,
        false,
    )?;
    require_hash(&qualification.qualification_sha256, &hash)?;
    validate_historical_v3_mechanical_qualification(
        protocol,
        collection,
        &materialization,
        &source_census,
        &semantic_census,
        &qualification,
    )?;
    Ok(hash)
}

fn read_stage<T: DeserializeOwned>(
    history: &[HistoricalV3StoredRankStage],
    index: usize,
    kind: ArtifactKind,
    excluded: bool,
) -> Result<(T, String), String> {
    let stored = history
        .get(index)
        .ok_or_else(|| "historical-v3 terminal exclusion is missing a prior stage".to_string())?;
    let outcome = &stored.checkpoint.outcome;
    let hash = match outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind,
            artifact_sha256,
        } if !excluded && *artifact_kind == kind => artifact_sha256,
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind,
            artifact_sha256,
        } if excluded && *artifact_kind == kind => artifact_sha256,
        _ => return Err("historical-v3 terminal exclusion has a wrong stage artifact".to_string()),
    };
    let artifact = stored.read_artifact::<T>()?.ok_or_else(|| {
        "historical-v3 terminal exclusion is missing its committed artifact".to_string()
    })?;
    Ok((artifact, hash.clone()))
}

fn require_hash(actual: &str, committed: &str) -> Result<(), String> {
    if actual != committed {
        return Err(
            "historical-v3 terminal exclusion artifact hash differs from its checkpoint"
                .to_string(),
        );
    }
    Ok(())
}

fn required<T>(value: &Option<T>) -> Result<&T, String> {
    value.as_ref().ok_or_else(|| {
        "historical-v3 terminal exclusion is missing a validated prior stage".to_string()
    })
}
