use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3MechanicalQualificationOutcome,
    HistoricalV3MechanicalQualificationStageRun, HistoricalV3Protocol,
    HistoricalV3RankArtifactKind, HistoricalV3RankJournal, HistoricalV3RankJournalError,
    HistoricalV3RankStage, HistoricalV3RankStageOutcome,
    derive_historical_v3_mechanical_qualification, historical_v3_rank_identity,
};
use super::store::{MechanicalInputs, invalid, read_inputs, resume};
use std::path::Path;

pub fn run_historical_v3_mechanical_qualification_stage(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
) -> Result<HistoricalV3MechanicalQualificationStageRun, HistoricalV3RankJournalError> {
    run_historical_v3_mechanical_qualification_stage_with(
        protocol,
        collection,
        stream_rank,
        journal_root,
        |inputs| {
            derive_historical_v3_mechanical_qualification(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
            )
            .map_err(invalid)
        },
    )
}

pub(super) fn run_historical_v3_mechanical_qualification_stage_with<F>(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    derive: F,
) -> Result<HistoricalV3MechanicalQualificationStageRun, HistoricalV3RankJournalError>
where
    F: FnOnce(
        &MechanicalInputs,
    )
        -> Result<HistoricalV3MechanicalQualificationOutcome, HistoricalV3RankJournalError>,
{
    let identity =
        historical_v3_rank_identity(protocol, collection, stream_rank).map_err(invalid)?;
    let mut journal = HistoricalV3RankJournal::open(journal_root, &identity)?;
    let inputs = read_inputs(journal.history())?;
    if let Some(stored) = journal.history().get(3) {
        return resume(protocol, collection, &inputs, stored);
    }
    if journal.next_stage() != Some(HistoricalV3RankStage::MechanicalQualification) {
        return Err(invalid(
            "historical-v3 rank is not open for mechanical qualification",
        ));
    }
    match derive(&inputs)? {
        HistoricalV3MechanicalQualificationOutcome::Qualified(artifact) => {
            super::super::validate_historical_v3_mechanical_qualification(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &artifact,
            )
            .map_err(invalid)?;
            journal.append(
                HistoricalV3RankStage::MechanicalQualification,
                HistoricalV3RankStageOutcome::Completed {
                    artifact_kind: HistoricalV3RankArtifactKind::MechanicalQualification,
                    artifact_sha256: artifact.qualification_sha256.clone(),
                },
                Some(artifact.as_ref()),
            )?;
            Ok(HistoricalV3MechanicalQualificationStageRun::Qualified {
                artifact,
                resumed: false,
            })
        }
        HistoricalV3MechanicalQualificationOutcome::Excluded(artifact) => {
            super::super::validate_historical_v3_mechanical_qualification_exclusion(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &artifact,
            )
            .map_err(invalid)?;
            journal.append(
                HistoricalV3RankStage::MechanicalQualification,
                HistoricalV3RankStageOutcome::Excluded {
                    artifact_kind: HistoricalV3RankArtifactKind::MechanicalQualificationExclusion,
                    artifact_sha256: artifact.exclusion_sha256.clone(),
                },
                Some(artifact.as_ref()),
            )?;
            Ok(HistoricalV3MechanicalQualificationStageRun::Excluded {
                artifact,
                resumed: false,
            })
        }
    }
}
