use super::super::intentional_boundary_source_census::INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT;
use super::super::intentional_boundary_source_census_commitment::validate_source_census_commitment;
use super::super::{
    BoundaryGitEntryKind, HistoricalV3CandidateCollection, HistoricalV3Materialization,
    HistoricalV3Protocol, HistoricalV3RankIdentity, historical_v3_rank_identity,
    validate_historical_v3_materialization_commitment,
    validate_intentional_boundary_repository_inventory_commitment_typed,
};
use super::failure_commitment::{
    failure_identity, failure_key, validate_failure, validate_failure_inventory_binding,
};
use super::{
    HISTORICAL_V3_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V3_SOURCE_CENSUS_SCHEMA_VERSION, HistoricalV3SourceCensus,
    HistoricalV3SourceCensusExclusion, HistoricalV3SourceCensusExclusionReason,
    HistoricalV3SourceFileFacts, HistoricalV3SourceSide, HistoricalV3SourceSnapshot,
    HistoricalV3SourceSnapshotEvidence, SOURCE_CENSUS_CONTRACT, SOURCE_CENSUS_EXCLUSION_CONTRACT,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn validate_historical_v3_source_census_commitment(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    artifact: &HistoricalV3SourceCensus,
) -> Result<(), String> {
    let expected_rank =
        historical_v3_rank_identity(protocol, collection, artifact.rank.stream_rank)?;
    validate_historical_v3_materialization_commitment(protocol, collection, materialization)
        .map_err(|error| error.detail)?;
    if artifact.schema_version != HISTORICAL_V3_SOURCE_CENSUS_SCHEMA_VERSION
        || artifact.source_census_contract != SOURCE_CENSUS_CONTRACT
        || artifact.rank != expected_rank
        || artifact.materialization_sha256 != materialization.materialization_sha256
        || artifact.source_extension_contract != INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT
    {
        return Err("historical-v3 source census identity changed".to_string());
    }
    validate_snapshot(
        &artifact.rank,
        materialization,
        &artifact.base,
        HistoricalV3SourceSide::Base,
        &materialization.identity.base_commit,
    )?;
    validate_snapshot(
        &artifact.rank,
        materialization,
        &artifact.merge,
        HistoricalV3SourceSide::Merge,
        &materialization.identity.merge_commit,
    )?;
    if artifact.source_census_sha256 != source_census_sha256(artifact)? {
        return Err("historical-v3 source census commitment changed".to_string());
    }
    Ok(())
}

pub fn validate_historical_v3_source_census_exclusion(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    artifact: &HistoricalV3SourceCensusExclusion,
) -> Result<(), String> {
    let expected_rank =
        historical_v3_rank_identity(protocol, collection, artifact.rank.stream_rank)?;
    validate_historical_v3_materialization_commitment(protocol, collection, materialization)
        .map_err(|error| error.detail)?;
    if artifact.schema_version != HISTORICAL_V3_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION
        || artifact.exclusion_contract != SOURCE_CENSUS_EXCLUSION_CONTRACT
        || artifact.rank != expected_rank
        || artifact.materialization_sha256 != materialization.materialization_sha256
        || artifact.source_extension_contract != INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT
        || artifact.sides.len() != 2
        || evidence_side(&artifact.sides[0]) != HistoricalV3SourceSide::Base
        || evidence_side(&artifact.sides[1]) != HistoricalV3SourceSide::Merge
        || !artifact
            .sides
            .iter()
            .any(|side| matches!(side, HistoricalV3SourceSnapshotEvidence::Excluded { .. }))
    {
        return Err("historical-v3 source exclusion identity changed".to_string());
    }
    validate_side_evidence(
        &artifact.rank,
        materialization,
        &artifact.sides[0],
        HistoricalV3SourceSide::Base,
        &materialization.identity.base_commit,
    )?;
    validate_side_evidence(
        &artifact.rank,
        materialization,
        &artifact.sides[1],
        HistoricalV3SourceSide::Merge,
        &materialization.identity.merge_commit,
    )?;
    if artifact.exclusion_sha256 != exclusion_sha256(artifact)? {
        return Err("historical-v3 source exclusion commitment changed".to_string());
    }
    Ok(())
}

pub(super) fn seal_source_census(
    mut artifact: HistoricalV3SourceCensus,
) -> Result<HistoricalV3SourceCensus, String> {
    artifact.source_census_sha256.clear();
    artifact.source_census_sha256 = source_census_sha256(&artifact)?;
    Ok(artifact)
}

pub(super) fn seal_source_exclusion(
    mut artifact: HistoricalV3SourceCensusExclusion,
) -> Result<HistoricalV3SourceCensusExclusion, String> {
    artifact.exclusion_sha256.clear();
    artifact.exclusion_sha256 = exclusion_sha256(&artifact)?;
    Ok(artifact)
}

pub(super) fn seal_snapshot(
    mut snapshot: HistoricalV3SourceSnapshot,
) -> Result<HistoricalV3SourceSnapshot, String> {
    snapshot.snapshot_sha256.clear();
    snapshot.snapshot_sha256 = snapshot_sha256(&snapshot)?;
    Ok(snapshot)
}

fn validate_snapshot(
    rank: &HistoricalV3RankIdentity,
    materialization: &HistoricalV3Materialization,
    snapshot: &HistoricalV3SourceSnapshot,
    side: HistoricalV3SourceSide,
    revision: &str,
) -> Result<(), String> {
    let repository = format!("github.com/{}", rank.name_with_owner);
    if snapshot.side != side
        || snapshot.revision != revision
        || snapshot.inventory.repository != repository
        || snapshot.inventory.revision != revision
        || snapshot.source_census.repository != repository
        || snapshot.source_census.revision != revision
        || snapshot.snapshot_sha256 != snapshot_sha256(snapshot)?
    {
        return Err("historical-v3 source snapshot identity changed".to_string());
    }
    validate_intentional_boundary_repository_inventory_commitment_typed(
        &repository,
        revision,
        &snapshot.inventory,
    )
    .map_err(|error| error.detail)?;
    validate_source_census_commitment(&snapshot.inventory, &snapshot.source_census)?;
    validate_source_file_facts(snapshot)?;
    if snapshot.source_census.source_files.is_empty() || materialization.identity != rank.candidate
    {
        return Err("historical-v3 source snapshot is not reviewable".to_string());
    }
    Ok(())
}

fn validate_source_file_facts(snapshot: &HistoricalV3SourceSnapshot) -> Result<(), String> {
    if snapshot.source_file_facts.len() != snapshot.source_census.source_files.len()
        || snapshot
            .source_file_facts
            .windows(2)
            .any(|pair| pair[0].repository_path >= pair[1].repository_path)
    {
        return Err("historical-v3 source facts are incomplete or noncanonical".to_string());
    }
    for (facts, source) in snapshot
        .source_file_facts
        .iter()
        .zip(&snapshot.source_census.source_files)
    {
        validate_source_file_fact(facts, source)?;
    }
    Ok(())
}

fn validate_source_file_fact(
    facts: &HistoricalV3SourceFileFacts,
    source: &super::super::IntentionalBoundarySourceFile,
) -> Result<(), String> {
    if facts.repository_path != source.repository_path
        || facts.source_sha256 != source.source_sha256
        || !is_lower_sha256(&facts.syntax_sha256)
        || facts.methods.len() != source.methods.len()
    {
        return Err("historical-v3 source facts changed their source identity".to_string());
    }
    for (facts, method) in facts.methods.iter().zip(&source.methods) {
        if facts.parser_unit_id != method.parser_unit_id
            || facts.source_sha256 != method.source_sha256
            || !is_lower_sha256(&facts.syntax_sha256)
        {
            return Err("historical-v3 source method facts changed their AST identity".to_string());
        }
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_side_evidence(
    rank: &HistoricalV3RankIdentity,
    materialization: &HistoricalV3Materialization,
    evidence: &HistoricalV3SourceSnapshotEvidence,
    expected_side: HistoricalV3SourceSide,
    expected_revision: &str,
) -> Result<(), String> {
    match evidence {
        HistoricalV3SourceSnapshotEvidence::Completed { snapshot } => validate_snapshot(
            rank,
            materialization,
            snapshot,
            expected_side,
            expected_revision,
        ),
        HistoricalV3SourceSnapshotEvidence::Excluded {
            side,
            revision,
            inventory,
            reason,
            failures,
        } => {
            let repository = format!("github.com/{}", rank.name_with_owner);
            if *side != expected_side
                || revision != expected_revision
                || inventory.repository != repository
                || inventory.revision != expected_revision
            {
                return Err("historical-v3 excluded source evidence changed".to_string());
            }
            validate_intentional_boundary_repository_inventory_commitment_typed(
                &repository,
                expected_revision,
                inventory,
            )
            .map_err(|error| error.detail)?;
            match reason {
                HistoricalV3SourceCensusExclusionReason::NoSupportedSources
                    if !failures.is_empty() =>
                {
                    return Err("historical-v3 source-free evidence has failures".to_string());
                }
                HistoricalV3SourceCensusExclusionReason::UnsupportedProjectShape
                    if failures.is_empty() =>
                {
                    return Err("historical-v3 unsupported source evidence is empty".to_string());
                }
                _ => {}
            }
            if *reason == HistoricalV3SourceCensusExclusionReason::NoSupportedSources
                && inventory.tracked_entries.iter().any(|entry| {
                    entry.kind == BoundaryGitEntryKind::Gitlink
                        || Path::new(&entry.repository_path)
                            .extension()
                            .and_then(|extension| extension.to_str())
                            .and_then(crate::languages::get_adapter)
                            .is_some()
                })
            {
                return Err(
                    "historical-v3 source-free inventory contains supported source".to_string(),
                );
            }
            if failures
                .windows(2)
                .any(|pair| failure_key(&pair[0]) >= failure_key(&pair[1]))
            {
                return Err("historical-v3 source failures are not canonical".to_string());
            }
            for failure in failures {
                validate_failure(failure, expected_revision.len())?;
                let (path, object_id) = failure_identity(failure);
                let entry = inventory
                    .tracked_entries
                    .iter()
                    .find(|entry| entry.repository_path == path)
                    .ok_or_else(|| {
                        "historical-v3 source failure is absent from its inventory".to_string()
                    })?;
                if entry.object_id != object_id {
                    return Err(
                        "historical-v3 source failure changed its inventory object".to_string()
                    );
                }
                validate_failure_inventory_binding(failure, entry)?;
            }
            Ok(())
        }
    }
}

fn evidence_side(evidence: &HistoricalV3SourceSnapshotEvidence) -> HistoricalV3SourceSide {
    match evidence {
        HistoricalV3SourceSnapshotEvidence::Completed { snapshot } => snapshot.side,
        HistoricalV3SourceSnapshotEvidence::Excluded { side, .. } => *side,
    }
}

fn snapshot_sha256(snapshot: &HistoricalV3SourceSnapshot) -> Result<String, String> {
    let mut committed = snapshot.clone();
    committed.snapshot_sha256.clear();
    json_sha256(&committed)
}

fn source_census_sha256(artifact: &HistoricalV3SourceCensus) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.source_census_sha256.clear();
    json_sha256(&committed)
}

fn exclusion_sha256(artifact: &HistoricalV3SourceCensusExclusion) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.exclusion_sha256.clear();
    json_sha256(&committed)
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v3 source artifact: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
