use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3Materialization, HistoricalV3Protocol,
    HistoricalV3RankIdentity, HistoricalV3SourceCensus, HistoricalV3SourceSide,
    HistoricalV3SourceSnapshot, IntentionalBoundarySemanticMethodStatus,
    historical_v3_rank_identity, validate_historical_v3_materialization_commitment,
    validate_historical_v3_source_census_commitment, validate_intentional_boundary_semantic_census,
};
use super::failure_commitment::{failure_key, validate_failure};
use super::surface::is_surface_symbol;
use super::surface::{collect_surface_symbols, evidence_indexes, semantic_indexer_kind};
use super::{
    HISTORICAL_V3_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V3_SEMANTIC_CENSUS_SCHEMA_VERSION, HistoricalV3SemanticCensus,
    HistoricalV3SemanticCensusExclusion, HistoricalV3SemanticSnapshot,
    HistoricalV3SemanticSnapshotEvidence, HistoricalV3SemanticSurfaceSymbol,
    SEMANTIC_CENSUS_CONTRACT, SEMANTIC_CENSUS_EXCLUSION_CONTRACT,
};
use crate::semantic_indexer_manifest::INDEXER_INSTALL_CONTRACT;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub fn validate_historical_v3_semantic_census_commitment(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    artifact: &HistoricalV3SemanticCensus,
) -> Result<(), String> {
    let expected_rank =
        historical_v3_rank_identity(protocol, collection, artifact.rank.stream_rank)?;
    validate_inputs(
        protocol,
        collection,
        materialization,
        source_census,
        &artifact.rank,
        &artifact.materialization_sha256,
        &artifact.source_census_sha256,
    )?;
    if artifact.schema_version != HISTORICAL_V3_SEMANTIC_CENSUS_SCHEMA_VERSION
        || artifact.semantic_census_contract != SEMANTIC_CENSUS_CONTRACT
        || artifact.indexer_install_contract != INDEXER_INSTALL_CONTRACT
        || artifact.rank != expected_rank
    {
        return Err("historical-v3 semantic census identity changed".to_string());
    }
    validate_snapshot(
        &artifact.base,
        &source_census.base,
        HistoricalV3SourceSide::Base,
    )?;
    validate_snapshot(
        &artifact.merge,
        &source_census.merge,
        HistoricalV3SourceSide::Merge,
    )?;
    if artifact.semantic_census_sha256 != semantic_census_sha256(artifact)? {
        return Err("historical-v3 semantic census commitment changed".to_string());
    }
    Ok(())
}

pub fn validate_historical_v3_semantic_census_exclusion(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    artifact: &HistoricalV3SemanticCensusExclusion,
) -> Result<(), String> {
    let expected_rank =
        historical_v3_rank_identity(protocol, collection, artifact.rank.stream_rank)?;
    validate_inputs(
        protocol,
        collection,
        materialization,
        source_census,
        &artifact.rank,
        &artifact.materialization_sha256,
        &artifact.source_census_sha256,
    )?;
    if artifact.schema_version != HISTORICAL_V3_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION
        || artifact.exclusion_contract != SEMANTIC_CENSUS_EXCLUSION_CONTRACT
        || artifact.indexer_install_contract != INDEXER_INSTALL_CONTRACT
        || artifact.rank != expected_rank
        || artifact.sides.len() != 2
        || evidence_side(&artifact.sides[0]) != HistoricalV3SourceSide::Base
        || evidence_side(&artifact.sides[1]) != HistoricalV3SourceSide::Merge
        || !artifact
            .sides
            .iter()
            .any(|side| matches!(side, HistoricalV3SemanticSnapshotEvidence::Excluded { .. }))
    {
        return Err("historical-v3 semantic exclusion identity changed".to_string());
    }
    validate_side_evidence(
        &artifact.sides[0],
        &source_census.base,
        HistoricalV3SourceSide::Base,
    )?;
    validate_side_evidence(
        &artifact.sides[1],
        &source_census.merge,
        HistoricalV3SourceSide::Merge,
    )?;
    if artifact.exclusion_sha256 != exclusion_sha256(artifact)? {
        return Err("historical-v3 semantic exclusion commitment changed".to_string());
    }
    Ok(())
}

fn validate_inputs(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    rank: &HistoricalV3RankIdentity,
    materialization_sha256: &str,
    source_census_sha256: &str,
) -> Result<(), String> {
    validate_historical_v3_materialization_commitment(protocol, collection, materialization)
        .map_err(|error| error.detail)?;
    validate_historical_v3_source_census_commitment(
        protocol,
        collection,
        materialization,
        source_census,
    )?;
    if rank != &source_census.rank
        || materialization_sha256 != materialization.materialization_sha256
        || source_census_sha256 != source_census.source_census_sha256
    {
        return Err("historical-v3 semantic input binding changed".to_string());
    }
    Ok(())
}

pub(super) fn validate_snapshot(
    snapshot: &HistoricalV3SemanticSnapshot,
    source: &HistoricalV3SourceSnapshot,
    expected_side: HistoricalV3SourceSide,
) -> Result<(), String> {
    if snapshot.side != expected_side
        || snapshot.revision != source.revision
        || snapshot.source_snapshot_sha256 != source.snapshot_sha256
        || snapshot.semantic_census.repository != source.source_census.repository
        || snapshot.semantic_census.revision != source.revision
        || snapshot.surface_symbol_count != snapshot.surface_symbols.len()
        || snapshot.snapshot_sha256 != snapshot_sha256(snapshot)?
    {
        return Err("historical-v3 semantic snapshot identity changed".to_string());
    }
    validate_intentional_boundary_semantic_census(
        &source.source_census,
        &snapshot.semantic_census,
    )?;
    validate_compiler_indexes(source, snapshot)?;
    validate_surface_symbols(source, snapshot)?;
    Ok(())
}

fn validate_compiler_indexes(
    source: &HistoricalV3SourceSnapshot,
    snapshot: &HistoricalV3SemanticSnapshot,
) -> Result<(), String> {
    if snapshot
        .compiler_indexes
        .windows(2)
        .any(|pair| pair[0].indexer >= pair[1].indexer)
        || snapshot.compiler_indexes.iter().any(|evidence| {
            evidence.index.repository_root != "."
                || !evidence.index.provenance.arguments.is_empty()
                || evidence
                    .index
                    .provenance
                    .invocations
                    .iter()
                    .any(|invocation| {
                        !invocation.arguments.is_empty() || !invocation.context.is_empty()
                    })
        })
    {
        return Err("historical-v3 compiler index evidence is noncanonical".to_string());
    }
    let indexes = evidence_indexes(&snapshot.compiler_indexes)?;
    let summaries = indexes
        .iter()
        .map(|(kind, index)| {
            super::super::intentional_boundary_semantic::summarize_index(*kind, index)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if summaries != snapshot.semantic_census.indexers
        || collect_surface_symbols(&indexes)? != snapshot.surface_symbols
    {
        return Err("historical-v3 compiler index projection changed".to_string());
    }
    for method in &snapshot.semantic_census.methods {
        let index = indexes
            .get(&semantic_indexer_kind(method.indexer))
            .ok_or_else(|| "historical-v3 method compiler index is missing".to_string())?;
        super::super::intentional_boundary_semantic::validate_method_projection(method, index)?;
    }
    let mut references = Vec::new();
    for (kind, index) in &indexes {
        references.extend(
            super::super::intentional_boundary_semantic::flatten_source_references(
                super::super::intentional_boundary_semantic::indexer_kind(*kind),
                &source.source_census,
                index,
            )?,
        );
    }
    let references =
        super::super::intentional_boundary_semantic::canonical_source_references(references)?;
    if references != snapshot.semantic_census.source_references {
        return Err("historical-v3 source-reference compiler projection changed".to_string());
    }
    Ok(())
}

fn validate_surface_symbols(
    source: &HistoricalV3SourceSnapshot,
    snapshot: &HistoricalV3SemanticSnapshot,
) -> Result<(), String> {
    let source_paths = source
        .source_census
        .source_files
        .iter()
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let indexers = snapshot
        .semantic_census
        .indexers
        .iter()
        .map(|indexer| indexer.indexer)
        .collect::<BTreeSet<_>>();
    let mut previous = None;
    let mut identities = BTreeSet::new();
    for symbol in &snapshot.surface_symbols {
        let key = (symbol.indexer, symbol.symbol.symbol_id.as_str());
        if previous.is_some_and(|prior| prior >= key)
            || !identities.insert((symbol.indexer, symbol.symbol.symbol_id.as_str()))
            || !indexers.contains(&symbol.indexer)
            || !valid_surface_symbol(symbol, &source_paths)
        {
            return Err("historical-v3 semantic surface is incomplete or noncanonical".to_string());
        }
        previous = Some(key);
    }
    for method in &snapshot.semantic_census.methods {
        let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } = &method.status
        else {
            continue;
        };
        if (symbol.visibility == super::super::IntentionalBoundarySemanticVisibility::Public
            || !symbol.surfaces.is_empty())
            && !snapshot.surface_symbols.iter().any(|surface| {
                surface.indexer == method.indexer && &surface.symbol == symbol.as_ref()
            })
        {
            return Err("historical-v3 semantic surface omitted a method symbol".to_string());
        }
    }
    Ok(())
}

fn valid_surface_symbol(
    symbol: &HistoricalV3SemanticSurfaceSymbol,
    source_paths: &BTreeSet<&str>,
) -> bool {
    is_surface_symbol(symbol)
        && !symbol.symbol.symbol_id.trim().is_empty()
        && !symbol.symbol.provider_identity.trim().is_empty()
        && !symbol.symbol.provider_kind.trim().is_empty()
        && !symbol.symbol.definitions.is_empty()
        && symbol
            .symbol
            .definitions
            .iter()
            .all(|location| source_paths.contains(location.repository_path.as_str()))
}

fn validate_side_evidence(
    evidence: &HistoricalV3SemanticSnapshotEvidence,
    source: &HistoricalV3SourceSnapshot,
    expected_side: HistoricalV3SourceSide,
) -> Result<(), String> {
    match evidence {
        HistoricalV3SemanticSnapshotEvidence::Completed { snapshot } => {
            validate_snapshot(snapshot, source, expected_side)
        }
        HistoricalV3SemanticSnapshotEvidence::Excluded {
            side,
            revision,
            source_snapshot_sha256,
            failures,
        } => {
            if *side != expected_side
                || revision != &source.revision
                || source_snapshot_sha256 != &source.snapshot_sha256
                || failures.is_empty()
                || failures
                    .windows(2)
                    .any(|pair| failure_key(&pair[0]) >= failure_key(&pair[1]))
            {
                return Err("historical-v3 semantic failure evidence changed".to_string());
            }
            let expected_indexers = source
                .source_census
                .source_files
                .iter()
                .map(|file| {
                    super::super::intentional_boundary_semantic::indexer_for_language(
                        &file.language,
                    )
                    .map(super::super::intentional_boundary_semantic::indexer_kind)
                })
                .collect::<Result<BTreeSet<_>, String>>()?;
            for failure in failures {
                validate_failure(failure, &expected_indexers)?;
            }
            Ok(())
        }
    }
}

fn evidence_side(evidence: &HistoricalV3SemanticSnapshotEvidence) -> HistoricalV3SourceSide {
    match evidence {
        HistoricalV3SemanticSnapshotEvidence::Completed { snapshot } => snapshot.side,
        HistoricalV3SemanticSnapshotEvidence::Excluded { side, .. } => *side,
    }
}

pub(super) fn seal_snapshot(
    mut snapshot: HistoricalV3SemanticSnapshot,
) -> Result<HistoricalV3SemanticSnapshot, String> {
    snapshot.snapshot_sha256.clear();
    snapshot.snapshot_sha256 = snapshot_sha256(&snapshot)?;
    Ok(snapshot)
}

pub(super) fn seal_semantic_census(
    mut artifact: HistoricalV3SemanticCensus,
) -> Result<HistoricalV3SemanticCensus, String> {
    artifact.semantic_census_sha256.clear();
    artifact.semantic_census_sha256 = semantic_census_sha256(&artifact)?;
    Ok(artifact)
}

pub(super) fn seal_semantic_exclusion(
    mut artifact: HistoricalV3SemanticCensusExclusion,
) -> Result<HistoricalV3SemanticCensusExclusion, String> {
    artifact.exclusion_sha256.clear();
    artifact.exclusion_sha256 = exclusion_sha256(&artifact)?;
    Ok(artifact)
}

fn snapshot_sha256(snapshot: &HistoricalV3SemanticSnapshot) -> Result<String, String> {
    let mut committed = snapshot.clone();
    committed.snapshot_sha256.clear();
    json_sha256(&committed)
}

fn semantic_census_sha256(artifact: &HistoricalV3SemanticCensus) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.semantic_census_sha256.clear();
    json_sha256(&committed)
}

fn exclusion_sha256(artifact: &HistoricalV3SemanticCensusExclusion) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.exclusion_sha256.clear();
    json_sha256(&committed)
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v3 semantic artifact: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
