use super::history_v2_slot_store_support::{require_plain_directory, write_compact_json_new};
use super::source_seal::artifact_io::read_plain_file;
use super::{
    BlindPriorTemporalProof, HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC,
    HistoricalV3PriorBenchmarkIdentitySeal, HistoricalV3PriorTemporalCoverage,
    HistoricalV3PriorTemporalObligation, HistoricalV3PriorTemporalObligationStatus,
    HistoricalV3PriorTemporalWitness, HistoricalV3PriorV2TemporalProof, SmallPriorTemporalProof,
    derive_blind_prior_temporal_proof, derive_frozen_historical_v3_prior_identity_seal,
    derive_frozen_historical_v3_prior_v2_temporal_proof, derive_small_prior_temporal_proof,
    validate_historical_v3_prior_identity_seal,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CONTRACT: &str = "sniffbench-historical-v3-prior-temporal-coverage-v1";
const MAX_COVERAGE_BYTES: u64 = 16 * 1024 * 1024;
const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const EXCLUSIONS: &[u8] = include_bytes!("../sniffbench/historical-v2-prior-exclusions.json");
const BLIND_RESPONSE: &[u8] =
    include_bytes!("../sniffbench/historical-v3-blind-prior-identities-response.json");
const SMALL_RESPONSE: &[u8] =
    include_bytes!("../sniffbench/historical-v3-small-prior-identities-response.json");

pub struct HistoricalV3PriorTemporalCoverageInputs<'a> {
    pub artifact_root: &'a Path,
    pub dataset_root: &'a Path,
    pub frame: &'a Path,
    pub exclusions: &'a Path,
    pub selection: &'a Path,
    pub blind_source_seal: &'a Path,
    pub source_repository: &'a Path,
}

/// Replays each available original source; missing historical-v1 proof is explicit.
/// No saved-name observation or caller-supplied proof can issue covered rows.
pub fn derive_frozen_historical_v3_prior_temporal_coverage(
    inputs: &HistoricalV3PriorTemporalCoverageInputs<'_>,
) -> Result<HistoricalV3PriorTemporalCoverage, String> {
    let blind = derive_blind_prior_temporal_proof(inputs.blind_source_seal, BLIND_RESPONSE)?;
    let small = derive_small_prior_temporal_proof(
        POLICY,
        EXCLUSIONS,
        SMALL_RESPONSE,
        inputs.source_repository,
    )?;
    let seal = derive_frozen_historical_v3_prior_identity_seal(
        inputs.artifact_root,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
    )?;
    let v2 = derive_frozen_historical_v3_prior_v2_temporal_proof(
        inputs.artifact_root,
        inputs.dataset_root,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
    )?;
    assemble_coverage(&seal, &v2, &blind, &small)
}

pub fn validate_frozen_historical_v3_prior_temporal_coverage(
    inputs: &HistoricalV3PriorTemporalCoverageInputs<'_>,
    coverage: &HistoricalV3PriorTemporalCoverage,
) -> Result<(), String> {
    let expected = derive_frozen_historical_v3_prior_temporal_coverage(inputs)?;
    require_coverage_match(coverage, &expected)
}

fn require_coverage_match(
    coverage: &HistoricalV3PriorTemporalCoverage,
    expected: &HistoricalV3PriorTemporalCoverage,
) -> Result<(), String> {
    if coverage != expected {
        return Err(
            "prior temporal coverage does not replay from its original sources".to_string(),
        );
    }
    Ok(())
}

pub fn read_historical_v3_prior_temporal_coverage(
    path: &Path,
) -> Result<HistoricalV3PriorTemporalCoverage, String> {
    let bytes = read_plain_file(path, MAX_COVERAGE_BYTES, "prior temporal coverage")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid prior temporal coverage: {error}"))
}

pub fn write_historical_v3_prior_temporal_coverage_new(
    path: &Path,
    coverage: &HistoricalV3PriorTemporalCoverage,
) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or("prior temporal coverage output requires an explicit parent directory")?;
    require_plain_directory(parent, "prior temporal coverage output parent")?;
    write_compact_json_new(path, coverage, MAX_COVERAGE_BYTES)
}

fn assemble_coverage(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
    v2: &HistoricalV3PriorV2TemporalProof,
    blind: &BlindPriorTemporalProof,
    small: &SmallPriorTemporalProof,
) -> Result<HistoricalV3PriorTemporalCoverage, String> {
    validate_historical_v3_prior_identity_seal(seal)?;
    if v2.prior_seal_sha256 != seal.seal_sha256
        || [&v2.cutoff_utc, &blind.cutoff_utc, &small.cutoff_utc]
            .iter()
            .any(|cutoff| cutoff.as_str() != HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC)
    {
        return Err("prior temporal coverage source seal or cutoff changed".to_string());
    }
    let mut evidence = BTreeMap::new();
    for witness in &v2.witnesses {
        insert_witness(
            &mut evidence,
            "historical-v2",
            &witness.canonical_repository,
            &v2.proof_sha256,
            HistoricalV3PriorTemporalWitness::SelectedPr(witness.clone()),
        )?;
    }
    for witness in &blind.witnesses {
        insert_witness(
            &mut evidence,
            "blind-oss-v1",
            &witness.canonical_repository,
            &blind.proof_sha256,
            HistoricalV3PriorTemporalWitness::BlindRepository(witness.clone()),
        )?;
    }
    for witness in &small.witnesses {
        if !matches!(
            witness.source_partition.as_str(),
            "slopcodebench" | "synthetic-gold-v1"
        ) {
            return Err("small prior witness has an unexpected source partition".to_string());
        }
        insert_witness(
            &mut evidence,
            &witness.source_partition,
            &witness.repository,
            &small.proof_sha256,
            HistoricalV3PriorTemporalWitness::ResearchOrSyntheticRepository(witness.clone()),
        )?;
    }
    let mut obligations = Vec::new();
    let mut unresolved_names = BTreeSet::new();
    let mut source_replayed_obligation_count = 0;
    for partition in &seal.inputs {
        for (seal_entry_index, name) in partition.repositories.iter().enumerate() {
            let status = match partition.artifact_id.as_str() {
                "historical-v1" | "intentional-boundary-v1" => {
                    unresolved_names.insert(name.clone());
                    HistoricalV3PriorTemporalObligationStatus::UnresolvedOriginalEntity
                }
                "historical-v2" | "blind-oss-v1" | "slopcodebench" | "synthetic-gold-v1" => {
                    let status = evidence
                        .remove(&(partition.artifact_id.clone(), name.clone()))
                        .ok_or("prior temporal coverage is missing a source-replayed witness")?;
                    source_replayed_obligation_count += 1;
                    status
                }
                _ => {
                    return Err(
                        "prior temporal coverage has an unsupported source partition".to_string(),
                    );
                }
            };
            obligations.push(HistoricalV3PriorTemporalObligation {
                partition: partition.artifact_id.clone(),
                source_artifact_sha256: partition.artifact_sha256.clone(),
                seal_entry_index,
                prior_name: name.clone(),
                evidence: status,
            });
        }
    }
    if !evidence.is_empty() {
        return Err("prior temporal coverage contains an unsealed source witness".to_string());
    }
    // A witness in one partition cannot close another partition's unresolved entity.
    let mut coverage = HistoricalV3PriorTemporalCoverage {
        schema_version: 1,
        contract: CONTRACT.to_string(),
        prior_seal_sha256: seal.seal_sha256.clone(),
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        unresolved_obligation_count: obligations.len() - source_replayed_obligation_count,
        source_replayed_obligation_count,
        fully_witnessed_repository_count: seal.repositories.len() - unresolved_names.len(),
        unresolved_repository_count: unresolved_names.len(),
        obligations,
        publication_qualified: false,
        coverage_sha256: String::new(),
    };
    coverage.coverage_sha256 =
        sha256(&serde_json::to_vec(&coverage).map_err(|error| error.to_string())?);
    Ok(coverage)
}

fn insert_witness(
    evidence: &mut BTreeMap<(String, String), HistoricalV3PriorTemporalObligationStatus>,
    partition: &str,
    name: &str,
    proof_sha256: &str,
    witness: HistoricalV3PriorTemporalWitness,
) -> Result<(), String> {
    if evidence
        .insert(
            (partition.to_string(), name.to_string()),
            HistoricalV3PriorTemporalObligationStatus::SourceReplayed {
                source_proof_sha256: proof_sha256.to_string(),
                witness,
            },
        )
        .is_some()
    {
        return Err("prior temporal coverage repeats a source witness".to_string());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v3_temporal_coverage_tests.rs"]
mod tests;
