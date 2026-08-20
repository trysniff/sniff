use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

#[path = "benchmark_history_v2_corpus_case.rs"]
mod case;
use case::*;

#[path = "benchmark_history_v2_corpus_paths.rs"]
mod paths;
use paths::*;

#[path = "benchmark_history_v2_corpus_persistence.rs"]
mod persistence;
pub use persistence::load_historical_v2_corpus_bundle;
use persistence::*;

#[path = "benchmark_history_v2_corpus_review.rs"]
mod review;
use review::*;

#[path = "benchmark_history_v2_corpus_sources.rs"]
mod sources;
use sources::*;

#[path = "benchmark_history_v2_corpus_validation.rs"]
mod validation;

const CORPUS_CONTRACT: &str = "sniffbench-historical-v2-corpus-bundle-v1";
const MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SOURCE_BUNDLE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CORPUS_SOURCE_BYTES: u64 = 1024 * 1024;

pub struct HistoricalV2CorpusBundleInputs<'a> {
    pub gate_inputs: &'a HistoricalV2ReleaseGateInputs<'a>,
    pub release_evidence: &'a HistoricalV2ReleaseEvidence,
    pub corpus_root: &'a Path,
    pub release_evidence_path: &'a Path,
}

pub fn create_historical_v2_corpus_bundle(
    inputs: &HistoricalV2CorpusBundleInputs<'_>,
    output_path: &Path,
) -> Result<HistoricalV2CorpusBundle, String> {
    require_historical_v2_release_gate(inputs.gate_inputs, inputs.release_evidence)?;
    let corpus_root = canonical_plain_directory(inputs.corpus_root, "historical-v2 corpus root")?;
    require_new_file_under_root(&corpus_root, output_path)?;
    let release_evidence_artifact_path = relative_plain_file(
        &corpus_root,
        inputs.release_evidence_path,
        "historical-v2 release evidence artifact",
    )?;
    let evidence_bytes = load_plain_file(
        inputs.release_evidence_path,
        MAX_RELEASE_EVIDENCE_ARTIFACT_BYTES,
        "historical-v2 release evidence artifact",
    )?;
    let persisted = load_historical_v2_release_evidence(
        inputs.gate_inputs.protocol_bytes,
        inputs.release_evidence_path,
    )?;
    if persisted != *inputs.release_evidence {
        return Err("historical-v2 persisted release evidence changed".into());
    }

    let reviews = index_reviewed_slots(inputs.gate_inputs.reviewed_slots)?;
    let protocol = validate_historical_v2_protocol(inputs.gate_inputs.protocol_bytes)?;
    let mut cases = Vec::with_capacity(inputs.release_evidence.accepted_count);
    for slot in &inputs.release_evidence.slots {
        if let HistoricalV2ReleaseSlotOutcome::Accepted { .. } = &slot.outcome {
            let reviewed = reviews
                .get(&(slot.language.as_str(), slot.slot_number))
                .ok_or_else(|| "historical-v2 accepted corpus slot lost its review".to_string())?;
            cases.push(build_historical_v2_corpus_binding(
                &protocol,
                &corpus_root,
                reviewed,
                &slot.outcome,
            )?);
        }
    }
    if cases.len() != inputs.release_evidence.accepted_count {
        return Err("historical-v2 corpus did not include every accepted slot".into());
    }
    let mut bundle = HistoricalV2CorpusBundle {
        schema_version: HISTORICAL_V2_CORPUS_BUNDLE_SCHEMA_VERSION,
        corpus_contract: CORPUS_CONTRACT.to_string(),
        protocol_sha256: inputs.release_evidence.protocol_sha256.clone(),
        selection_sha256: inputs.release_evidence.selection_sha256.clone(),
        release_evidence_artifact_path,
        release_evidence_artifact_sha256: file_sha256(&evidence_bytes),
        release_evidence_sha256: inputs.release_evidence.evidence_sha256.clone(),
        accepted_count: cases.len(),
        cases,
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = corpus_bundle_sha256(&bundle)?;
    validation::validate_historical_v2_corpus_bundle(
        inputs.gate_inputs.protocol_bytes,
        &corpus_root,
        &bundle,
    )?;
    persist_corpus_bundle(output_path, &bundle)?;
    let loaded = load_historical_v2_corpus_bundle(
        inputs.gate_inputs.protocol_bytes,
        &corpus_root,
        output_path,
    )?;
    if loaded != bundle {
        return Err("historical-v2 corpus bundle changed while being published".into());
    }
    Ok(bundle)
}

pub use validation::validate_historical_v2_corpus_bundle;

fn index_reviewed_slots<'a>(
    reviewed: &'a [HistoricalV2ReviewedSlotArtifacts<'a>],
) -> Result<BTreeMap<(&'a str, usize), &'a HistoricalV2ReviewedSlotArtifacts<'a>>, String> {
    let mut indexed = BTreeMap::new();
    for item in reviewed {
        if indexed
            .insert((item.language, item.slot_number), item)
            .is_some()
        {
            return Err("historical-v2 corpus reviews repeat a fixed slot".into());
        }
    }
    Ok(indexed)
}

pub(super) fn corpus_bundle_sha256(bundle: &HistoricalV2CorpusBundle) -> Result<String, String> {
    hash_json(&(
        bundle.schema_version,
        &bundle.corpus_contract,
        &bundle.protocol_sha256,
        &bundle.selection_sha256,
        &bundle.release_evidence_artifact_path,
        &bundle.release_evidence_artifact_sha256,
        &bundle.release_evidence_sha256,
        bundle.accepted_count,
        &bundle.cases,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 corpus bundle: {error}"))
}

#[cfg(test)]
#[path = "benchmark_history_v2_corpus_tests.rs"]
mod tests;
