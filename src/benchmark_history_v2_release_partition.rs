use super::*;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;

const MAX_HISTORICAL_V2_PROTOCOL_BYTES: u64 = 1024 * 1024;
const MAX_HISTORICAL_V2_CORPUS_BYTES: u64 = 128 * 1024 * 1024;

pub(super) fn validate_historical_v2_release_partition(
    corpus: &BenchmarkCorpus,
    corpus_root: &Path,
) -> Result<(), String> {
    let root = fs::canonicalize(corpus_root).map_err(|error| {
        format!(
            "failed to resolve benchmark corpus root {}: {error}",
            corpus_root.display()
        )
    })?;
    let (_, protocol_bytes) = read_plain_bounded(
        &root,
        &corpus.historical_v2.protocol_artifact_path,
        MAX_HISTORICAL_V2_PROTOCOL_BYTES,
        "historical-v2 protocol artifact",
    )?;
    validate_artifact_hash(
        &protocol_bytes,
        &corpus.historical_v2.protocol_artifact_sha256,
        "historical-v2 protocol artifact",
    )?;
    let (bundle_path, bundle_bytes) = read_plain_bounded(
        &root,
        &corpus.historical_v2.corpus_bundle_artifact_path,
        MAX_HISTORICAL_V2_CORPUS_BYTES,
        "historical-v2 corpus bundle artifact",
    )?;
    validate_artifact_hash(
        &bundle_bytes,
        &corpus.historical_v2.corpus_bundle_artifact_sha256,
        "historical-v2 corpus bundle artifact",
    )?;
    let bundle = load_historical_v2_corpus_bundle(&protocol_bytes, &root, &bundle_path)?;
    let expected = historical_v2_release_cases(&bundle);
    let actual = corpus
        .cases
        .iter()
        .filter(|case| case.partition == BenchmarkPartition::HistoricalSimplificationV2)
        .cloned()
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(
            "historical-v2 release cases differ from the accepted corpus bundle".to_string(),
        );
    }
    let analysis_sources = corpus.analysis_sources.iter().collect::<HashSet<_>>();
    if expected
        .iter()
        .flat_map(|case| &case.before)
        .any(|source| !analysis_sources.contains(source))
    {
        return Err("historical-v2 release source is absent from analysis_sources".into());
    }
    Ok(())
}

pub(super) fn historical_v2_release_cases(
    bundle: &HistoricalV2CorpusBundle,
) -> Vec<ReleaseBenchmarkCase> {
    bundle
        .cases
        .iter()
        .map(|binding| ReleaseBenchmarkCase {
            label: binding.case.label.clone(),
            partition: BenchmarkPartition::HistoricalSimplificationV2,
            before: binding.case.before.clone(),
            after: binding.case.after.clone(),
            human_explanation: binding.case.human_explanation.clone(),
            behavioral_evidence: binding.case.behavioral_evidence.clone(),
            scope: binding.case.scope,
            expected_proof_level: binding.case.expected_proof_level,
            provenance_id: Some(binding.case.provenance_id.clone()),
            covered_method_ids: Vec::new(),
            adjudications: binding.case.adjudications.clone(),
            disputed: binding.case.disputed,
            dispute_resolution: binding.case.dispute_resolution.clone(),
        })
        .collect()
}

fn read_plain_bounded(
    root: &Path,
    artifact_path: &str,
    maximum: u64,
    label: &str,
) -> Result<(PathBuf, Vec<u8>), String> {
    let path = root.join(artifact_path);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(format!("{label} is unsafe or exceeds its size limit"));
    }
    let resolved =
        fs::canonicalize(&path).map_err(|error| format!("failed to resolve {label}: {error}"))?;
    if !resolved.starts_with(root) {
        return Err(format!("{label} escapes the benchmark corpus root"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(&resolved)
        .and_then(|file| file.take(maximum + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("failed to read {label}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(format!("{label} exceeds its size limit"));
    }
    Ok((resolved, bytes))
}

fn validate_artifact_hash(bytes: &[u8], expected: &str, label: &str) -> Result<(), String> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(format!(
            "{label} hash mismatch; expected {expected}, got {actual}"
        ))
    }
}
