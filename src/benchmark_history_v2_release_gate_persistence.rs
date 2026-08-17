use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const MAX_RELEASE_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;

pub fn validate_historical_v2_release_evidence_commitment(
    protocol_bytes: &[u8],
    evidence: &HistoricalV2ReleaseEvidence,
) -> Result<(), String> {
    let protocol = validate_historical_v2_protocol(protocol_bytes)?;
    super::validate_release_protocol(&protocol)?;
    super::validate_historical_v2_release_evidence_structure(&protocol, evidence)
}

pub fn write_historical_v2_release_evidence(
    inputs: &HistoricalV2ReleaseGateInputs<'_>,
    evidence: &HistoricalV2ReleaseEvidence,
    output_path: &Path,
) -> Result<(), String> {
    validate_historical_v2_release_evidence(inputs, evidence)?;
    validate_historical_v2_release_evidence_commitment(inputs.protocol_bytes, evidence)?;
    let mut bytes = serde_json::to_vec_pretty(evidence)
        .map_err(|error| format!("failed to serialize historical-v2 release evidence: {error}"))?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RELEASE_EVIDENCE_BYTES {
        return Err("historical-v2 release evidence exceeds its size limit".into());
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output_path)
        .map_err(|error| format!("failed to create historical-v2 release evidence: {error}"))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist historical-v2 release evidence: {error}"))
}

pub fn load_historical_v2_release_evidence(
    protocol_bytes: &[u8],
    path: &Path,
) -> Result<HistoricalV2ReleaseEvidence, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect historical-v2 release evidence: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_RELEASE_EVIDENCE_BYTES
    {
        return Err("historical-v2 release evidence is unsafe or exceeds its size limit".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(path)
        .and_then(|file| {
            file.take(MAX_RELEASE_EVIDENCE_BYTES + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|error| format!("failed to read historical-v2 release evidence: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RELEASE_EVIDENCE_BYTES {
        return Err("historical-v2 release evidence exceeds its size limit".into());
    }
    let evidence = serde_json::from_slice::<HistoricalV2ReleaseEvidence>(&bytes)
        .map_err(|error| format!("invalid historical-v2 release evidence: {error}"))?;
    validate_historical_v2_release_evidence_commitment(protocol_bytes, &evidence)?;
    Ok(evidence)
}

#[cfg(test)]
#[path = "benchmark_history_v2_release_gate_persistence_tests.rs"]
mod tests;
