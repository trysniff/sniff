#[cfg(any(feature = "sniffbench-frame", test))]
use super::HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC;
#[cfg(any(feature = "sniffbench-frame", test))]
use super::history_v3_time::parse_utc_second;
use super::{
    HistoricalV2ExclusionManifest, HistoricalV2Frame, HistoricalV2SlotOutcome,
    HistoricalV2SlotSelection, HistoricalV3PriorArtifactBinding,
    HistoricalV3PriorBenchmarkIdentitySeal, derive_historical_v2_exclusion_manifest,
    prepare_historical_v3_prior_identity_seal, select_historical_v2_slots,
};
#[cfg(feature = "sniffbench-frame")]
use crate::benchmark::validate_historical_v2_frame_sources;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(feature = "sniffbench-frame", test))]
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

const PROTOCOL_FILE_SHA256: &str =
    "deb98a285867fc5ea52761c252839d74268f239824bfc1a82027a352695cfc6f";

// Frozen main run 32804623556, public Actions artifact 9547888605.
const FRAME_FILE_SHA256: &str = "de8dca6b0248229171a3e82f61b3e59e324ebca47c902e315628d4335120719f";
const EXCLUSIONS_FILE_SHA256: &str =
    "74bccb100eb48ab87952bd7eec137b2285edbc68d2547715bc0e06a80e029f76";
const SELECTION_FILE_SHA256: &str =
    "e6f06b0b887168205dcaa1d903ffcf54efe6199ea730ee118b28ad8e24925853";
#[cfg(any(feature = "sniffbench-frame", test))]
const HISTORICAL_V2_TEMPORAL_CONTRACT: &str = "sniffbench-historical-v3-prior-v2-temporal-v1";
pub const HISTORICAL_V3_PRIOR_V2_TEMPORAL_PROOF_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3PriorV2PrWitness {
    pub canonical_repository: String,
    pub global_row_index: usize,
    pub pull_number: u64,
    pub created_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3PriorV2TemporalProof {
    pub schema_version: u32,
    pub contract: String,
    pub prior_seal_sha256: String,
    pub frame_file_sha256: String,
    pub selection_file_sha256: String,
    pub cutoff_utc: String,
    pub witnesses: Vec<HistoricalV3PriorV2PrWitness>,
    pub latest_witness_utc: String,
    pub proof_sha256: String,
}

/// Replays the pinned Parquet shards before treating selected PR dates as witnesses.
#[cfg(feature = "sniffbench-frame")]
pub fn derive_frozen_historical_v3_prior_v2_temporal_proof(
    artifact_root: &Path,
    dataset_root: &Path,
    frame_path: &Path,
    exclusions_path: &Path,
    selection_path: &Path,
) -> Result<HistoricalV3PriorV2TemporalProof, String> {
    let protocol = read_pinned_file(
        &artifact_root.join("sniffbench/historical-v2-protocol.json"),
        64 * 1024,
        PROTOCOL_FILE_SHA256,
        "protocol",
    )?;
    let frame_bytes = read_pinned_file(frame_path, 128 * 1024 * 1024, FRAME_FILE_SHA256, "frame")?;
    let exclusion_bytes = read_pinned_file(
        exclusions_path,
        1024 * 1024,
        EXCLUSIONS_FILE_SHA256,
        "exclusions",
    )?;
    let selection_bytes = read_pinned_file(
        selection_path,
        16 * 1024 * 1024,
        SELECTION_FILE_SHA256,
        "selection",
    )?;
    let seal = derive_prior_seal(
        artifact_root,
        &protocol,
        &frame_bytes,
        &exclusion_bytes,
        &selection_bytes,
    )?;
    let frame: HistoricalV2Frame = serde_json::from_slice(&frame_bytes)
        .map_err(|error| format!("invalid frozen historical-v2 frame: {error}"))?;
    validate_historical_v2_frame_sources(&protocol, dataset_root, &frame)?;
    let selection: HistoricalV2SlotSelection = serde_json::from_slice(&selection_bytes)
        .map_err(|error| format!("invalid frozen historical-v2 selection: {error}"))?;
    derive_prior_v2_temporal_proof(&seal, &frame, &selection, &frame_bytes, &selection_bytes)
}

#[cfg(feature = "sniffbench-frame")]
pub fn validate_frozen_historical_v3_prior_v2_temporal_proof(
    artifact_root: &Path,
    dataset_root: &Path,
    frame_path: &Path,
    exclusions_path: &Path,
    selection_path: &Path,
    proof: &HistoricalV3PriorV2TemporalProof,
) -> Result<(), String> {
    let expected = derive_frozen_historical_v3_prior_v2_temporal_proof(
        artifact_root,
        dataset_root,
        frame_path,
        exclusions_path,
        selection_path,
    )?;
    if *proof != expected {
        return Err("historical-v2 temporal proof does not replay".to_string());
    }
    Ok(())
}

#[cfg(any(feature = "sniffbench-frame", test))]
fn derive_prior_v2_temporal_proof(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
    frame: &HistoricalV2Frame,
    selection: &HistoricalV2SlotSelection,
    frame_bytes: &[u8],
    selection_bytes: &[u8],
) -> Result<HistoricalV3PriorV2TemporalProof, String> {
    let cutoff = parse_utc_second(HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC)?;
    let expected = seal
        .inputs
        .iter()
        .find(|input| input.artifact_id == "historical-v2")
        .ok_or("historical-v2 prior partition is missing")?;
    if expected.artifact_sha256 != sha256(selection_bytes)
        || selection.frame_sha256 != frame.frame_sha256
        || expected.repositories.is_empty()
    {
        return Err("historical-v2 temporal source commitment changed".to_string());
    }
    let mut witnessed = BTreeMap::new();
    let mut latest = None;
    for slot in &selection.slots {
        let HistoricalV2SlotOutcome::Selected {
            global_row_index,
            canonical_repository,
            pull_number,
            ..
        } = &slot.outcome
        else {
            continue;
        };
        let row = frame
            .records
            .get(*global_row_index)
            .ok_or("historical-v2 temporal slot row is missing")?;
        if row.canonical_repository.as_deref() != Some(canonical_repository)
            || row.pull_number != Some(*pull_number)
        {
            return Err("historical-v2 temporal slot does not match its PR row".to_string());
        }
        let timestamp = if row.created_at.len() == 19
            && row.created_at.is_ascii()
            && row.created_at.as_bytes()[10] == b' '
        {
            format!("{}T{}Z", &row.created_at[..10], &row.created_at[11..])
        } else {
            row.created_at.clone()
        };
        let observed = parse_utc_second(&timestamp)?;
        if observed >= cutoff {
            return Err(format!(
                "historical-v2 prior PR is not before the v3 cutoff: {canonical_repository}"
            ));
        }
        if witnessed
            .insert(
                canonical_repository.clone(),
                HistoricalV3PriorV2PrWitness {
                    canonical_repository: canonical_repository.clone(),
                    global_row_index: *global_row_index,
                    pull_number: *pull_number,
                    created_at_utc: timestamp.clone(),
                },
            )
            .is_some()
        {
            return Err("historical-v2 temporal repository has repeated selected rows".to_string());
        }
        if latest.as_ref().is_none_or(|(time, _)| observed > *time) {
            latest = Some((observed, timestamp));
        }
    }
    if witnessed.keys().map(String::as_str).collect::<Vec<_>>()
        != expected
            .repositories
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err(
            "historical-v2 temporal witnesses do not cover every sealed repository".to_string(),
        );
    }
    let mut proof = HistoricalV3PriorV2TemporalProof {
        schema_version: HISTORICAL_V3_PRIOR_V2_TEMPORAL_PROOF_SCHEMA_VERSION,
        contract: HISTORICAL_V2_TEMPORAL_CONTRACT.to_string(),
        prior_seal_sha256: seal.seal_sha256.clone(),
        frame_file_sha256: sha256(frame_bytes),
        selection_file_sha256: sha256(selection_bytes),
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        witnesses: witnessed.into_values().collect(),
        latest_witness_utc: latest
            .ok_or("historical-v2 temporal witnesses are empty")?
            .1,
        proof_sha256: String::new(),
    };
    proof.proof_sha256 = sha256(
        &serde_json::to_vec(&proof)
            .map_err(|error| format!("failed to commit historical-v2 temporal proof: {error}"))?,
    );
    Ok(proof)
}

pub fn derive_frozen_historical_v3_prior_identity_seal(
    artifact_root: &Path,
    frame_path: &Path,
    exclusions_path: &Path,
    selection_path: &Path,
) -> Result<HistoricalV3PriorBenchmarkIdentitySeal, String> {
    let protocol = read_pinned_file(
        &artifact_root.join("sniffbench/historical-v2-protocol.json"),
        64 * 1024,
        PROTOCOL_FILE_SHA256,
        "protocol",
    )?;
    let frame = read_pinned_file(frame_path, 128 * 1024 * 1024, FRAME_FILE_SHA256, "frame")?;
    let exclusions = read_pinned_file(
        exclusions_path,
        1024 * 1024,
        EXCLUSIONS_FILE_SHA256,
        "exclusions",
    )?;
    let selection = read_pinned_file(
        selection_path,
        16 * 1024 * 1024,
        SELECTION_FILE_SHA256,
        "selection",
    )?;
    derive_prior_seal(artifact_root, &protocol, &frame, &exclusions, &selection)
}

fn derive_prior_seal(
    artifact_root: &Path,
    protocol: &[u8],
    frame_bytes: &[u8],
    exclusion_bytes: &[u8],
    selection_bytes: &[u8],
) -> Result<HistoricalV3PriorBenchmarkIdentitySeal, String> {
    let frame: HistoricalV2Frame = serde_json::from_slice(frame_bytes)
        .map_err(|error| format!("invalid frozen historical-v2 frame: {error}"))?;
    let exclusions: HistoricalV2ExclusionManifest = serde_json::from_slice(exclusion_bytes)
        .map_err(|error| format!("invalid frozen historical-v2 exclusions: {error}"))?;
    let selection: HistoricalV2SlotSelection = serde_json::from_slice(selection_bytes)
        .map_err(|error| format!("invalid frozen historical-v2 selection: {error}"))?;

    let derived_exclusions = derive_historical_v2_exclusion_manifest(protocol, artifact_root)?;
    if exclusions != derived_exclusions {
        return Err(
            "historical-v2 prior exclusions differ from their original sources".to_string(),
        );
    }
    let derived_selection =
        select_historical_v2_slots(protocol, artifact_root, &frame, &exclusions)?;
    if selection != derived_selection {
        return Err("historical-v2 prior selection differs from the fixed slots".to_string());
    }

    let exclusion_sha256 = sha256(exclusion_bytes);
    let mut inputs = exclusions
        .partitions
        .iter()
        .filter(|partition| !partition.repositories.is_empty())
        .map(|partition| HistoricalV3PriorArtifactBinding {
            artifact_id: partition.partition.clone(),
            artifact_sha256: exclusion_sha256.clone(),
            repositories: partition.repositories.clone(),
        })
        .collect::<Vec<_>>();
    inputs.push(HistoricalV3PriorArtifactBinding {
        artifact_id: "historical-v2".to_string(),
        artifact_sha256: sha256(selection_bytes),
        repositories: selection
            .slots
            .iter()
            .filter_map(|slot| match &slot.outcome {
                HistoricalV2SlotOutcome::Selected {
                    canonical_repository,
                    ..
                } => Some(canonical_repository.clone()),
                HistoricalV2SlotOutcome::Unfilled => None,
            })
            .collect(),
    });
    prepare_historical_v3_prior_identity_seal(inputs)
}

fn read_pinned_file(
    path: &Path,
    limit: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err(format!("historical-v2 {label} path must be absolute"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect historical-v2 {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!("historical-v2 {label} is not a plain bounded file"));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("failed to open historical-v2 {label}: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("failed to inspect opened historical-v2 {label}: {error}"))?;
    if !opened.is_file() || opened.file_type().is_symlink() || opened.len() > limit {
        return Err(format!("historical-v2 {label} is not a plain bounded file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("historical-v2 {label} is not a plain bounded file"));
        }
    }
    read_pinned_bytes(file, limit, expected_sha256, label)
}

fn read_pinned_bytes(
    reader: impl Read,
    limit: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| format!("historical-v2 {label} read limit is invalid"))?;
    let mut bytes = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read historical-v2 {label}: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("historical-v2 {label} exceeds its read limit"));
    }
    if sha256(&bytes) != expected_sha256 {
        return Err(format!(
            "historical-v2 {label} changed from the frozen frame run"
        ));
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v3_prior_artifacts_tests.rs"]
mod tests;
