use super::{
    HistoricalV2ExclusionManifest, HistoricalV2Frame, HistoricalV2SlotOutcome,
    HistoricalV2SlotSelection, HistoricalV3PriorArtifactBinding,
    HistoricalV3PriorBenchmarkIdentitySeal, derive_historical_v2_exclusion_manifest,
    prepare_historical_v3_prior_identity_seal, select_historical_v2_slots,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
const PROTOCOL_FILE_SHA256: &str =
    "deb98a285867fc5ea52761c252839d74268f239824bfc1a82027a352695cfc6f";

// Frozen main run 32804623556, public Actions artifact 9547888605.
const FRAME_FILE_SHA256: &str = "de8dca6b0248229171a3e82f61b3e59e324ebca47c902e315628d4335120719f";
const EXCLUSIONS_FILE_SHA256: &str =
    "74bccb100eb48ab87952bd7eec137b2285edbc68d2547715bc0e06a80e029f76";
const SELECTION_FILE_SHA256: &str =
    "e6f06b0b887168205dcaa1d903ffcf54efe6199ea730ee118b28ad8e24925853";

pub fn derive_frozen_historical_v3_prior_identity_seal(
    artifact_root: &Path,
    frame_path: &Path,
    exclusions_path: &Path,
    selection_path: &Path,
) -> Result<HistoricalV3PriorBenchmarkIdentitySeal, String> {
    if sha256(PROTOCOL) != PROTOCOL_FILE_SHA256 {
        return Err("frozen historical-v2 protocol bytes changed".to_string());
    }
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
    derive_prior_seal(artifact_root, PROTOCOL, &frame, &exclusions, &selection)
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
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read historical-v2 {label}: {error}"))?;
    if bytes.len() as u64 > limit || sha256(&bytes) != expected_sha256 {
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
