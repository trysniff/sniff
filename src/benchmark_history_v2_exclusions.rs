use super::{
    HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION, HistoricalV2ExclusionManifest,
    validate_historical_v2_protocol,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Component, Path};

pub(crate) fn seal_historical_v2_exclusion_manifest(
    protocol_bytes: &[u8],
    artifact_root: &Path,
    mut manifest: HistoricalV2ExclusionManifest,
) -> Result<HistoricalV2ExclusionManifest, String> {
    if !manifest.manifest_sha256.is_empty() {
        return Err("historical-v2 exclusion draft is already sealed".to_string());
    }
    manifest.manifest_sha256 = exclusion_manifest_sha256(&manifest)?;
    validate_historical_v2_exclusion_manifest(protocol_bytes, artifact_root, &manifest)?;
    Ok(manifest)
}

pub fn validate_historical_v2_exclusion_manifest(
    protocol_bytes: &[u8],
    artifact_root: &Path,
    manifest: &HistoricalV2ExclusionManifest,
) -> Result<(), String> {
    let protocol = validate_historical_v2_protocol(protocol_bytes)?;
    if manifest.schema_version != HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION
        || manifest.protocol_sha256 != protocol.protocol_sha256
        || manifest.manifest_sha256 != exclusion_manifest_sha256(manifest)?
    {
        return Err("historical-v2 exclusion manifest commitment changed".to_string());
    }
    let partition_names = manifest
        .partitions
        .iter()
        .map(|partition| partition.partition.as_str())
        .collect::<Vec<_>>();
    if partition_names != protocol.protocol.selection.excluded_partitions {
        return Err("historical-v2 exclusion partitions changed or are out of order".to_string());
    }

    let canonical_root = fs::canonicalize(artifact_root)
        .map_err(|error| format!("failed to resolve exclusion artifact root: {error}"))?;
    let mut repositories = BTreeSet::new();
    for partition in &manifest.partitions {
        if partition.artifacts.is_empty()
            || !strictly_sorted(
                partition
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.artifact_path.as_str()),
            )
            || !strictly_sorted(partition.repositories.iter().map(String::as_str))
        {
            return Err(format!(
                "historical-v2 partition {} must have sorted unique artifacts and repositories",
                partition.partition
            ));
        }
        for artifact in &partition.artifacts {
            require_sha256(
                "historical-v2 exclusion artifact",
                &artifact.artifact_sha256,
            )?;
            validate_artifact(
                &canonical_root,
                &artifact.artifact_path,
                &artifact.artifact_sha256,
            )?;
        }
        for repository in &partition.repositories {
            if canonical_repository(repository).as_deref() != Some(repository.as_str()) {
                return Err(format!(
                    "historical-v2 exclusion repository is not canonical: {repository}"
                ));
            }
            repositories.insert(repository.as_str());
        }
    }
    if manifest.repository_count != repositories.len() {
        return Err("historical-v2 exclusion repository count changed".to_string());
    }
    Ok(())
}

fn validate_artifact(root: &Path, relative: &str, expected_sha256: &str) -> Result<(), String> {
    let relative = safe_relative_path(relative)?;
    let path = fs::canonicalize(root.join(relative))
        .map_err(|error| format!("failed to resolve exclusion artifact {relative:?}: {error}"))?;
    if !path.starts_with(root) {
        return Err(format!(
            "historical-v2 exclusion artifact escapes root: {relative:?}"
        ));
    }
    if sha256_file(&path)? != expected_sha256 {
        return Err(format!(
            "historical-v2 exclusion artifact changed: {relative:?}"
        ));
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> Result<&Path, String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe historical-v2 artifact path: {value}"));
    }
    Ok(path)
}

fn canonical_repository(value: &str) -> Option<String> {
    let mut segments = value.split('/');
    let owner = segments.next()?;
    let repository = segments.next()?;
    if segments.next().is_some() || !valid_segment(owner) || !valid_segment(repository) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn strictly_sorted<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|previous| previous >= value) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn exclusion_manifest_sha256(manifest: &HistoricalV2ExclusionManifest) -> Result<String, String> {
    hash_json(&(
        manifest.schema_version,
        &manifest.protocol_sha256,
        &manifest.partitions,
        manifest.repository_count,
    ))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|error| format!("failed to open artifact: {error}"))?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash artifact: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("{label} must be a 64-character SHA-256 digest"))
    }
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 artifact: {error}"))
}
