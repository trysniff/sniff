use super::super::history_v2_slot_store_support::{
    read_limited, require_plain_directory, sync_directory, write_compact_json_new,
};
use super::{
    HistoricalV3CandidateCollection, HistoricalV3CandidateCollectionManifest,
    HistoricalV3CandidatePartitionRecord, HistoricalV3PriorBenchmarkIdentitySeal,
    HistoricalV3Protocol, HistoricalV3SourceBindingAudit, HistoricalV3SourceFrameArtifact,
    decode_page, read_committed_page_checkpoint, validate_historical_v3_candidate_collection,
};
use std::ffi::OsString;
use std::fs;
use std::path::Path;

const MAX_COLLECTION_MANIFEST_BYTES: u64 = 512 * 1024 * 1024;

pub fn write_historical_v3_candidate_collection_manifest_new(
    path: &Path,
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    source_artifacts: &[HistoricalV3SourceFrameArtifact<'_>],
    source_binding_audit: &HistoricalV3SourceBindingAudit,
    state_root: &Path,
    collection: &HistoricalV3CandidateCollection,
) -> Result<(), String> {
    validate_historical_v3_candidate_collection(
        protocol,
        prior_identities,
        source_artifacts,
        source_binding_audit,
        state_root,
        collection,
    )?;
    let parent = path
        .parent()
        .ok_or_else(|| "historical-v3 candidate manifest path has no parent".to_string())?;
    require_plain_directory(parent, "historical-v3 candidate manifest parent")?;
    if path.exists() {
        return Err("historical-v3 candidate manifest already exists".to_string());
    }
    let name = path
        .file_name()
        .ok_or_else(|| "historical-v3 candidate manifest path has no file name".to_string())?;
    let mut pending_name = OsString::from(".");
    pending_name.push(name);
    pending_name.push(format!(".{}.pending", collection.manifest.manifest_sha256));
    let pending = parent.join(pending_name);
    if pending.exists() {
        let metadata = fs::symlink_metadata(&pending).map_err(|error| {
            format!("failed to inspect historical-v3 pending manifest: {error}")
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("historical-v3 pending manifest is not a plain file".to_string());
        }
        match read_limited(
            &pending,
            MAX_COLLECTION_MANIFEST_BYTES,
            "historical-v3 pending candidate manifest",
        )
        .and_then(|bytes| {
            serde_json::from_slice::<HistoricalV3CandidateCollectionManifest>(&bytes)
                .map_err(|error| error.to_string())
        }) {
            Ok(existing) if existing == collection.manifest => {}
            Ok(_) => return Err("historical-v3 pending manifest identity changed".to_string()),
            Err(_) => fs::remove_file(&pending).map_err(|error| {
                format!("failed to clear incomplete historical-v3 pending manifest: {error}")
            })?,
        }
    }
    if !pending.exists() {
        write_compact_json_new(
            &pending,
            &collection.manifest,
            MAX_COLLECTION_MANIFEST_BYTES,
        )
        .map_err(|error| format!("failed to stage historical-v3 candidate manifest: {error}"))?;
    }
    fs::hard_link(&pending, path)
        .map_err(|error| format!("failed to publish historical-v3 candidate manifest: {error}"))?;
    sync_directory(parent)?;
    fs::remove_file(&pending)
        .map_err(|error| format!("failed to clear historical-v3 pending manifest: {error}"))
}

pub fn read_historical_v3_candidate_collection_manifest(
    path: &Path,
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    source_artifacts: &[HistoricalV3SourceFrameArtifact<'_>],
    source_binding_audit: &HistoricalV3SourceBindingAudit,
    state_root: &Path,
) -> Result<HistoricalV3CandidateCollection, String> {
    let bytes = read_limited(
        path,
        MAX_COLLECTION_MANIFEST_BYTES,
        "historical-v3 candidate manifest",
    )?;
    let manifest: HistoricalV3CandidateCollectionManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 candidate manifest: {error}"))?;
    let mut candidates = Vec::new();
    for partition in &manifest.partitions {
        if let HistoricalV3CandidatePartitionRecord::Complete {
            page_request_sha256s,
            ..
        } = partition
        {
            for request_sha256 in page_request_sha256s {
                let checkpoint = read_committed_page_checkpoint(state_root, request_sha256)?;
                candidates.extend(decode_page(&checkpoint)?.candidates);
            }
        }
    }
    let collection = HistoricalV3CandidateCollection {
        manifest,
        candidates,
    };
    validate_historical_v3_candidate_collection(
        protocol,
        prior_identities,
        source_artifacts,
        source_binding_audit,
        state_root,
        &collection,
    )?;
    Ok(collection)
}
