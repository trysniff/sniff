use super::history_v2_parquet::{safe_relative_path, sha256_file};
use super::history_v2_payload_commitment::{
    PAYLOAD_CONTRACT, seal_historical_v2_selected_payload, seal_historical_v2_selected_payloads,
};
use super::history_v2_payload_parquet::visit_historical_v2_post_selection_shard;
use super::{
    HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION, HistoricalV2ExclusionManifest,
    HistoricalV2Frame, HistoricalV2ProjectedPayloadRow, HistoricalV2SelectedPayload,
    HistoricalV2SelectedPayloads, HistoricalV2SlotOutcome, HistoricalV2SlotSelection,
    validate_historical_v2_frame_sources, validate_historical_v2_protocol,
    validate_historical_v2_slot_selection,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn extract_historical_v2_selected_payloads(
    protocol_bytes: &[u8],
    dataset_root: &Path,
    artifact_root: &Path,
    frame: &HistoricalV2Frame,
    exclusions: &HistoricalV2ExclusionManifest,
    selection: &HistoricalV2SlotSelection,
) -> Result<HistoricalV2SelectedPayloads, String> {
    let protocol = validate_historical_v2_protocol(protocol_bytes)?;

    // These complete replays happen before either post-selection field is projected.
    validate_historical_v2_frame_sources(protocol_bytes, dataset_root, frame)?;
    validate_historical_v2_slot_selection(
        protocol_bytes,
        artifact_root,
        frame,
        exclusions,
        selection,
    )?;

    let canonical_root = fs::canonicalize(dataset_root)
        .map_err(|error| format!("failed to resolve historical-v2 dataset root: {error}"))?;
    let selected = selected_rows(frame, selection)?;
    let selected_indices = selected.keys().copied().collect::<BTreeSet<_>>();
    let mut opened = BTreeMap::new();
    let mut global_row_start = 0;
    for (source_shard_index, expected_shard) in protocol.protocol.dataset.shards.iter().enumerate()
    {
        let relative = safe_relative_path(&expected_shard.path)?;
        let path = fs::canonicalize(canonical_root.join(relative)).map_err(|error| {
            format!(
                "failed to resolve historical-v2 shard {}: {error}",
                expected_shard.path
            )
        })?;
        if !path.starts_with(&canonical_root) {
            return Err(format!(
                "historical-v2 shard escapes the dataset root: {}",
                expected_shard.path
            ));
        }
        let metadata = fs::metadata(&path).map_err(|error| {
            format!(
                "failed to inspect historical-v2 shard {}: {error}",
                expected_shard.path
            )
        })?;
        if metadata.len() != expected_shard.size_bytes {
            return Err(format!(
                "historical-v2 shard size changed for {}",
                expected_shard.path
            ));
        }
        if !sha256_file(&path)?.eq_ignore_ascii_case(&expected_shard.lfs_sha256) {
            return Err(format!(
                "historical-v2 shard SHA-256 changed for {}",
                expected_shard.path
            ));
        }

        let row_count = visit_historical_v2_post_selection_shard(
            &path,
            source_shard_index,
            global_row_start,
            &selected_indices,
            |row| {
                let binding = selected.get(&row.global_row_index).ok_or_else(|| {
                    "historical-v2 opened a payload outside the fixed slots".to_string()
                })?;
                if row.source_shard_index != binding.source_shard_index
                    || row.source_row_index != binding.source_row_index
                    || row.instance_id != binding.instance_id
                {
                    return Err(
                        "historical-v2 selected payload identity changed at its source row"
                            .to_string(),
                    );
                }
                let payload = committed_payload(binding, row)?;
                if opened.insert(payload.global_row_index, payload).is_some() {
                    return Err("historical-v2 opened a selected payload twice".to_string());
                }
                Ok(())
            },
        )?;
        global_row_start += row_count;
    }
    if global_row_start != frame.row_count {
        return Err("historical-v2 payload replay row count changed".to_string());
    }

    let mut records = Vec::with_capacity(selected.len());
    for row_index in selected.keys() {
        records.push(
            opened.remove(row_index).ok_or_else(|| {
                format!("historical-v2 selected payload row {row_index} is missing")
            })?,
        );
    }
    records.sort_by(|left, right| {
        (&left.language, left.slot_number).cmp(&(&right.language, right.slot_number))
    });
    if !opened.is_empty() || records.len() != selection.selected_count {
        return Err("historical-v2 selected payload count changed".to_string());
    }

    let payloads = HistoricalV2SelectedPayloads {
        schema_version: HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION,
        payload_contract: PAYLOAD_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256,
        frame_sha256: frame.frame_sha256.clone(),
        exclusion_manifest_sha256: exclusions.manifest_sha256.clone(),
        selection_sha256: selection.selection_sha256.clone(),
        selected_count: records.len(),
        records,
        payloads_sha256: String::new(),
    };
    seal_historical_v2_selected_payloads(payloads)
}

pub fn validate_historical_v2_selected_payloads(
    protocol_bytes: &[u8],
    dataset_root: &Path,
    artifact_root: &Path,
    frame: &HistoricalV2Frame,
    exclusions: &HistoricalV2ExclusionManifest,
    selection: &HistoricalV2SlotSelection,
    payloads_path: &Path,
) -> Result<(), String> {
    let expected = extract_historical_v2_selected_payloads(
        protocol_bytes,
        dataset_root,
        artifact_root,
        frame,
        exclusions,
        selection,
    )?;
    let payloads: HistoricalV2SelectedPayloads = serde_json::from_slice(
        &fs::read(payloads_path)
            .map_err(|error| format!("failed to read historical-v2 selected payloads: {error}"))?,
    )
    .map_err(|error| format!("failed to parse historical-v2 selected payloads: {error}"))?;
    if payloads != expected {
        return Err("historical-v2 selected payloads changed".to_string());
    }
    Ok(())
}

pub fn write_historical_v2_selected_payloads(
    protocol_bytes: &[u8],
    dataset_root: &Path,
    artifact_root: &Path,
    frame: &HistoricalV2Frame,
    exclusions: &HistoricalV2ExclusionManifest,
    selection: &HistoricalV2SlotSelection,
    output_path: &Path,
) -> Result<HistoricalV2SelectedPayloads, String> {
    let payloads = extract_historical_v2_selected_payloads(
        protocol_bytes,
        dataset_root,
        artifact_root,
        frame,
        exclusions,
        selection,
    )?;
    write_create_new(output_path, &payloads)?;
    Ok(payloads)
}

#[derive(Debug)]
struct SelectedBinding {
    language: String,
    slot_number: usize,
    source_shard_index: usize,
    source_row_index: usize,
    instance_id: String,
    patch_sha256: String,
}

fn selected_rows(
    frame: &HistoricalV2Frame,
    selection: &HistoricalV2SlotSelection,
) -> Result<BTreeMap<usize, SelectedBinding>, String> {
    let frame_records = frame
        .records
        .iter()
        .map(|record| (record.global_row_index, record))
        .collect::<BTreeMap<_, _>>();
    if frame_records.len() != frame.records.len() {
        return Err("historical-v2 frame repeats a global row index".to_string());
    }
    let mut selected = BTreeMap::new();
    for slot in &selection.slots {
        let HistoricalV2SlotOutcome::Selected {
            global_row_index,
            instance_id,
            ..
        } = &slot.outcome
        else {
            continue;
        };
        let record = frame_records.get(global_row_index).ok_or_else(|| {
            "historical-v2 selected row is absent from the source frame".to_string()
        })?;
        let binding = SelectedBinding {
            language: slot.language.clone(),
            slot_number: slot.slot_number,
            source_shard_index: record.source_shard_index,
            source_row_index: record.source_row_index,
            instance_id: instance_id.clone(),
            patch_sha256: record.patch_sha256.clone(),
        };
        if selected.insert(*global_row_index, binding).is_some() {
            return Err("historical-v2 fixed slots repeat a source row".to_string());
        }
    }
    if selected.len() != selection.selected_count {
        return Err("historical-v2 fixed-slot selected count changed".to_string());
    }
    Ok(selected)
}

fn committed_payload(
    binding: &SelectedBinding,
    row: HistoricalV2ProjectedPayloadRow,
) -> Result<HistoricalV2SelectedPayload, String> {
    let patch_sha256 = sha256(&row.patch);
    if patch_sha256 != binding.patch_sha256 {
        return Err("historical-v2 selected patch changed from the fixed frame".to_string());
    }
    let install_config_sha256 = row.install_config.as_deref().map(sha256);
    let test_patch_sha256 = row.test_patch.as_deref().map(sha256);
    seal_historical_v2_selected_payload(HistoricalV2SelectedPayload {
        language: binding.language.clone(),
        slot_number: binding.slot_number,
        source_shard_index: row.source_shard_index,
        source_row_index: row.source_row_index,
        global_row_index: row.global_row_index,
        instance_id: row.instance_id,
        patch: row.patch,
        patch_sha256,
        install_config: row.install_config,
        install_config_sha256,
        test_patch: row.test_patch,
        test_patch_sha256,
        payload_sha256: String::new(),
    })
}

fn write_create_new(path: &Path, payloads: &HistoricalV2SelectedPayloads) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(payloads)
        .map_err(|error| format!("failed to serialize historical-v2 selected payloads: {error}"))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("failed to create historical-v2 selected payloads: {error}"))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist historical-v2 selected payloads: {error}"))
}

fn sha256(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_commitment_binds_slot_identity_and_opened_values() {
        let binding = SelectedBinding {
            language: "rust".to_string(),
            slot_number: 7,
            source_shard_index: 1,
            source_row_index: 11,
            instance_id: "owner__repo-42".to_string(),
            patch_sha256: sha256("diff --git a/src.rs b/src.rs"),
        };
        let row = HistoricalV2ProjectedPayloadRow {
            source_shard_index: 1,
            source_row_index: 11,
            global_row_index: 101,
            instance_id: binding.instance_id.clone(),
            patch: "diff --git a/src.rs b/src.rs".to_string(),
            install_config: Some("{\"python\":\"3.12\"}".to_string()),
            test_patch: Some("diff --git a/test.rs b/test.rs".to_string()),
        };

        let committed = committed_payload(&binding, row.clone()).unwrap();
        assert_eq!(
            committed.install_config_sha256.as_deref(),
            Some(sha256(row.install_config.as_deref().unwrap()).as_str())
        );
        assert_eq!(
            committed.test_patch_sha256.as_deref(),
            Some(sha256(row.test_patch.as_deref().unwrap()).as_str())
        );

        let mut changed = row;
        changed.test_patch = Some("changed".to_string());
        assert_ne!(
            committed.payload_sha256,
            committed_payload(&binding, changed).unwrap().payload_sha256
        );
    }

    #[test]
    fn absent_optional_payloads_are_explicit_and_committed() {
        let binding = SelectedBinding {
            language: "go".to_string(),
            slot_number: 1,
            source_shard_index: 0,
            source_row_index: 0,
            instance_id: "owner__repo-1".to_string(),
            patch_sha256: sha256("patch"),
        };
        let committed = committed_payload(
            &binding,
            HistoricalV2ProjectedPayloadRow {
                source_shard_index: 0,
                source_row_index: 0,
                global_row_index: 0,
                instance_id: binding.instance_id.clone(),
                patch: "patch".to_string(),
                install_config: None,
                test_patch: None,
            },
        )
        .unwrap();

        assert_eq!(committed.install_config, None);
        assert_eq!(committed.install_config_sha256, None);
        assert_eq!(committed.test_patch, None);
        assert_eq!(committed.test_patch_sha256, None);
        assert_eq!(committed.payload_sha256.len(), 64);
    }

    #[test]
    fn rejects_a_patch_that_does_not_match_the_fixed_frame() {
        let binding = SelectedBinding {
            language: "python".to_string(),
            slot_number: 3,
            source_shard_index: 0,
            source_row_index: 4,
            instance_id: "owner__repo-3".to_string(),
            patch_sha256: sha256("expected patch"),
        };
        let error = committed_payload(
            &binding,
            HistoricalV2ProjectedPayloadRow {
                source_shard_index: 0,
                source_row_index: 4,
                global_row_index: 4,
                instance_id: binding.instance_id.clone(),
                patch: "different patch".to_string(),
                install_config: None,
                test_patch: None,
            },
        )
        .unwrap_err();

        assert!(error.contains("patch changed"));
    }
}
