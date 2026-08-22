use super::{
    HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION, HistoricalV2ExclusionManifest,
    HistoricalV2Frame, HistoricalV2FrameDisposition, HistoricalV2SelectedPayload,
    HistoricalV2SelectedPayloads, HistoricalV2SlotOutcome, HistoricalV2SlotSelection,
    ValidatedHistoricalV2Protocol, validate_historical_v2_frame_commitment,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const PAYLOAD_CONTRACT: &str = "sniffbench-historical-v2-selected-payloads-v1";

pub fn validate_historical_v2_selected_payloads_commitment(
    protocol: &ValidatedHistoricalV2Protocol,
    frame: &HistoricalV2Frame,
    exclusions: &HistoricalV2ExclusionManifest,
    selection: &HistoricalV2SlotSelection,
    payloads: &HistoricalV2SelectedPayloads,
) -> Result<(), String> {
    validate_historical_v2_frame_commitment(frame)?;
    if frame.protocol_sha256 != protocol.protocol_sha256
        || exclusions.protocol_sha256 != protocol.protocol_sha256
        || selection.protocol_sha256 != protocol.protocol_sha256
        || selection.frame_sha256 != frame.frame_sha256
        || selection.exclusion_manifest_sha256 != exclusions.manifest_sha256
        || payloads.schema_version != HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION
        || payloads.payload_contract != PAYLOAD_CONTRACT
        || payloads.protocol_sha256 != protocol.protocol_sha256
        || payloads.frame_sha256 != frame.frame_sha256
        || payloads.exclusion_manifest_sha256 != exclusions.manifest_sha256
        || payloads.selection_sha256 != selection.selection_sha256
        || payloads.selected_count != payloads.records.len()
        || payloads.selected_count != selection.selected_count
        || payloads.payloads_sha256 != payloads_sha256(payloads)?
    {
        return Err("historical-v2 selected payload commitment changed".to_string());
    }

    let selected = selected_slots(selection)?;
    let frame_records = frame
        .records
        .iter()
        .map(|record| (record.global_row_index, record))
        .collect::<BTreeMap<_, _>>();
    if frame_records.len() != frame.records.len() {
        return Err("historical-v2 frame repeats a global row index".to_string());
    }

    let mut previous = None;
    let mut seen = BTreeSet::new();
    for payload in &payloads.records {
        let key = (payload.language.as_str(), payload.slot_number);
        if previous.is_some_and(|previous| previous >= key) || !seen.insert(key) {
            return Err(
                "historical-v2 selected payloads must be sorted by unique slot".to_string(),
            );
        }
        previous = Some(key);
        validate_payload(payload)?;

        let selected = selected.get(&key).ok_or_else(|| {
            "historical-v2 payload does not belong to a selected fixed slot".to_string()
        })?;
        if payload.global_row_index != selected.global_row_index
            || payload.instance_id != selected.instance_id
            || payload.patch_sha256 != selected.patch_sha256
        {
            return Err("historical-v2 payload changed its fixed-slot identity".to_string());
        }
        let record = frame_records
            .get(&payload.global_row_index)
            .ok_or_else(|| "historical-v2 payload source row is absent".to_string())?;
        let HistoricalV2FrameDisposition::Eligible { facts, rank_sha256 } = &record.disposition
        else {
            return Err("historical-v2 payload source row is not eligible".to_string());
        };
        if payload.source_shard_index != record.source_shard_index
            || payload.source_row_index != record.source_row_index
            || payload.instance_id != record.instance_id
            || payload.patch_sha256 != record.patch_sha256
            || payload.language != facts.language
            || rank_sha256 != selected.rank_sha256
        {
            return Err("historical-v2 payload changed from its committed frame row".to_string());
        }
    }
    if seen.len() != selected.len() {
        return Err("historical-v2 selected payload set is incomplete".to_string());
    }
    Ok(())
}

#[cfg(any(test, feature = "sniffbench-frame"))]
pub(super) fn seal_historical_v2_selected_payload(
    mut payload: HistoricalV2SelectedPayload,
) -> Result<HistoricalV2SelectedPayload, String> {
    if !payload.payload_sha256.is_empty() {
        return Err("historical-v2 selected payload is already sealed".to_string());
    }
    payload.payload_sha256 = payload_sha256(&payload)?;
    Ok(payload)
}

#[cfg(any(test, feature = "sniffbench-frame"))]
pub(super) fn seal_historical_v2_selected_payloads(
    mut payloads: HistoricalV2SelectedPayloads,
) -> Result<HistoricalV2SelectedPayloads, String> {
    if !payloads.payloads_sha256.is_empty() {
        return Err("historical-v2 selected payload collection is already sealed".to_string());
    }
    payloads.payloads_sha256 = payloads_sha256(&payloads)?;
    Ok(payloads)
}

struct SelectedSlot<'a> {
    global_row_index: usize,
    instance_id: &'a str,
    patch_sha256: &'a str,
    rank_sha256: &'a str,
}

fn selected_slots(
    selection: &HistoricalV2SlotSelection,
) -> Result<BTreeMap<(&str, usize), SelectedSlot<'_>>, String> {
    let mut selected = BTreeMap::new();
    for slot in &selection.slots {
        let HistoricalV2SlotOutcome::Selected {
            global_row_index,
            instance_id,
            patch_sha256,
            rank_sha256,
            ..
        } = &slot.outcome
        else {
            continue;
        };
        if selected
            .insert(
                (slot.language.as_str(), slot.slot_number),
                SelectedSlot {
                    global_row_index: *global_row_index,
                    instance_id,
                    patch_sha256,
                    rank_sha256,
                },
            )
            .is_some()
        {
            return Err("historical-v2 fixed selection repeats a slot".to_string());
        }
    }
    if selected.len() != selection.selected_count {
        return Err("historical-v2 fixed selection count changed".to_string());
    }
    Ok(selected)
}

fn validate_payload(payload: &HistoricalV2SelectedPayload) -> Result<(), String> {
    if payload.patch.is_empty()
        || sha256(payload.patch.as_bytes()) != payload.patch_sha256
        || digest_option(payload.install_config.as_deref()) != payload.install_config_sha256
        || digest_option(payload.test_patch.as_deref()) != payload.test_patch_sha256
        || payload.payload_sha256 != payload_sha256(payload)?
    {
        return Err("historical-v2 selected payload opened values changed".to_string());
    }
    Ok(())
}

fn payload_sha256(payload: &HistoricalV2SelectedPayload) -> Result<String, String> {
    hash_json(&(
        &payload.language,
        payload.slot_number,
        payload.source_shard_index,
        payload.source_row_index,
        payload.global_row_index,
        &payload.instance_id,
        &payload.patch,
        &payload.patch_sha256,
        &payload.install_config,
        &payload.install_config_sha256,
        &payload.test_patch,
        &payload.test_patch_sha256,
    ))
}

fn payloads_sha256(payloads: &HistoricalV2SelectedPayloads) -> Result<String, String> {
    hash_json(&(
        payloads.schema_version,
        &payloads.payload_contract,
        &payloads.protocol_sha256,
        &payloads.frame_sha256,
        &payloads.exclusion_manifest_sha256,
        &payloads.selection_sha256,
        payloads.selected_count,
        &payloads.records,
    ))
}

fn digest_option(value: Option<&str>) -> Option<String> {
    value.map(|value| sha256(value.as_bytes()))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 payload artifact: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_seal_binds_opened_values() {
        let payload = seal_historical_v2_selected_payload(payload()).expect("seal payload");
        assert!(validate_payload(&payload).is_ok());

        let mut changed = payload;
        changed.test_patch = Some("different".to_string());
        assert!(validate_payload(&changed).is_err());
    }

    #[test]
    fn payload_collection_cannot_be_resealed() {
        let payload = seal_historical_v2_selected_payload(payload()).expect("seal payload");
        let collection = seal_historical_v2_selected_payloads(HistoricalV2SelectedPayloads {
            schema_version: HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION,
            payload_contract: PAYLOAD_CONTRACT.to_string(),
            protocol_sha256: "0".repeat(64),
            frame_sha256: "1".repeat(64),
            exclusion_manifest_sha256: "2".repeat(64),
            selection_sha256: "3".repeat(64),
            selected_count: 1,
            records: vec![payload],
            payloads_sha256: String::new(),
        })
        .expect("seal collection");
        assert!(seal_historical_v2_selected_payloads(collection).is_err());
    }

    fn payload() -> HistoricalV2SelectedPayload {
        HistoricalV2SelectedPayload {
            language: "rust".to_string(),
            slot_number: 1,
            source_shard_index: 0,
            source_row_index: 2,
            global_row_index: 2,
            instance_id: "instance".to_string(),
            patch: "patch".to_string(),
            patch_sha256: sha256(b"patch"),
            install_config: Some("install".to_string()),
            install_config_sha256: Some(sha256(b"install")),
            test_patch: Some("test".to_string()),
            test_patch_sha256: Some(sha256(b"test")),
            payload_sha256: String::new(),
        }
    }
}
