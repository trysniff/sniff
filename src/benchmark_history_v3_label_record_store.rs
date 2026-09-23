use super::history_v2_slot_store_support::{
    read_limited, require_plain_directory, write_compact_json_new,
};
use super::{HistoricalV3LabelAudit, HistoricalV3ResolutionWorksheet};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::Path;

const MAX_LABEL_RECORD_BYTES: u64 = 64 * 1024 * 1024;

pub fn write_historical_v3_label_audit_new(
    path: &Path,
    audit: &HistoricalV3LabelAudit,
) -> Result<(), String> {
    write_new(path, audit, "historical-v3 label audit")
}

pub fn read_historical_v3_label_audit(path: &Path) -> Result<HistoricalV3LabelAudit, String> {
    read(path, "historical-v3 label audit")
}

pub fn write_historical_v3_resolution_worksheet_new(
    path: &Path,
    worksheet: &HistoricalV3ResolutionWorksheet,
) -> Result<(), String> {
    write_new(path, worksheet, "historical-v3 resolution worksheet")
}

pub fn read_historical_v3_resolution_worksheet(
    path: &Path,
) -> Result<HistoricalV3ResolutionWorksheet, String> {
    read(path, "historical-v3 resolution worksheet")
}

fn write_new<T: Serialize>(path: &Path, value: &T, label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent"))?;
    require_plain_directory(parent, &format!("{label} parent"))?;
    write_compact_json_new(path, value, MAX_LABEL_RECORD_BYTES)
        .map_err(|error| format!("failed to create {label}: {error}"))
}

fn read<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, String> {
    let bytes = read_limited(path, MAX_LABEL_RECORD_BYTES, label)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid {label}: {error}"))
}
