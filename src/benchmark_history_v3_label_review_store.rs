use super::super::history_v2_slot_store_support::{
    read_limited, require_plain_directory, write_compact_json_new,
};
use super::HistoricalV3LabelWorksheet;
use std::path::Path;

const MAX_LABEL_WORKSHEET_BYTES: u64 = 1024 * 1024 * 1024;

pub fn write_historical_v3_label_worksheet_new(
    path: &Path,
    worksheet: &HistoricalV3LabelWorksheet,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "historical-v3 worksheet path has no parent".to_string())?;
    require_plain_directory(parent, "historical-v3 worksheet parent")?;
    write_compact_json_new(path, worksheet, MAX_LABEL_WORKSHEET_BYTES)
        .map_err(|error| format!("failed to create historical-v3 worksheet: {error}"))
}

pub fn read_historical_v3_label_worksheet(
    path: &Path,
) -> Result<HistoricalV3LabelWorksheet, String> {
    let bytes = read_limited(
        path,
        MAX_LABEL_WORKSHEET_BYTES,
        "historical-v3 label worksheet",
    )?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 label worksheet: {error}"))
}
