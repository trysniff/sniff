use super::*;
use std::fs::OpenOptions;
use std::io::Write;

const MAX_CORPUS_BUNDLE_BYTES: u64 = 128 * 1024 * 1024;

pub(super) fn persist_corpus_bundle(
    output_path: &Path,
    bundle: &HistoricalV2CorpusBundle,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(bundle)
        .map_err(|error| format!("failed to serialize historical-v2 corpus bundle: {error}"))?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CORPUS_BUNDLE_BYTES {
        return Err("historical-v2 corpus bundle exceeds its size limit".into());
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output_path)
        .map_err(|error| format!("failed to create historical-v2 corpus bundle: {error}"))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist historical-v2 corpus bundle: {error}"))
}

pub fn load_historical_v2_corpus_bundle(
    protocol_bytes: &[u8],
    corpus_root: &Path,
    path: &Path,
) -> Result<HistoricalV2CorpusBundle, String> {
    let corpus_root = canonical_plain_directory(corpus_root, "historical-v2 corpus root")?;
    relative_plain_file(&corpus_root, path, "historical-v2 corpus bundle")?;
    let bytes = load_plain_file(path, MAX_CORPUS_BUNDLE_BYTES, "historical-v2 corpus bundle")?;
    let bundle = serde_json::from_slice::<HistoricalV2CorpusBundle>(&bytes)
        .map_err(|error| format!("invalid historical-v2 corpus bundle: {error}"))?;
    validate_historical_v2_corpus_bundle(protocol_bytes, &corpus_root, &bundle)?;
    Ok(bundle)
}
