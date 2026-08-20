use super::*;
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) fn source_snapshots(
    corpus_root: &Path,
    bundle_root: &Path,
    bundle_relative: &str,
    bundle: &HistoricalV2SourceReviewBundle,
    side: HistoricalV2ReviewSnapshotSide,
) -> Result<Vec<SourceSnapshot>, String> {
    let snapshot = bundle
        .snapshots
        .iter()
        .find(|snapshot| snapshot.side == side)
        .ok_or_else(|| "historical-v2 corpus source snapshot disappeared".to_string())?;
    let mut sources = Vec::new();
    for artifact in &snapshot.artifacts {
        if !crate::parser::supports_source_path(&artifact.repository_path) {
            continue;
        }
        let relative = artifact
            .artifact_path
            .as_deref()
            .ok_or_else(|| "historical-v2 supported corpus source has no artifact".to_string())?;
        let content_sha256 = artifact
            .content_sha256
            .as_deref()
            .ok_or_else(|| "historical-v2 supported corpus source has no commitment".to_string())?;
        let byte_length = artifact.byte_length.ok_or_else(|| {
            "historical-v2 supported corpus source has no byte length".to_string()
        })?;
        if byte_length > MAX_CORPUS_SOURCE_BYTES {
            return Err("historical-v2 corpus source exceeds the parser size limit".into());
        }
        let path = safe_join(bundle_root, relative)?;
        let bytes = load_plain_file(&path, byte_length, "historical-v2 corpus source")?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != byte_length {
            return Err("historical-v2 corpus source changed byte length".into());
        }
        crate::parser::parse_source_checked(&artifact.repository_path, &bytes)?;
        if format!("{:x}", Sha256::digest(&bytes)) != content_sha256 {
            return Err("historical-v2 corpus source changed from its review bundle".into());
        }
        let artifact_path = format!("{bundle_relative}/{relative}");
        safe_join(corpus_root, &artifact_path)?;
        sources.push(SourceSnapshot {
            repository: bundle.review_item_id.clone(),
            revision: snapshot.revision.clone(),
            repository_path: artifact.repository_path.clone(),
            artifact_path,
            sha256: content_sha256.to_string(),
        });
    }
    sources.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    if sources.is_empty() {
        return Err("historical-v2 corpus snapshot has no supported source".into());
    }
    Ok(sources)
}
