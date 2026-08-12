use super::{
    ActualCostReceipt, require_safe_artifact_path, require_sha256, require_text,
    validate_artifact_hash,
};
use std::fs;
use std::path::Path;

const ACTUAL_COST_RECEIPT_SCHEMA_VERSION: u32 = 1;

pub fn validate_actual_cost_receipt(
    corpus_root: &Path,
    artifact_path: &str,
    expected_hash: &str,
    provider: &str,
    model: &str,
    actual_cost_microusd: u64,
    provenance: &str,
) -> Result<(), String> {
    require_safe_artifact_path(artifact_path)?;
    require_sha256("actual_cost_artifact_sha256", expected_hash)?;
    validate_artifact_hash(
        corpus_root,
        artifact_path,
        expected_hash,
        "actual provider cost receipt",
    )?;
    let root = fs::canonicalize(corpus_root).map_err(|error| {
        format!(
            "failed to resolve benchmark corpus root {}: {error}",
            corpus_root.display()
        )
    })?;
    let path = fs::canonicalize(root.join(artifact_path)).map_err(|error| {
        format!("failed to resolve actual provider cost receipt {artifact_path}: {error}")
    })?;
    let bytes = fs::read(&path).map_err(|error| {
        format!("failed to read actual provider cost receipt {artifact_path}: {error}")
    })?;
    let receipt: ActualCostReceipt = serde_json::from_slice(&bytes).map_err(|error| {
        format!("actual provider cost receipt {artifact_path} is not valid JSON: {error}")
    })?;
    if receipt.schema_version != ACTUAL_COST_RECEIPT_SCHEMA_VERSION {
        return Err(format!(
            "actual provider cost receipt schema_version must be {ACTUAL_COST_RECEIPT_SCHEMA_VERSION}"
        ));
    }
    require_text("cost receipt provider", &receipt.provider)?;
    require_text("cost receipt model", &receipt.model)?;
    require_text("cost receipt provenance", &receipt.provenance)?;
    if receipt.provider != provider
        || receipt.model != model
        || receipt.actual_cost_microusd != actual_cost_microusd
        || receipt.provenance != provenance
    {
        return Err("actual provider cost receipt does not match the benchmark run".to_string());
    }
    if receipt.currency != "USD" {
        return Err("actual provider cost receipt currency must be USD".to_string());
    }
    require_safe_artifact_path(&receipt.raw_evidence_artifact_path)?;
    require_sha256("raw_evidence_sha256", &receipt.raw_evidence_sha256)?;
    if receipt.raw_evidence_artifact_path == artifact_path {
        return Err("actual cost receipt cannot cite itself as raw evidence".to_string());
    }
    validate_artifact_hash(
        corpus_root,
        &receipt.raw_evidence_artifact_path,
        &receipt.raw_evidence_sha256,
        "raw provider cost evidence",
    )
}
