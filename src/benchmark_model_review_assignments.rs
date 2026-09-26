use super::{BenchmarkSourceSeal, prepare_label_review};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

pub const MODEL_REVIEW_ASSIGNMENTS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelReviewShard {
    pub shard_id: String,
    pub repository: String,
    pub method_ids: Vec<String>,
    pub reviewer_slots: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelReviewAssignments {
    pub schema_version: u32,
    pub source_seal_artifact_sha256: String,
    pub source_seal_commitment_sha256: String,
    pub task_commitment_sha256: String,
    pub prompt_sha256: String,
    pub max_methods_per_shard: usize,
    pub excluded_method_ids: Vec<String>,
    pub included_method_count: usize,
    pub shards: Vec<ModelReviewShard>,
    pub manifest_sha256: String,
}

impl ModelReviewAssignments {
    pub fn computed_sha256(&self) -> Result<String, String> {
        serde_json::to_vec(&(
            self.schema_version,
            &self.source_seal_artifact_sha256,
            &self.source_seal_commitment_sha256,
            &self.task_commitment_sha256,
            &self.prompt_sha256,
            self.max_methods_per_shard,
            &self.excluded_method_ids,
            self.included_method_count,
            &self.shards,
        ))
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("cannot commit model-review assignments: {error}"))
    }
}

pub fn prepare_model_review_assignments(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    source_seal_artifact_sha256: &str,
    prompt_bytes: &[u8],
    max_methods_per_shard: usize,
    excluded_method_ids: &[String],
) -> Result<ModelReviewAssignments, String> {
    if prompt_bytes.is_empty() {
        return Err("model-review prompt is empty".to_string());
    }
    if !(1..=8).contains(&max_methods_per_shard) {
        return Err("model-review shard size must be between 1 and 8".to_string());
    }
    let task = prepare_label_review(seal, seal_root, source_seal_artifact_sha256)?;
    let known = task
        .methods
        .iter()
        .map(|method| method.method_id.as_str())
        .collect::<HashSet<_>>();
    let mut excluded = excluded_method_ids.to_vec();
    excluded.sort();
    if excluded.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("model-review exclusions repeat a method".to_string());
    }
    if excluded
        .iter()
        .any(|method_id| !known.contains(method_id.as_str()))
    {
        return Err("model-review exclusions contain an unknown method".to_string());
    }
    let excluded_set = excluded.iter().map(String::as_str).collect::<HashSet<_>>();
    let mut by_repository = BTreeMap::<String, Vec<String>>::new();
    for method in &task.methods {
        if !excluded_set.contains(method.method_id.as_str()) {
            by_repository
                .entry(method.repository.clone())
                .or_default()
                .push(method.method_id.clone());
        }
    }
    let included_method_count = task.methods.len() - excluded.len();
    if included_method_count == 0 {
        return Err("model-review assignments have no included methods".to_string());
    }
    let mut shards = Vec::new();
    for (repository, method_ids) in by_repository {
        for chunk in method_ids.chunks(max_methods_per_shard) {
            shards.push(ModelReviewShard {
                shard_id: format!("model-review-{:04}", shards.len() + 1),
                repository: repository.clone(),
                method_ids: chunk.to_vec(),
                reviewer_slots: 2,
            });
        }
    }
    let mut manifest = ModelReviewAssignments {
        schema_version: MODEL_REVIEW_ASSIGNMENTS_SCHEMA_VERSION,
        source_seal_artifact_sha256: task.source_seal_artifact_sha256,
        source_seal_commitment_sha256: task.source_seal_commitment_sha256,
        task_commitment_sha256: task.task_commitment_sha256,
        prompt_sha256: format!("{:x}", Sha256::digest(prompt_bytes)),
        max_methods_per_shard,
        excluded_method_ids: excluded,
        included_method_count,
        shards,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest.computed_sha256()?;
    Ok(manifest)
}

pub fn validate_model_review_assignments(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    source_seal_artifact_sha256: &str,
    prompt_bytes: &[u8],
    manifest: &ModelReviewAssignments,
) -> Result<(), String> {
    let expected = prepare_model_review_assignments(
        seal,
        seal_root,
        source_seal_artifact_sha256,
        prompt_bytes,
        manifest.max_methods_per_shard,
        &manifest.excluded_method_ids,
    )?;
    if manifest != &expected {
        return Err("model-review assignments do not replay from sealed source".to_string());
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_model_review_assignments_tests.rs"]
mod tests;
