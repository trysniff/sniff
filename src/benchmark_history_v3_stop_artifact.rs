use super::history_v2_slot_store_support::{
    read_limited, require_plain_directory, write_compact_json_new,
};
use super::{
    HistoricalV3CandidateCollection, HistoricalV3Language, HistoricalV3OrderedRankOutcome,
    HistoricalV3OrderedStopStatus, HistoricalV3Protocol, HistoricalV3RankIdentity,
    HistoricalV3RankStage, HistoricalV3ReviewDisposition, evaluate_historical_v3_ordered_prefix,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const HISTORICAL_V3_STOP_ARTIFACT_SCHEMA_VERSION: u32 = 1;
const STOP_CONTRACT: &str = "sniffbench-historical-v3-ordered-stop-v1";
const MAX_STOP_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3StopRankDecision {
    Excluded {
        stage: HistoricalV3RankStage,
        artifact_sha256: String,
    },
    Reviewed {
        source_bundle_sha256: String,
        final_label_sha256: String,
        disposition: HistoricalV3ReviewDisposition,
    },
    Capped {
        qualification_sha256: String,
        cap_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3StopRankEntry {
    pub rank: HistoricalV3RankIdentity,
    pub decision: HistoricalV3StopRankDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3StopArtifact {
    pub schema_version: u32,
    pub contract: String,
    pub protocol_sha256: String,
    pub candidate_manifest_sha256: String,
    pub stream_task_sha256: String,
    pub language: HistoricalV3Language,
    pub entries: Vec<HistoricalV3StopRankEntry>,
    pub status: HistoricalV3OrderedStopStatus,
    pub stop_sha256: String,
}

pub fn prepare_historical_v3_stop_artifact(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    language: HistoricalV3Language,
    outcomes: &[HistoricalV3OrderedRankOutcome],
) -> Result<HistoricalV3StopArtifact, String> {
    let status = evaluate_historical_v3_ordered_prefix(protocol, collection, language, outcomes)?;
    if matches!(status, HistoricalV3OrderedStopStatus::Continue { .. }) {
        return Err("historical-v3 stop artifact cannot commit a nonterminal prefix".to_string());
    }
    let entries = outcomes
        .iter()
        .map(|outcome| HistoricalV3StopRankEntry {
            rank: outcome.rank().clone(),
            decision: match outcome {
                HistoricalV3OrderedRankOutcome::Excluded(proof) => {
                    HistoricalV3StopRankDecision::Excluded {
                        stage: proof.stage(),
                        artifact_sha256: proof.artifact_sha256().to_string(),
                    }
                }
                HistoricalV3OrderedRankOutcome::Reviewed(proof) => {
                    HistoricalV3StopRankDecision::Reviewed {
                        source_bundle_sha256: proof.source_bundle_sha256().to_string(),
                        final_label_sha256: proof.final_label_sha256().to_string(),
                        disposition: proof.record().disposition,
                    }
                }
                HistoricalV3OrderedRankOutcome::Capped(proof) => {
                    HistoricalV3StopRankDecision::Capped {
                        qualification_sha256: proof.qualification_sha256().to_string(),
                        cap_sha256: proof.cap_sha256().to_string(),
                    }
                }
            },
        })
        .collect();
    let mut artifact = HistoricalV3StopArtifact {
        schema_version: HISTORICAL_V3_STOP_ARTIFACT_SCHEMA_VERSION,
        contract: STOP_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        candidate_manifest_sha256: collection.manifest.manifest_sha256.clone(),
        stream_task_sha256: collection.manifest.stream_task.task_sha256.clone(),
        language,
        entries,
        status,
        stop_sha256: String::new(),
    };
    artifact.stop_sha256 = stop_sha256(&artifact)?;
    Ok(artifact)
}

pub fn verify_historical_v3_stop_artifact(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    language: HistoricalV3Language,
    outcomes: &[HistoricalV3OrderedRankOutcome],
    path: &Path,
) -> Result<HistoricalV3StopArtifact, String> {
    let stored = read_historical_v3_stop_artifact(path)?;
    let expected = prepare_historical_v3_stop_artifact(protocol, collection, language, outcomes)?;
    if stored != expected {
        return Err("historical-v3 stop artifact changed from the verified prefix".to_string());
    }
    Ok(stored)
}

pub fn write_historical_v3_stop_artifact_new(
    path: &Path,
    artifact: &HistoricalV3StopArtifact,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "historical-v3 stop-artifact path has no parent".to_string())?;
    require_plain_directory(parent, "historical-v3 stop-artifact parent")?;
    write_compact_json_new(path, artifact, MAX_STOP_BYTES)
        .map_err(|error| format!("failed to create historical-v3 stop artifact: {error}"))
}

pub fn read_historical_v3_stop_artifact(path: &Path) -> Result<HistoricalV3StopArtifact, String> {
    let bytes = read_limited(path, MAX_STOP_BYTES, "historical-v3 stop artifact")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 stop artifact: {error}"))
}

fn stop_sha256(artifact: &HistoricalV3StopArtifact) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.stop_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 stop artifact: {error}"))
}
