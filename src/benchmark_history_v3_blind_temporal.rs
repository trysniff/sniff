use super::HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC;
use super::history_v3_time::parse_utc_second;
use super::{
    BenchmarkSourceSeal, SourceAssessmentEvidenceKind, SourceCandidateAssessment,
    SourceSelectionCompositeAudit, SourceSelectionDisposition, validate_source_seal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const BLIND_SEAL_FILE_SHA256: &str =
    "33bf6eaac53c3e58c6d4ff2f3ecf54321ef59b1c7f81a58f5e19790bb7b4f5a4";
const BLIND_SEAL_COMMITMENT_SHA256: &str =
    "45fbabccc0ec2541e5033f2bfd3c85c0fb06c3235d0c077c40109d3e2484298e";
const BLIND_AUDIT_FILE_SHA256: &str =
    "e42d39cfa74e67b226f3c36b59180f6aa43e587a7cbf98c42dc67f704df91196";
const GRAPHQL_RESPONSE_SHA256: &str =
    "2e11d32941f4a9addc88b72301f3312a02ac938e9b3d18107df475d180992141";
const BLIND_SELECTION_ID: &str = "sniffbench-blind-oss-v1-composite";
const BLIND_AUDIT_PATH: &str = "blind-source-seal.sources/selection/source-selection-audit.json";
const BLIND_TEMPORAL_CONTRACT: &str = "sniffbench-historical-v3-prior-blind-temporal-v1";

// The response fixture stores GitHub's `.data` projection; volatile extensions are excluded.
pub const BLIND_PRIOR_IDENTITIES_QUERY: &str =
    include_str!("benchmark_assets/historical-v3-blind-prior-identities.graphql");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindPriorRepositoryWitness {
    pub canonical_repository: String,
    pub source_component: String,
    pub github_repository_id: u64,
    pub github_node_id: String,
    pub created_at_utc: String,
    pub raw_source_payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindPriorTemporalProof {
    pub contract: String,
    pub source_seal_file_sha256: String,
    pub source_seal_commitment_sha256: String,
    pub selection_audit_file_sha256: String,
    pub selection_recorded_at_utc: String,
    pub graphql_response_sha256: String,
    pub graphql_query_sha256: String,
    pub cutoff_utc: String,
    pub witnesses: Vec<BlindPriorRepositoryWitness>,
    pub latest_witness_utc: String,
    pub proof_sha256: String,
}

#[derive(Deserialize)]
struct GraphqlData {
    nodes: Vec<Option<GraphqlRepository>>,
}

#[derive(Deserialize)]
struct GraphqlRepository {
    id: String,
    #[serde(rename = "databaseId")]
    database_id: u64,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "nameWithOwner")]
    name_with_owner: String,
}

#[derive(Deserialize)]
struct RawRepository {
    id: u64,
    node_id: String,
    created_at: String,
    full_name: String,
}

/// Replays the full blind source seal before using its selected API responses.
/// GitHub creation time establishes repository existence, not name continuity.
pub fn derive_blind_prior_temporal_proof(
    seal_path: &Path,
    graphql_response_bytes: &[u8],
) -> Result<BlindPriorTemporalProof, String> {
    let seal_root = seal_path
        .parent()
        .filter(|_| seal_path.is_absolute())
        .ok_or("blind prior source-seal path must be absolute")?;
    let metadata = fs::symlink_metadata(seal_path)
        .map_err(|error| format!("failed to inspect blind prior source seal: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4 * 1024 * 1024
    {
        return Err("blind prior source seal is not a plain bounded file".to_string());
    }
    let seal_bytes = fs::read(seal_path)
        .map_err(|error| format!("failed to read blind prior source seal: {error}"))?;
    if sha256(&seal_bytes) != BLIND_SEAL_FILE_SHA256 {
        return Err("blind prior source seal differs from its frozen artifact".to_string());
    }
    if sha256(graphql_response_bytes) != GRAPHQL_RESPONSE_SHA256 {
        return Err("blind prior GraphQL projection differs from its frozen capture".to_string());
    }
    let seal: BenchmarkSourceSeal = serde_json::from_slice(&seal_bytes)
        .map_err(|error| format!("invalid blind prior source seal: {error}"))?;
    if seal.selection_id != BLIND_SELECTION_ID
        || seal.seal_sha256 != BLIND_SEAL_COMMITMENT_SHA256
        || seal.selection_audit_artifact_path != BLIND_AUDIT_PATH
        || seal.selection_audit_artifact_sha256 != BLIND_AUDIT_FILE_SHA256
    {
        return Err("blind prior source-seal identity changed".to_string());
    }
    validate_source_seal(&seal, seal_root)?;
    let audit_bytes = fs::read(seal_root.join(BLIND_AUDIT_PATH))
        .map_err(|error| format!("failed to read blind prior selection audit: {error}"))?;
    if sha256(&audit_bytes) != BLIND_AUDIT_FILE_SHA256 {
        return Err("blind prior selection audit differs from its frozen artifact".to_string());
    }
    let audit: SourceSelectionCompositeAudit = serde_json::from_slice(&audit_bytes)
        .map_err(|error| format!("invalid blind prior selection audit: {error}"))?;
    let nodes = parse_graphql_nodes(graphql_response_bytes)?;
    let cutoff = parse_utc_second(HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC)?;
    let mut witnesses = Vec::new();
    for component in &audit.components {
        for assessment in &component.assessments {
            if assessment.disposition != Some(SourceSelectionDisposition::Selected) {
                continue;
            }
            witnesses.push(witness_selected(
                assessment,
                &component.policy.selection_id,
                &nodes,
                cutoff,
            )?);
        }
    }
    witnesses.sort_by(|left, right| left.canonical_repository.cmp(&right.canonical_repository));
    let names = witnesses
        .iter()
        .map(|witness| witness.canonical_repository.as_str())
        .collect::<Vec<_>>();
    let sealed_names = seal
        .sources
        .iter()
        .map(|source| {
            source
                .repository
                .strip_prefix("https://github.com/")
                .ok_or("blind prior sealed source is not a GitHub repository")
        })
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>();
    let distinct_nodes = witnesses
        .iter()
        .map(|witness| witness.github_node_id.as_str())
        .collect::<BTreeSet<_>>();
    if witnesses.len() != 12
        || names != sealed_names
        || nodes.len() != witnesses.len()
        || distinct_nodes.len() != witnesses.len()
    {
        return Err(
            "blind prior temporal proof does not cover the sealed 12 repositories".to_string(),
        );
    }
    let latest_witness_utc = witnesses
        .iter()
        .max_by_key(|witness| parse_utc_second(&witness.created_at_utc).ok())
        .ok_or("blind prior temporal proof has no witnesses")?
        .created_at_utc
        .clone();
    let mut proof = BlindPriorTemporalProof {
        contract: BLIND_TEMPORAL_CONTRACT.to_string(),
        source_seal_file_sha256: BLIND_SEAL_FILE_SHA256.to_string(),
        source_seal_commitment_sha256: BLIND_SEAL_COMMITMENT_SHA256.to_string(),
        selection_audit_file_sha256: BLIND_AUDIT_FILE_SHA256.to_string(),
        selection_recorded_at_utc: seal.selected_at.clone(),
        graphql_response_sha256: GRAPHQL_RESPONSE_SHA256.to_string(),
        graphql_query_sha256: sha256(BLIND_PRIOR_IDENTITIES_QUERY.as_bytes()),
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        witnesses,
        latest_witness_utc,
        proof_sha256: String::new(),
    };
    proof.proof_sha256 = sha256(
        &serde_json::to_vec(&proof)
            .map_err(|error| format!("failed to commit blind prior temporal proof: {error}"))?,
    );
    Ok(proof)
}

pub fn validate_blind_prior_temporal_proof(
    seal_path: &Path,
    graphql_response_bytes: &[u8],
    proof: &BlindPriorTemporalProof,
) -> Result<(), String> {
    if proof != &derive_blind_prior_temporal_proof(seal_path, graphql_response_bytes)? {
        return Err("blind prior temporal proof does not replay".to_string());
    }
    Ok(())
}

fn parse_graphql_nodes(bytes: &[u8]) -> Result<BTreeMap<String, GraphqlRepository>, String> {
    let response: GraphqlData = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid blind prior GraphQL projection: {error}"))?;
    if response.nodes.len() != 12 {
        return Err("blind prior GraphQL projection must contain 12 nodes".to_string());
    }
    let mut nodes = BTreeMap::new();
    for node in response.nodes {
        let node = node.ok_or("blind prior GraphQL repository node is missing")?;
        if node.database_id == 0 || nodes.insert(node.id.clone(), node).is_some() {
            return Err("blind prior GraphQL repository ID is invalid or repeated".to_string());
        }
    }
    Ok(nodes)
}

fn witness_selected(
    assessment: &SourceCandidateAssessment,
    component_id: &str,
    nodes: &BTreeMap<String, GraphqlRepository>,
    cutoff: i64,
) -> Result<BlindPriorRepositoryWitness, String> {
    let repository = &assessment.candidate.repository;
    let path = repository
        .strip_prefix("github.com/")
        .ok_or("blind prior candidate is not a GitHub repository")?;
    let selected_repository = format!("https://{repository}");
    if assessment
        .selected_repository
        .as_ref()
        .map(|selected| selected.repository.as_str())
        != Some(selected_repository.as_str())
    {
        return Err("blind prior selected repository differs from its candidate".to_string());
    }
    let expected_source = format!("https://api.github.com/repos/{path}");
    let raw_sources = assessment
        .evidence
        .iter()
        .filter(|evidence| evidence.kind == SourceAssessmentEvidenceKind::RawSource)
        .collect::<Vec<_>>();
    if raw_sources.len() != 1 || raw_sources[0].source != expected_source {
        return Err(
            "blind prior selected repository lacks its exact GitHub API response".to_string(),
        );
    }
    let raw = raw_sources[0];
    let identity: RawRepository = serde_json::from_str(&raw.payload)
        .map_err(|error| format!("invalid blind prior GitHub repository response: {error}"))?;
    let node = nodes
        .get(&identity.node_id)
        .ok_or("blind prior GitHub repository node is not in the first-party response")?;
    if identity.id == 0
        || identity.id != node.database_id
        || identity.created_at != node.created_at
        || identity.full_name != node.name_with_owner
        || parse_utc_second(&identity.created_at)? >= cutoff
    {
        return Err(format!(
            "blind prior repository identity or creation time differs: {repository}"
        ));
    }
    Ok(BlindPriorRepositoryWitness {
        canonical_repository: path.to_string(),
        source_component: component_id.to_string(),
        github_repository_id: identity.id,
        github_node_id: identity.node_id,
        created_at_utc: identity.created_at,
        raw_source_payload_sha256: raw.payload_sha256.clone(),
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v3_blind_temporal_tests.rs"]
mod tests;
