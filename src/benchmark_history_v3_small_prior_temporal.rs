use super::HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC;
use super::HistoricalV2ExclusionManifest;
use super::history_v3_time::parse_utc_second;
use super::non_blind_history::NonBlindSelectionPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

const POLICY_SHA256: &str = "43269a234b55ff406edf1893584418d0eefc3a79eada16764c2114fd7f88c44d";
const EXCLUSIONS_SHA256: &str = "74bccb100eb48ab87952bd7eec137b2285edbc68d2547715bc0e06a80e029f76";
const RESPONSE_SHA256: &str = "45d43ea544fe3ee6ecb407657f7bf56a918646b49d4ef74b8f4b673d536c0885";
const HARNESS_REVISION: &str = "25bd2b9a216df93e85bb46f741c0e2d1f422b111";
const PROBLEMS_REVISION: &str = "ef6a9dd13911566b6b01075ca121758c9f7b5c5f";
const GOLD_REVISION: &str = "d2db3d124c2ecf6534e6856fb65c2e57a98b052b";
const GOLD_TREE_OID: &str = "ecb744731cbd00242f93a067632c390b0ddf344d";
const CONTRACT: &str = "sniffbench-historical-v3-prior-research-synthetic-temporal-v1";

pub const SMALL_PRIOR_IDENTITIES_QUERY: &str =
    include_str!("benchmark_assets/historical-v3-small-prior-identities.graphql");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmallPriorRepositoryWitness {
    pub source_partition: String,
    pub repository: String,
    pub github_repository_id: u64,
    pub github_node_id: String,
    pub created_at_utc: String,
    pub source_revision: String,
    pub gold_tree_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmallPriorTemporalProof {
    pub contract: String,
    pub policy_sha256: String,
    pub exclusions_sha256: String,
    pub response_sha256: String,
    pub query_sha256: String,
    pub cutoff_utc: String,
    pub witnesses: Vec<SmallPriorRepositoryWitness>,
    pub proof_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlData {
    harness: Option<GraphqlRepository>,
    problems: Option<GraphqlRepository>,
    synthetic: Option<GraphqlRepository>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlRepository {
    id: String,
    #[serde(rename = "databaseId")]
    database_id: u64,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "nameWithOwner")]
    name_with_owner: String,
    source: Option<GraphqlObject>,
    gold: Option<GraphqlObject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlObject {
    #[serde(rename = "__typename")]
    kind: String,
    oid: Option<String>,
}

/// Proves existence of three repository IDs, not historical name continuity.
pub fn derive_small_prior_temporal_proof(
    policy_bytes: &[u8],
    exclusions_bytes: &[u8],
    response_bytes: &[u8],
    artifact_root: &Path,
) -> Result<SmallPriorTemporalProof, String> {
    if sha256(policy_bytes) != POLICY_SHA256 {
        return Err("small prior policy differs from the frozen source".to_string());
    }
    if sha256(response_bytes) != RESPONSE_SHA256 {
        return Err("small prior GraphQL projection differs from its frozen capture".to_string());
    }
    if sha256(exclusions_bytes) != EXCLUSIONS_SHA256 {
        return Err("small prior exclusions differ from the frozen source".to_string());
    }
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("invalid small prior policy: {error}"))?;
    validate_research_policy(&policy)?;
    let exclusions: HistoricalV2ExclusionManifest = serde_json::from_slice(exclusions_bytes)
        .map_err(|error| format!("invalid small prior exclusions: {error}"))?;
    validate_exclusion_membership(&exclusions, artifact_root)?;
    let data: GraphqlData = serde_json::from_slice(response_bytes)
        .map_err(|error| format!("invalid small prior GraphQL projection: {error}"))?;
    let witnesses = validate_response(data)?;
    let mut proof = SmallPriorTemporalProof {
        contract: CONTRACT.to_string(),
        policy_sha256: POLICY_SHA256.to_string(),
        exclusions_sha256: EXCLUSIONS_SHA256.to_string(),
        response_sha256: RESPONSE_SHA256.to_string(),
        query_sha256: sha256(SMALL_PRIOR_IDENTITIES_QUERY.as_bytes()),
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        witnesses,
        proof_sha256: String::new(),
    };
    proof.proof_sha256 = sha256(
        &serde_json::to_vec(&proof)
            .map_err(|error| format!("failed to commit small prior proof: {error}"))?,
    );
    Ok(proof)
}

pub fn validate_small_prior_temporal_proof(
    policy_bytes: &[u8],
    exclusions_bytes: &[u8],
    response_bytes: &[u8],
    artifact_root: &Path,
    proof: &SmallPriorTemporalProof,
) -> Result<(), String> {
    if proof
        != &derive_small_prior_temporal_proof(
            policy_bytes,
            exclusions_bytes,
            response_bytes,
            artifact_root,
        )?
    {
        return Err("small prior temporal proof does not replay".to_string());
    }
    Ok(())
}

fn validate_exclusion_membership(
    exclusions: &HistoricalV2ExclusionManifest,
    artifact_root: &Path,
) -> Result<(), String> {
    let partitions = exclusions
        .partitions
        .iter()
        .filter(|partition| {
            matches!(
                partition.partition.as_str(),
                "slopcodebench" | "synthetic-gold-v1"
            )
        })
        .collect::<Vec<_>>();
    if exclusions.schema_version != 1 || partitions.len() != 2 {
        return Err("small prior exclusion partitions are missing".to_string());
    }
    let research = partitions
        .iter()
        .find(|partition| partition.partition == "slopcodebench")
        .ok_or("SlopCodeBench exclusion partition is missing")?;
    if research.repositories != ["gabeorlanski/scb-problems", "sprocketlab/slop-code-bench"]
        || research.artifacts.len() != 1
        || research.artifacts[0].artifact_path != "sniffbench/non-blind-v1-selection-policy.json"
        || research.artifacts[0].artifact_sha256 != POLICY_SHA256
    {
        return Err("SlopCodeBench frozen prior membership changed".to_string());
    }
    let synthetic = partitions
        .iter()
        .find(|partition| partition.partition == "synthetic-gold-v1")
        .ok_or("synthetic gold exclusion partition is missing")?;
    if synthetic.repositories != ["trysniff/sniff"] || synthetic.artifacts.len() != 12 {
        return Err("synthetic gold frozen prior membership changed".to_string());
    }
    let root = fs::canonicalize(artifact_root)
        .map_err(|error| format!("failed to resolve small prior artifact root: {error}"))?;
    let toplevel = git(&root, &["rev-parse", "--show-toplevel"])?;
    let toplevel = std::str::from_utf8(&toplevel)
        .map_err(|error| format!("invalid Git root encoding: {error}"))?;
    let toplevel = fs::canonicalize(toplevel.trim())
        .map_err(|error| format!("failed to resolve Git root: {error}"))?;
    if toplevel != root {
        return Err("small prior artifact root is not the Git repository root".to_string());
    }
    let tree = git(&root, &["rev-parse", "HEAD:gold_fixtures/repo"])?;
    if tree != format!("{GOLD_TREE_OID}\n").as_bytes() {
        return Err("synthetic gold Git tree differs from the pinned source".to_string());
    }
    let mut paths = BTreeSet::new();
    for artifact in &synthetic.artifacts {
        if !artifact.artifact_path.starts_with("gold_fixtures/repo/")
            || !paths.insert(artifact.artifact_path.as_str())
        {
            return Err("synthetic gold artifact path changed".to_string());
        }
        let object = format!("HEAD:{}", artifact.artifact_path);
        let bytes = git(&root, &["show", &object])?;
        if sha256(&bytes) != artifact.artifact_sha256 {
            return Err(format!(
                "synthetic gold artifact differs: {}",
                artifact.artifact_path
            ));
        }
    }
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run Git for small prior source: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed to resolve small prior Git source: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn validate_research_policy(policy: &NonBlindSelectionPolicy) -> Result<(), String> {
    if policy.policy_id != "sniffbench-non-blind-v1" {
        return Err("small prior source policy changed".to_string());
    }
    let source = policy
        .research_trajectories
        .required_sources
        .iter()
        .find(|source| {
            source.get("source_id").and_then(serde_json::Value::as_str) == Some("slopcodebench")
        })
        .ok_or("SlopCodeBench source is missing from the frozen policy")?;
    let text = |key: &str| source.get(key).and_then(serde_json::Value::as_str);
    if text("harness_repository") != Some("https://github.com/SprocketLab/slop-code-bench")
        || text("harness_revision") != Some(HARNESS_REVISION)
        || text("problem_repository") != Some("https://github.com/gabeorlanski/scb-problems")
        || text("problem_revision") != Some(PROBLEMS_REVISION)
    {
        return Err("SlopCodeBench policy repositories or revisions changed".to_string());
    }
    Ok(())
}

fn validate_response(data: GraphqlData) -> Result<Vec<SmallPriorRepositoryWitness>, String> {
    let cutoff = parse_utc_second(HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC)?;
    let mut witnesses = vec![
        witness(
            data.harness
                .ok_or("SlopCodeBench harness repository is missing")?,
            "slopcodebench",
            "SprocketLab/slop-code-bench",
            HARNESS_REVISION,
            None,
            cutoff,
        )?,
        witness(
            data.problems
                .ok_or("SlopCodeBench problem repository is missing")?,
            "slopcodebench",
            "gabeorlanski/scb-problems",
            PROBLEMS_REVISION,
            None,
            cutoff,
        )?,
        witness(
            data.synthetic
                .ok_or("Sniff synthetic repository is missing")?,
            "synthetic-gold-v1",
            "trysniff/sniff",
            GOLD_REVISION,
            Some(GOLD_TREE_OID),
            cutoff,
        )?,
    ];
    let unique_ids = witnesses
        .iter()
        .map(|witness| witness.github_repository_id)
        .collect::<BTreeSet<_>>();
    let unique_nodes = witnesses
        .iter()
        .map(|witness| witness.github_node_id.as_str())
        .collect::<BTreeSet<_>>();
    if unique_ids.len() != 3 || unique_nodes.len() != 3 {
        return Err("small prior repositories do not have distinct GitHub IDs".to_string());
    }
    witnesses.sort_by(|left, right| left.repository.cmp(&right.repository));
    Ok(witnesses)
}

fn witness(
    repository: GraphqlRepository,
    partition: &str,
    expected_name: &str,
    expected_revision: &str,
    expected_gold_tree: Option<&str>,
    cutoff: i64,
) -> Result<SmallPriorRepositoryWitness, String> {
    let source = repository
        .source
        .ok_or("small prior source revision is missing")?;
    if repository.name_with_owner != expected_name
        || repository.database_id == 0
        || repository.id.trim().is_empty()
        || source.kind != "Commit"
        || source.oid.as_deref() != Some(expected_revision)
        || parse_utc_second(&repository.created_at)? >= cutoff
    {
        return Err(format!(
            "small prior repository identity or source changed: {expected_name}"
        ));
    }
    match (repository.gold, expected_gold_tree) {
        (None, None) => {}
        (Some(gold), Some(expected))
            if gold.kind == "Tree" && gold.oid.as_deref() == Some(expected) => {}
        _ => return Err(format!("small prior gold tree changed: {expected_name}")),
    }
    Ok(SmallPriorRepositoryWitness {
        source_partition: partition.to_string(),
        repository: expected_name.to_ascii_lowercase(),
        github_repository_id: repository.database_id,
        github_node_id: repository.id,
        created_at_utc: repository.created_at,
        source_revision: expected_revision.to_string(),
        gold_tree_oid: expected_gold_tree.map(str::to_string),
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v3_small_prior_temporal_tests.rs"]
mod tests;
