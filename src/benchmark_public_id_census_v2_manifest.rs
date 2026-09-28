use super::{
    PUBLIC_ID_CENSUS_V2_PUBLIC_POLICY_SHA256, PublicIdCensusV2NullRecord, PublicIdCensusV2Policy,
    PublicIdCensusV2Replay, public_id_census_v2_policy_sha256, replay_public_id_census_v2_stream,
    validate_public_id_census_v2_policy,
};
use crate::benchmark::release::public_id_census::replay::valid_utc_timestamp;
use crate::benchmark::release::public_id_census::{
    PublicIdCensusExchange, PublicIdCensusExchangeCommitment, PublicIdCensusFrameCommitment,
    PublicIdCensusPreflight, read_public_id_census_artifact,
};
use same_file::Handle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

pub const PUBLIC_ID_CENSUS_V2_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const PUBLIC_ID_CENSUS_V2_NULL_LEDGER_SCHEMA_VERSION: u32 = 1;
pub const PUBLIC_ID_CENSUS_V2_ARTIFACT_CONTRACT_SHA256: &str =
    "5a34b709a8a20d06b1170c1c893bf2ea54bff392837fe77cca1389e265ae2973";
pub const PUBLIC_ID_CENSUS_V2_ARTIFACT_CONTRACT_COMMIT_SHA: &str =
    "e97bd5c0f2efc90b1f37ea0f74712d4ec5f9014d";
const ARTIFACT_CONTRACT: &str =
    include_str!("../sniffbench/historical-v3-id-census-v2/artifact-contract.json");
const MAX_PREFLIGHT_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RAW_EXCHANGE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FRAME_BYTES: u64 = 512 * 1024 * 1024;
const MAX_NULL_LEDGER_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactContract {
    schema_version: u32,
    source_policy_sha256: String,
    manifest_schema_version: u32,
    null_ledger_schema_version: u32,
    manifest_encoding: String,
    manifest_digest: String,
    null_ledger_encoding: String,
    null_ledger_reconciliation: String,
    frame_reconciliation: String,
    source_commitment: String,
    live_precondition: String,
}

pub fn validate_bundled_public_id_census_v2_artifact_contract() -> Result<(), String> {
    let bytes = ARTIFACT_CONTRACT.replace("\r\n", "\n").into_bytes();
    if sha256(&bytes) != PUBLIC_ID_CENSUS_V2_ARTIFACT_CONTRACT_SHA256 {
        return Err("public-ID census v2 artifact contract bytes changed".to_string());
    }
    let contract: ArtifactContract = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid public-ID census v2 artifact contract: {error}"))?;
    if contract.schema_version != 1
        || contract.source_policy_sha256 != PUBLIC_ID_CENSUS_V2_PUBLIC_POLICY_SHA256
        || contract.manifest_schema_version != PUBLIC_ID_CENSUS_V2_MANIFEST_SCHEMA_VERSION
        || contract.null_ledger_schema_version != PUBLIC_ID_CENSUS_V2_NULL_LEDGER_SCHEMA_VERSION
        || [
            contract.manifest_encoding,
            contract.manifest_digest,
            contract.null_ledger_encoding,
            contract.null_ledger_reconciliation,
            contract.frame_reconciliation,
            contract.source_commitment,
            contract.live_precondition,
        ]
        .iter()
        .any(String::is_empty)
    {
        return Err("public-ID census v2 artifact contract is incompatible".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusV2NullLedger {
    pub schema_version: u32,
    pub records: Vec<PublicIdCensusV2NullRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusV2ContractPreflight {
    pub public_contract_url: String,
    pub fetched_contract: String,
    pub fetched_contract_sha256: String,
    pub fetched_at_utc: String,
    pub response_status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusV2Manifest {
    pub schema_version: u32,
    pub policy: PublicIdCensusV2Policy,
    pub policy_sha256: String,
    pub preflight: PublicIdCensusPreflight,
    pub preflight_artifact_path: String,
    pub preflight_artifact_sha256: String,
    pub contract_preflight: PublicIdCensusV2ContractPreflight,
    pub contract_preflight_artifact_path: String,
    pub contract_preflight_artifact_sha256: String,
    pub exchanges: Vec<PublicIdCensusExchangeCommitment>,
    pub frames: Vec<PublicIdCensusFrameCommitment>,
    pub null_ledger_artifact_path: String,
    pub null_ledger_artifact_sha256: String,
    pub listed_repository_count: usize,
    pub resolved_in_window_count: usize,
    pub resolved_ineligible_count: usize,
    pub probe_only_null_count: usize,
    pub crawled_null_count: usize,
    pub name_disagreement_count: usize,
    pub lower_boundary_repository_id: u64,
    pub upper_boundary_repository_id: u64,
    pub manifest_sha256: String,
}

impl PublicIdCensusV2Manifest {
    pub fn computed_manifest_sha256(&self) -> Result<String, String> {
        let mut unsigned = self.clone();
        unsigned.manifest_sha256.clear();
        let bytes = serde_json::to_vec(&unsigned)
            .map_err(|error| format!("failed to encode public-ID census v2 commitment: {error}"))?;
        Ok(sha256(&bytes))
    }
}

pub fn public_id_census_v2_manifest_bytes(
    manifest: &PublicIdCensusV2Manifest,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(manifest)
        .map_err(|error| format!("failed to encode public-ID census v2 manifest: {error}"))
}

pub fn read_public_id_census_v2_manifest(
    artifact_root: &Path,
) -> Result<PublicIdCensusV2Manifest, String> {
    let bytes = read_artifact(artifact_root, "manifest.json", MAX_MANIFEST_BYTES)?;
    let manifest: PublicIdCensusV2Manifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid public-ID census v2 manifest: {error}"))?;
    if bytes != public_id_census_v2_manifest_bytes(&manifest)? {
        return Err("public-ID census v2 manifest bytes are not canonical".to_string());
    }
    validate_public_id_census_v2_manifest(&manifest, artifact_root)?;
    Ok(manifest)
}

pub fn public_id_census_v2_null_ledger_bytes(
    replay: &PublicIdCensusV2Replay,
) -> Result<Vec<u8>, String> {
    if replay
        .null_ledger
        .windows(2)
        .any(|pair| pair[0].repository_id >= pair[1].repository_id)
        || replay
            .probe_only_null_count
            .checked_add(replay.crawled_null_count)
            != Some(replay.null_ledger.len())
        || replay.crawled_null_count
            != replay
                .null_ledger
                .iter()
                .filter(|record| record.crawled)
                .count()
    {
        return Err("public-ID census v2 null ledger is not canonical".to_string());
    }
    serde_json::to_vec(&PublicIdCensusV2NullLedger {
        schema_version: PUBLIC_ID_CENSUS_V2_NULL_LEDGER_SCHEMA_VERSION,
        records: replay.null_ledger.clone(),
    })
    .map_err(|error| format!("failed to encode public-ID census v2 null ledger: {error}"))
}

pub fn prepare_public_id_census_v2_manifest(
    policy: PublicIdCensusV2Policy,
    preflight: PublicIdCensusPreflight,
    contract_preflight: PublicIdCensusV2ContractPreflight,
    artifact_root: &Path,
    exchange_paths: &[String],
    frame_paths: &BTreeMap<String, String>,
) -> Result<PublicIdCensusV2Manifest, String> {
    validate_bundled_public_id_census_v2_artifact_contract()?;
    validate_public_id_census_v2_policy(&policy)?;
    if exchange_paths.is_empty() || frame_paths.len() != policy.languages.len() {
        return Err("public-ID census v2 lacks complete source artifacts".to_string());
    }
    let preflight_bytes = read_artifact(artifact_root, "preflight.json", MAX_PREFLIGHT_BYTES)?;
    let recorded_preflight: PublicIdCensusPreflight = serde_json::from_slice(&preflight_bytes)
        .map_err(|error| format!("invalid public-ID census v2 preflight: {error}"))?;
    if recorded_preflight != preflight {
        return Err("public-ID census v2 preflight differs from replay".to_string());
    }
    let contract_preflight_bytes = read_artifact(
        artifact_root,
        "contract-preflight.json",
        MAX_PREFLIGHT_BYTES,
    )?;
    let recorded_contract_preflight: PublicIdCensusV2ContractPreflight =
        serde_json::from_slice(&contract_preflight_bytes)
            .map_err(|error| format!("invalid public-ID census v2 contract preflight: {error}"))?;
    if recorded_contract_preflight != contract_preflight {
        return Err("public-ID census v2 contract preflight differs from replay".to_string());
    }
    validate_contract_preflight(&contract_preflight)?;
    let exchanges = exchange_paths
        .iter()
        .enumerate()
        .map(|(sequence, path)| {
            if path != &format!("raw/{sequence:08}.json") {
                return Err("public-ID census v2 raw path is not canonical".to_string());
            }
            let bytes = read_artifact(artifact_root, path, MAX_RAW_EXCHANGE_BYTES)?;
            Ok(PublicIdCensusExchangeCommitment {
                sequence,
                artifact_path: path.clone(),
                artifact_sha256: sha256(&bytes),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let derived = replay_from_raw(&policy, &preflight, artifact_root, &exchanges)?;
    let frames = policy
        .languages
        .iter()
        .map(|language| {
            let path = frame_paths
                .get(language)
                .ok_or("public-ID census v2 frame path is missing")?;
            if path != &format!("frames/{}.csv", language.to_ascii_lowercase()) {
                return Err("public-ID census v2 frame path is not canonical".to_string());
            }
            let bytes = read_artifact(artifact_root, path, MAX_FRAME_BYTES)?;
            if derived.frames.get(language) != Some(&bytes) {
                return Err("public-ID census v2 frame does not replay".to_string());
            }
            Ok(PublicIdCensusFrameCommitment {
                language: language.clone(),
                frame_id: policy.frame_ids[language].clone(),
                artifact_path: path.clone(),
                artifact_sha256: sha256(&bytes),
                repository_count: frame_repository_count(&bytes)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    ensure_exact_files(
        &artifact_root.join("raw"),
        &exchanges
            .iter()
            .map(|exchange| format!("{:08}.json", exchange.sequence))
            .collect::<Vec<_>>(),
    )?;
    ensure_exact_files(
        &artifact_root.join("frames"),
        &policy
            .languages
            .iter()
            .map(|language| format!("{}.csv", language.to_ascii_lowercase()))
            .collect::<Vec<_>>(),
    )?;
    let ledger_bytes = read_artifact(artifact_root, "null-ledger.json", MAX_NULL_LEDGER_BYTES)?;
    if ledger_bytes != public_id_census_v2_null_ledger_bytes(&derived)? {
        return Err("public-ID census v2 null ledger does not replay".to_string());
    }
    let mut manifest = PublicIdCensusV2Manifest {
        schema_version: PUBLIC_ID_CENSUS_V2_MANIFEST_SCHEMA_VERSION,
        policy_sha256: public_id_census_v2_policy_sha256(&policy)?,
        policy,
        preflight,
        preflight_artifact_path: "preflight.json".to_string(),
        preflight_artifact_sha256: sha256(&preflight_bytes),
        contract_preflight,
        contract_preflight_artifact_path: "contract-preflight.json".to_string(),
        contract_preflight_artifact_sha256: sha256(&contract_preflight_bytes),
        exchanges,
        frames,
        null_ledger_artifact_path: "null-ledger.json".to_string(),
        null_ledger_artifact_sha256: sha256(&ledger_bytes),
        listed_repository_count: derived.listed_repository_count,
        resolved_in_window_count: derived.resolved_in_window_count,
        resolved_ineligible_count: derived.resolved_ineligible_count,
        probe_only_null_count: derived.probe_only_null_count,
        crawled_null_count: derived.crawled_null_count,
        name_disagreement_count: derived.name_disagreement_count,
        lower_boundary_repository_id: derived.lower_boundary_repository_id,
        upper_boundary_repository_id: derived.upper_boundary_repository_id,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest.computed_manifest_sha256()?;
    validate_public_id_census_v2_manifest(&manifest, artifact_root)?;
    Ok(manifest)
}

pub fn validate_public_id_census_v2_manifest(
    manifest: &PublicIdCensusV2Manifest,
    artifact_root: &Path,
) -> Result<(), String> {
    validate_bundled_public_id_census_v2_artifact_contract()?;
    if manifest.schema_version != PUBLIC_ID_CENSUS_V2_MANIFEST_SCHEMA_VERSION {
        return Err("public-ID census v2 manifest schema is unsupported".to_string());
    }
    if artifact_root
        .join("manifest.json")
        .try_exists()
        .map_err(|error| format!("failed to inspect public-ID census v2 manifest: {error}"))?
        && read_artifact(artifact_root, "manifest.json", MAX_MANIFEST_BYTES)?
            != public_id_census_v2_manifest_bytes(manifest)?
    {
        return Err("public-ID census v2 manifest file bytes changed".to_string());
    }
    validate_public_id_census_v2_policy(&manifest.policy)?;
    for digest in [
        &manifest.policy_sha256,
        &manifest.preflight_artifact_sha256,
        &manifest.contract_preflight_artifact_sha256,
        &manifest.null_ledger_artifact_sha256,
        &manifest.manifest_sha256,
    ] {
        require_sha256(digest)?;
    }
    if manifest.policy_sha256 != public_id_census_v2_policy_sha256(&manifest.policy)?
        || manifest.manifest_sha256 != manifest.computed_manifest_sha256()?
        || manifest.preflight_artifact_path != "preflight.json"
        || manifest.contract_preflight_artifact_path != "contract-preflight.json"
        || manifest.null_ledger_artifact_path != "null-ledger.json"
        || manifest.exchanges.is_empty()
        || manifest.frames.len() != manifest.policy.languages.len()
    {
        return Err("public-ID census v2 manifest commitment changed".to_string());
    }
    let mut identities = HashSet::new();
    for path in [
        &manifest.preflight_artifact_path,
        &manifest.contract_preflight_artifact_path,
        &manifest.null_ledger_artifact_path,
    ] {
        let handle = artifact_handle(artifact_root, path)?;
        if !identities.insert(handle) {
            return Err("public-ID census v2 artifacts alias one file".to_string());
        }
    }
    let preflight_bytes = read_artifact(
        artifact_root,
        &manifest.preflight_artifact_path,
        MAX_PREFLIGHT_BYTES,
    )?;
    let recorded_preflight: PublicIdCensusPreflight = serde_json::from_slice(&preflight_bytes)
        .map_err(|error| format!("invalid public-ID census v2 preflight: {error}"))?;
    if recorded_preflight != manifest.preflight
        || sha256(&preflight_bytes) != manifest.preflight_artifact_sha256
    {
        return Err("public-ID census v2 preflight commitment changed".to_string());
    }
    let contract_preflight_bytes = read_artifact(
        artifact_root,
        &manifest.contract_preflight_artifact_path,
        MAX_PREFLIGHT_BYTES,
    )?;
    let recorded_contract_preflight: PublicIdCensusV2ContractPreflight =
        serde_json::from_slice(&contract_preflight_bytes)
            .map_err(|error| format!("invalid public-ID census v2 contract preflight: {error}"))?;
    if recorded_contract_preflight != manifest.contract_preflight
        || sha256(&contract_preflight_bytes) != manifest.contract_preflight_artifact_sha256
    {
        return Err("public-ID census v2 contract preflight commitment changed".to_string());
    }
    validate_contract_preflight(&manifest.contract_preflight)?;
    for (sequence, exchange) in manifest.exchanges.iter().enumerate() {
        require_sha256(&exchange.artifact_sha256)?;
        if exchange.sequence != sequence
            || exchange.artifact_path != format!("raw/{sequence:08}.json")
            || !identities.insert(artifact_handle(artifact_root, &exchange.artifact_path)?)
        {
            return Err("public-ID census v2 raw exchange identity changed".to_string());
        }
    }
    for (language, frame) in manifest.policy.languages.iter().zip(&manifest.frames) {
        require_sha256(&frame.artifact_sha256)?;
        if frame.language != *language
            || frame.frame_id != manifest.policy.frame_ids[language]
            || frame.artifact_path != format!("frames/{}.csv", language.to_ascii_lowercase())
            || !identities.insert(artifact_handle(artifact_root, &frame.artifact_path)?)
        {
            return Err("public-ID census v2 frame identity changed".to_string());
        }
    }
    ensure_exact_files(
        &artifact_root.join("raw"),
        &manifest
            .exchanges
            .iter()
            .map(|exchange| format!("{:08}.json", exchange.sequence))
            .collect::<Vec<_>>(),
    )?;
    ensure_exact_files(
        &artifact_root.join("frames"),
        &manifest
            .policy
            .languages
            .iter()
            .map(|language| format!("{}.csv", language.to_ascii_lowercase()))
            .collect::<Vec<_>>(),
    )?;
    let first_exchange: PublicIdCensusExchange = serde_json::from_slice(&read_artifact(
        artifact_root,
        &manifest.exchanges[0].artifact_path,
        MAX_RAW_EXCHANGE_BYTES,
    )?)
    .map_err(|error| format!("invalid public-ID census v2 first exchange: {error}"))?;
    if first_exchange.received_at_utc < manifest.contract_preflight.fetched_at_utc
        || first_exchange
            .failed_attempts
            .iter()
            .any(|attempt| attempt.received_at_utc < manifest.contract_preflight.fetched_at_utc)
    {
        return Err("public-ID census v2 source request preceded contract preflight".to_string());
    }
    let derived = replay_from_raw(
        &manifest.policy,
        &manifest.preflight,
        artifact_root,
        &manifest.exchanges,
    )?;
    if manifest.listed_repository_count != derived.listed_repository_count
        || manifest.resolved_in_window_count != derived.resolved_in_window_count
        || manifest.resolved_ineligible_count != derived.resolved_ineligible_count
        || manifest.probe_only_null_count != derived.probe_only_null_count
        || manifest.crawled_null_count != derived.crawled_null_count
        || manifest.name_disagreement_count != derived.name_disagreement_count
        || manifest.lower_boundary_repository_id != derived.lower_boundary_repository_id
        || manifest.upper_boundary_repository_id != derived.upper_boundary_repository_id
    {
        return Err("public-ID census v2 manifest counts do not replay".to_string());
    }
    let ledger_bytes = read_artifact(
        artifact_root,
        &manifest.null_ledger_artifact_path,
        MAX_NULL_LEDGER_BYTES,
    )?;
    if sha256(&ledger_bytes) != manifest.null_ledger_artifact_sha256
        || ledger_bytes != public_id_census_v2_null_ledger_bytes(&derived)?
    {
        return Err("public-ID census v2 null ledger commitment changed".to_string());
    }
    for frame in &manifest.frames {
        let bytes = read_artifact(artifact_root, &frame.artifact_path, MAX_FRAME_BYTES)?;
        if sha256(&bytes) != frame.artifact_sha256
            || derived.frames.get(&frame.language) != Some(&bytes)
            || frame.repository_count != frame_repository_count(&bytes)?
        {
            return Err("public-ID census v2 frame commitment changed".to_string());
        }
    }
    let frame_count = manifest.frames.iter().try_fold(0_usize, |sum, frame| {
        sum.checked_add(frame.repository_count)
            .ok_or("public-ID census v2 frame count overflowed".to_string())
    })?;
    if manifest
        .resolved_in_window_count
        .checked_sub(manifest.resolved_ineligible_count)
        != Some(frame_count)
        || manifest.crawled_null_count > manifest.listed_repository_count
    {
        return Err("public-ID census v2 manifest counts do not reconcile".to_string());
    }
    Ok(())
}

fn replay_from_raw(
    policy: &PublicIdCensusV2Policy,
    preflight: &PublicIdCensusPreflight,
    artifact_root: &Path,
    commitments: &[PublicIdCensusExchangeCommitment],
) -> Result<PublicIdCensusV2Replay, String> {
    let exchanges = commitments.iter().map(|commitment| {
        let bytes = read_artifact(
            artifact_root,
            &commitment.artifact_path,
            MAX_RAW_EXCHANGE_BYTES,
        )?;
        if sha256(&bytes) != commitment.artifact_sha256 {
            return Err("public-ID census v2 raw exchange commitment changed".to_string());
        }
        serde_json::from_slice::<PublicIdCensusExchange>(&bytes)
            .map_err(|error| format!("invalid public-ID census v2 raw exchange: {error}"))
    });
    replay_public_id_census_v2_stream(policy, preflight, exchanges)
}

fn read_artifact(root: &Path, relative: &str, limit: u64) -> Result<Vec<u8>, String> {
    read_public_id_census_artifact(root, relative, limit)
}

fn artifact_handle(root: &Path, relative: &str) -> Result<Handle, String> {
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|error| format!("failed to resolve public-ID census v2 root: {error}"))?;
    let path = std::fs::canonicalize(canonical_root.join(relative))
        .map_err(|error| format!("failed to resolve public-ID census v2 artifact: {error}"))?;
    if !path.starts_with(canonical_root) {
        return Err("public-ID census v2 artifact escapes root".to_string());
    }
    Handle::from_path(path)
        .map_err(|error| format!("failed to identify public-ID census v2 artifact: {error}"))
}

fn ensure_exact_files(directory: &Path, expected: &[String]) -> Result<(), String> {
    let mut actual = fs::read_dir(directory)
        .map_err(|error| format!("failed to list public-ID census v2 artifacts: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| {
                format!("failed to inspect public-ID census v2 artifact: {error}")
            })?;
            if !entry
                .file_type()
                .map_err(|error| format!("failed to type public-ID census v2 artifact: {error}"))?
                .is_file()
            {
                return Err("public-ID census v2 artifact is not a plain file".to_string());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "public-ID census v2 artifact filename is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut expected = expected.to_vec();
    actual.sort();
    expected.sort();
    if actual != expected {
        return Err("public-ID census v2 artifact directory has uncommitted files".to_string());
    }
    Ok(())
}

fn frame_repository_count(frame: &[u8]) -> Result<usize, String> {
    if !frame.starts_with(b"repo,metadata\n") || !frame.ends_with(b"\n") {
        return Err("public-ID census v2 frame has invalid CSV envelope".to_string());
    }
    Ok(frame.iter().filter(|byte| **byte == b'\n').count() - 1)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn validate_contract_preflight(
    receipt: &PublicIdCensusV2ContractPreflight,
) -> Result<(), String> {
    valid_utc_timestamp(&receipt.fetched_at_utc)?;
    let prefix = "https://raw.githubusercontent.com/trysniff/sniff/";
    let suffix = "/sniffbench/historical-v3-id-census-v2/artifact-contract.json";
    let commit = receipt
        .public_contract_url
        .strip_prefix(prefix)
        .and_then(|url| url.strip_suffix(suffix))
        .ok_or("public-ID census v2 contract URL is not immutable".to_string())?;
    if commit != PUBLIC_ID_CENSUS_V2_ARTIFACT_CONTRACT_COMMIT_SHA
        || receipt.response_status != 200
        || receipt.fetched_contract_sha256 != PUBLIC_ID_CENSUS_V2_ARTIFACT_CONTRACT_SHA256
        || receipt.fetched_contract != ARTIFACT_CONTRACT.replace("\r\n", "\n")
    {
        return Err("public-ID census v2 public contract preflight changed".to_string());
    }
    Ok(())
}

fn require_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("public-ID census v2 manifest has an invalid SHA-256".to_string());
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_public_id_census_v2_manifest_tests.rs"]
mod tests;
