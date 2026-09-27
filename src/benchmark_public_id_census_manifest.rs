use super::{
    PUBLIC_ID_CENSUS_MAX_FRAME_BYTES, PublicIdCensusExchange, PublicIdCensusPolicy,
    PublicIdCensusPreflight, PublicIdCensusReplay, public_id_census_policy_sha256,
    replay_public_id_census_stream, validate_public_id_census_policy,
};
use same_file::Handle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub const PUBLIC_ID_CENSUS_MANIFEST_SCHEMA_VERSION: u32 = 2;
pub(super) const MAX_RAW_EXCHANGE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PREFLIGHT_BYTES: u64 = 1024 * 1024;
const MAX_FRAME_BYTES: u64 = PUBLIC_ID_CENSUS_MAX_FRAME_BYTES as u64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusExchangeCommitment {
    pub sequence: usize,
    pub artifact_path: String,
    pub artifact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusFrameCommitment {
    pub language: String,
    pub frame_id: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub repository_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusManifest {
    pub schema_version: u32,
    pub policy: PublicIdCensusPolicy,
    pub policy_sha256: String,
    pub preflight: PublicIdCensusPreflight,
    pub preflight_artifact_path: String,
    pub preflight_artifact_sha256: String,
    pub exchanges: Vec<PublicIdCensusExchangeCommitment>,
    pub frames: Vec<PublicIdCensusFrameCommitment>,
    pub listed_repository_count: usize,
    pub in_window_repository_count: usize,
    pub excluded_repository_count: usize,
    pub name_disagreement_count: usize,
    pub lower_boundary_repository_id: u64,
    pub upper_boundary_repository_id: u64,
    pub manifest_sha256: String,
}

impl PublicIdCensusManifest {
    pub fn computed_manifest_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u32,
            policy: &'a PublicIdCensusPolicy,
            policy_sha256: &'a str,
            preflight: &'a PublicIdCensusPreflight,
            preflight_artifact_path: &'a str,
            preflight_artifact_sha256: &'a str,
            exchanges: &'a [PublicIdCensusExchangeCommitment],
            frames: &'a [PublicIdCensusFrameCommitment],
            listed_repository_count: usize,
            in_window_repository_count: usize,
            excluded_repository_count: usize,
            name_disagreement_count: usize,
            lower_boundary_repository_id: u64,
            upper_boundary_repository_id: u64,
        }
        let bytes = serde_json::to_vec(&Commitment {
            schema_version: self.schema_version,
            policy: &self.policy,
            policy_sha256: &self.policy_sha256,
            preflight: &self.preflight,
            preflight_artifact_path: &self.preflight_artifact_path,
            preflight_artifact_sha256: &self.preflight_artifact_sha256,
            exchanges: &self.exchanges,
            frames: &self.frames,
            listed_repository_count: self.listed_repository_count,
            in_window_repository_count: self.in_window_repository_count,
            excluded_repository_count: self.excluded_repository_count,
            name_disagreement_count: self.name_disagreement_count,
            lower_boundary_repository_id: self.lower_boundary_repository_id,
            upper_boundary_repository_id: self.upper_boundary_repository_id,
        })
        .map_err(|error| format!("failed to commit public-ID census manifest: {error}"))?;
        Ok(sha256(&bytes))
    }
}

pub fn prepare_public_id_census_manifest(
    policy: PublicIdCensusPolicy,
    preflight: PublicIdCensusPreflight,
    artifact_root: &Path,
    exchange_paths: &[String],
    frame_paths: &BTreeMap<String, String>,
) -> Result<PublicIdCensusManifest, String> {
    validate_public_id_census_policy(&policy)?;
    if exchange_paths.is_empty() || frame_paths.len() != policy.languages.len() {
        return Err("public-ID census manifest lacks its complete source artifacts".to_string());
    }
    let root = canonical_root(artifact_root)?;
    let preflight_bytes = read_artifact(&root, "preflight.json", MAX_PREFLIGHT_BYTES)?;
    let recorded_preflight: PublicIdCensusPreflight = serde_json::from_slice(&preflight_bytes)
        .map_err(|error| format!("invalid public-ID census preflight artifact: {error}"))?;
    if recorded_preflight != preflight {
        return Err("public-ID census preflight artifact differs from replay".to_string());
    }
    let exchanges = exchange_paths
        .iter()
        .enumerate()
        .map(|(sequence, path)| {
            let bytes = read_artifact(&root, path, MAX_RAW_EXCHANGE_BYTES)?;
            Ok(PublicIdCensusExchangeCommitment {
                sequence,
                artifact_path: path.clone(),
                artifact_sha256: sha256(&bytes),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let derived = replay_from_committed_exchanges(&policy, &preflight, &root, &exchanges)?;
    let frames = policy
        .languages
        .iter()
        .map(|language| {
            let path = frame_paths
                .get(language)
                .ok_or("public-ID census frame path is missing")?;
            let bytes = read_artifact(&root, path, MAX_FRAME_BYTES)?;
            let expected = derived
                .frames
                .get(language)
                .ok_or("public-ID census replay omitted a language frame")?;
            if &bytes != expected {
                return Err(
                    "public-ID census frame bytes do not replay from raw exchanges".to_string(),
                );
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
    let mut manifest = PublicIdCensusManifest {
        schema_version: PUBLIC_ID_CENSUS_MANIFEST_SCHEMA_VERSION,
        policy_sha256: public_id_census_policy_sha256(&policy)?,
        policy,
        preflight,
        preflight_artifact_path: "preflight.json".to_string(),
        preflight_artifact_sha256: sha256(&preflight_bytes),
        exchanges,
        frames,
        listed_repository_count: derived.listed_repository_count,
        in_window_repository_count: derived.in_window_repository_count,
        excluded_repository_count: derived.excluded_repository_count,
        name_disagreement_count: derived.name_disagreement_count,
        lower_boundary_repository_id: derived.lower_boundary_repository_id,
        upper_boundary_repository_id: derived.upper_boundary_repository_id,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest.computed_manifest_sha256()?;
    validate_public_id_census_manifest(&manifest, artifact_root)?;
    Ok(manifest)
}

pub fn validate_public_id_census_manifest(
    manifest: &PublicIdCensusManifest,
    artifact_root: &Path,
) -> Result<(), String> {
    if manifest.schema_version != PUBLIC_ID_CENSUS_MANIFEST_SCHEMA_VERSION {
        return Err("public-ID census manifest schema is unsupported".to_string());
    }
    validate_public_id_census_policy(&manifest.policy)?;
    require_sha256(&manifest.policy_sha256)?;
    require_sha256(&manifest.manifest_sha256)?;
    require_sha256(&manifest.preflight_artifact_sha256)?;
    if manifest.policy_sha256 != public_id_census_policy_sha256(&manifest.policy)?
        || manifest.manifest_sha256 != manifest.computed_manifest_sha256()?
        || manifest.exchanges.is_empty()
        || manifest.frames.len() != manifest.policy.languages.len()
    {
        return Err("public-ID census manifest commitment changed".to_string());
    }
    let root = canonical_root(artifact_root)?;
    let mut paths = HashSet::new();
    let mut frame_files = HashSet::new();
    if manifest.preflight_artifact_path != "preflight.json" {
        return Err("public-ID census preflight artifact path changed".to_string());
    }
    let preflight_bytes = read_artifact(
        &root,
        &manifest.preflight_artifact_path,
        MAX_PREFLIGHT_BYTES,
    )?;
    let recorded_preflight: PublicIdCensusPreflight = serde_json::from_slice(&preflight_bytes)
        .map_err(|error| format!("invalid public-ID census preflight artifact: {error}"))?;
    if sha256(&preflight_bytes) != manifest.preflight_artifact_sha256
        || recorded_preflight != manifest.preflight
    {
        return Err("public-ID census preflight artifact commitment changed".to_string());
    }
    paths.insert(resolve_artifact(&root, &manifest.preflight_artifact_path)?);
    for (sequence, exchange) in manifest.exchanges.iter().enumerate() {
        require_sha256(&exchange.artifact_sha256)?;
        let resolved = resolve_artifact(&root, &exchange.artifact_path)?;
        if exchange.sequence != sequence || !paths.insert(resolved) {
            return Err("public-ID census exchange paths or sequence changed".to_string());
        }
    }
    for (language, frame) in manifest.policy.languages.iter().zip(&manifest.frames) {
        require_sha256(&frame.artifact_sha256)?;
        let resolved = resolve_artifact(&root, &frame.artifact_path)?;
        let identity = Handle::from_path(&resolved)
            .map_err(|error| format!("failed to identify public-ID census frame: {error}"))?;
        if frame.language != *language
            || frame.frame_id != manifest.policy.frame_ids[language]
            || !paths.insert(resolved)
            || !frame_files.insert(identity)
        {
            return Err("public-ID census frame identity or path changed".to_string());
        }
    }
    let derived = replay_from_committed_exchanges(
        &manifest.policy,
        &manifest.preflight,
        &root,
        &manifest.exchanges,
    )?;
    if manifest.listed_repository_count != derived.listed_repository_count
        || manifest.in_window_repository_count != derived.in_window_repository_count
        || manifest.excluded_repository_count != derived.excluded_repository_count
        || manifest.name_disagreement_count != derived.name_disagreement_count
        || manifest.lower_boundary_repository_id != derived.lower_boundary_repository_id
        || manifest.upper_boundary_repository_id != derived.upper_boundary_repository_id
    {
        return Err("public-ID census manifest counts do not replay".to_string());
    }
    for frame in &manifest.frames {
        let bytes = read_artifact(&root, &frame.artifact_path, MAX_FRAME_BYTES)?;
        if sha256(&bytes) != frame.artifact_sha256
            || derived.frames.get(&frame.language) != Some(&bytes)
            || frame.repository_count != frame_repository_count(&bytes)?
        {
            return Err("public-ID census frame commitment does not replay".to_string());
        }
    }
    Ok(())
}

fn replay_from_committed_exchanges(
    policy: &PublicIdCensusPolicy,
    preflight: &PublicIdCensusPreflight,
    root: &Path,
    commitments: &[PublicIdCensusExchangeCommitment],
) -> Result<PublicIdCensusReplay, String> {
    let exchanges = commitments.iter().map(|commitment| {
        let bytes = read_artifact(root, &commitment.artifact_path, MAX_RAW_EXCHANGE_BYTES)?;
        if sha256(&bytes) != commitment.artifact_sha256 {
            return Err("public-ID census raw exchange commitment changed".to_string());
        }
        serde_json::from_slice::<PublicIdCensusExchange>(&bytes)
            .map_err(|error| format!("invalid public-ID census raw exchange: {error}"))
    });
    replay_public_id_census_stream(policy, preflight, exchanges)
}

fn canonical_root(root: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(root)
        .map_err(|error| format!("failed to resolve public-ID census artifact root: {error}"))
}

pub(crate) fn read_public_id_census_artifact(
    artifact_root: &Path,
    relative: &str,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let root = canonical_root(artifact_root)?;
    read_artifact(&root, relative, limit)
}

pub(super) fn read_artifact(root: &Path, relative: &str, limit: u64) -> Result<Vec<u8>, String> {
    let path = resolve_artifact(root, relative)?;
    let file = fs::File::open(&path)
        .map_err(|error| format!("failed to open public-ID census artifact: {error}"))?;
    let opened =
        Handle::from_file(file.try_clone().map_err(|error| {
            format!("failed to clone public-ID census artifact handle: {error}")
        })?)
        .map_err(|error| format!("failed to identify public-ID census artifact: {error}"))?;
    let rechecked = resolve_artifact(root, relative)?;
    let current = Handle::from_path(&rechecked)
        .map_err(|error| format!("failed to reidentify public-ID census artifact: {error}"))?;
    if path != rechecked || opened != current {
        return Err("public-ID census artifact changed during path resolution".to_string());
    }
    let size = file
        .metadata()
        .map_err(|error| format!("failed to size public-ID census artifact: {error}"))?
        .len();
    if size > limit {
        return Err("public-ID census artifact exceeds its read limit".to_string());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read public-ID census artifact: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err("public-ID census artifact grew beyond its read limit".to_string());
    }
    Ok(bytes)
}

fn resolve_artifact(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("public-ID census artifact path is not relative and safe".to_string());
    }
    let path = fs::canonicalize(root.join(relative))
        .map_err(|error| format!("failed to resolve public-ID census artifact: {error}"))?;
    if !path.starts_with(root) {
        return Err("public-ID census artifact escapes its root".to_string());
    }
    Ok(path)
}

fn frame_repository_count(frame: &[u8]) -> Result<usize, String> {
    if !frame.starts_with(b"repo,metadata\n") || !frame.ends_with(b"\n") {
        return Err("public-ID census frame has an invalid CSV envelope".to_string());
    }
    Ok(frame.iter().filter(|byte| **byte == b'\n').count() - 1)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("public-ID census manifest contains an invalid SHA-256".to_string());
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_public_id_census_manifest_tests.rs"]
mod tests;
