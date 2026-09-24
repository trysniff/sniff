use super::store::{self, BoundInputs};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

const MAX_PUBLIC_ARTIFACT_BYTES: usize = 1024 * 1024;
const MAX_PROOF_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicArtifactProof {
    url: String,
    semantic_sha256: String,
    fetched_sha256: String,
    fetched_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicCommitProof {
    api_url: String,
    commit_sha: String,
    fetched_sha256: String,
    fetched_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicPrecommitProof {
    schema_version: u32,
    commits: Vec<PublicCommitProof>,
    protocol: PublicArtifactProof,
    source_policies: Vec<PublicArtifactProof>,
    proof_sha256: String,
}

pub(super) trait PublicArtifactTransport {
    fn fetch<'a>(
        &'a mut self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;
}

pub(super) struct GithubRawTransport {
    client: reqwest::Client,
}

impl GithubRawTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl PublicArtifactTransport for GithubRawTransport {
    fn fetch<'a>(
        &'a mut self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut response = self
                .client
                .get(url)
                .header(reqwest::header::USER_AGENT, "sniff-cli")
                .send()
                .await
                .map_err(|error| format!("public precommit fetch failed: {error}"))?;
            if !response.status().is_success() {
                return Err(format!(
                    "public precommit fetch returned HTTP {}",
                    response.status()
                ));
            }
            if response
                .content_length()
                .is_some_and(|size| size > MAX_PUBLIC_ARTIFACT_BYTES as u64)
            {
                return Err("public precommit artifact is too large".to_string());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| format!("public precommit body failed: {error}"))?
            {
                if bytes.len().saturating_add(chunk.len()) > MAX_PUBLIC_ARTIFACT_BYTES {
                    return Err("public precommit artifact is too large".to_string());
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        })
    }
}

pub(super) fn validate_public_url(value: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(value)
        .map_err(|error| format!("invalid public precommit URL: {error}"))?;
    if url.scheme() != "https"
        || url.host_str() != Some("raw.githubusercontent.com")
        || url.port().is_some()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
    {
        return Err("public precommit URL must be an immutable GitHub raw URL".to_string());
    }
    let segments = url
        .path_segments()
        .ok_or_else(|| "public precommit URL has no path".to_string())?
        .collect::<Vec<_>>();
    if segments.len() < 4
        || segments[..2].iter().any(|segment| !safe_segment(segment))
        || segments[2].len() != 40
        || !segments[2]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || segments[3..].iter().any(|segment| !safe_segment(segment))
    {
        return Err(
            "public precommit URL must identify an exact GitHub commit and file".to_string(),
        );
    }
    Ok(())
}

fn safe_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(super) fn expected_commits(bound: &BoundInputs) -> Result<BTreeMap<String, String>, String> {
    let config = &bound.unbound.config;
    let mut commits = BTreeMap::new();
    for url in std::iter::once(&config.public_protocol_url).chain(
        config
            .source_frames
            .iter()
            .map(|frame| &frame.public_policy_url),
    ) {
        validate_public_url(url)?;
        let parsed = reqwest::Url::parse(url).map_err(|error| error.to_string())?;
        let parts = parsed
            .path_segments()
            .ok_or_else(|| "public precommit URL has no path".to_string())?
            .collect::<Vec<_>>();
        let api_url = format!(
            "https://api.github.com/repos/{}/{}/git/commits/{}",
            parts[0], parts[1], parts[2]
        );
        commits.insert(api_url, parts[2].to_string());
    }
    Ok(commits)
}

pub(super) async fn ensure_public_precommit<T: PublicArtifactTransport>(
    bound: &BoundInputs,
    transport: &mut T,
) -> Result<(), String> {
    let path = bound.root.join("public-precommit-proof.json");
    if path.exists() {
        return validate_public_precommit(bound);
    }
    let config = &bound.unbound.config;
    let mut commits = Vec::new();
    for (api_url, commit_sha) in expected_commits(bound)? {
        let fetched = transport.fetch(&api_url).await?;
        if fetched.len() > MAX_PUBLIC_ARTIFACT_BYTES {
            return Err("public precommit commit response is too large".to_string());
        }
        let value: serde_json::Value = serde_json::from_slice(&fetched)
            .map_err(|error| format!("invalid public commit response: {error}"))?;
        if value.get("sha").and_then(serde_json::Value::as_str) != Some(commit_sha.as_str()) {
            return Err("public precommit ref did not resolve to the exact commit".to_string());
        }
        commits.push(PublicCommitProof {
            api_url,
            commit_sha,
            fetched_sha256: sha256(&fetched),
            fetched_base64: STANDARD.encode(&fetched),
        });
    }
    let protocol_bytes = store::read_plain(
        &config.protocol,
        MAX_PUBLIC_ARTIFACT_BYTES as u64,
        "protocol",
    )?;
    let remote_protocol = transport.fetch(&config.public_protocol_url).await?;
    if remote_protocol != protocol_bytes {
        return Err("public precommit protocol differs from the bound local protocol".to_string());
    }
    let protocol = PublicArtifactProof {
        url: config.public_protocol_url.clone(),
        semantic_sha256: sha256(&protocol_bytes),
        fetched_sha256: sha256(&remote_protocol),
        fetched_base64: STANDARD.encode(&remote_protocol),
    };
    let mut source_policies = Vec::with_capacity(bound.unbound.frames.len());
    for (paths, frame) in config.source_frames.iter().zip(&bound.unbound.frames) {
        let remote = transport.fetch(&paths.public_policy_url).await?;
        if remote.len() > MAX_PUBLIC_ARTIFACT_BYTES {
            return Err("public precommit source policy is too large".to_string());
        }
        let policy: serde_json::Value = serde_json::from_slice(&remote)
            .map_err(|error| format!("invalid public source policy: {error}"))?;
        if policy
            != serde_json::to_value(&frame.manifest.policy).map_err(|error| error.to_string())?
        {
            return Err("public precommit source policy differs from the bound frame".to_string());
        }
        source_policies.push(PublicArtifactProof {
            url: paths.public_policy_url.clone(),
            semantic_sha256: sha256(
                &serde_json::to_vec(&frame.manifest.policy).map_err(|error| error.to_string())?,
            ),
            fetched_sha256: sha256(&remote),
            fetched_base64: STANDARD.encode(&remote),
        });
    }
    let mut proof = PublicPrecommitProof {
        schema_version: 1,
        commits,
        protocol,
        source_policies,
        proof_sha256: String::new(),
    };
    proof.proof_sha256 = sha256(&serde_json::to_vec(&proof).map_err(|error| error.to_string())?);
    store::write_json_durable(&path, &proof)?;
    validate_public_precommit(bound)
}

pub(super) fn validate_public_precommit(bound: &BoundInputs) -> Result<(), String> {
    let path = bound.root.join("public-precommit-proof.json");
    if !path.exists() {
        return Err(
            "historical-v3 public precommit proof is missing; run benchmark historical-v3 preflight before collect"
                .to_string(),
        );
    }
    let proof: PublicPrecommitProof =
        store::read_json(&path, MAX_PROOF_BYTES, "public precommit proof")?;
    let mut unsigned = proof.clone();
    unsigned.proof_sha256.clear();
    if proof.schema_version != 1
        || proof.proof_sha256
            != sha256(&serde_json::to_vec(&unsigned).map_err(|error| error.to_string())?)
        || proof.protocol.url != bound.unbound.config.public_protocol_url
        || proof.source_policies.len() != bound.unbound.frames.len()
    {
        return Err("public precommit proof changed".to_string());
    }
    let expected = expected_commits(bound)?;
    if proof.commits.len() != expected.len() {
        return Err("public precommit commit count changed".to_string());
    }
    for (entry, (api_url, commit_sha)) in proof.commits.iter().zip(expected) {
        let fetched = verified_encoded_bytes(&entry.fetched_base64, &entry.fetched_sha256)?;
        let value: serde_json::Value = serde_json::from_slice(&fetched)
            .map_err(|error| format!("invalid replayed public commit response: {error}"))?;
        if entry.api_url != api_url
            || entry.commit_sha != commit_sha
            || value.get("sha").and_then(serde_json::Value::as_str) != Some(commit_sha.as_str())
        {
            return Err("public precommit commit proof changed".to_string());
        }
    }
    let protocol_bytes = store::read_plain(
        &bound.unbound.config.protocol,
        MAX_PUBLIC_ARTIFACT_BYTES as u64,
        "protocol",
    )?;
    let fetched_protocol = verified_fetched_bytes(&proof.protocol)?;
    if proof.protocol.semantic_sha256 != sha256(&protocol_bytes)
        || fetched_protocol != protocol_bytes
    {
        return Err("public precommit protocol proof changed".to_string());
    }
    for ((entry, paths), frame) in proof
        .source_policies
        .iter()
        .zip(&bound.unbound.config.source_frames)
        .zip(&bound.unbound.frames)
    {
        let semantic = serde_json::to_vec(&frame.manifest.policy)
            .map_err(|error| format!("failed to verify source policy: {error}"))?;
        let fetched = verified_fetched_bytes(entry)?;
        let fetched_policy: serde_json::Value = serde_json::from_slice(&fetched)
            .map_err(|error| format!("invalid replayed public source policy: {error}"))?;
        if entry.url != paths.public_policy_url
            || entry.semantic_sha256 != sha256(&semantic)
            || fetched_policy
                != serde_json::to_value(&frame.manifest.policy)
                    .map_err(|error| error.to_string())?
        {
            return Err("public precommit source policy proof changed".to_string());
        }
    }
    Ok(())
}

fn verified_fetched_bytes(proof: &PublicArtifactProof) -> Result<Vec<u8>, String> {
    verified_encoded_bytes(&proof.fetched_base64, &proof.fetched_sha256)
}

fn verified_encoded_bytes(encoded: &str, expected_sha256: &str) -> Result<Vec<u8>, String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|error| format!("invalid public precommit evidence: {error}"))?;
    if bytes.len() > MAX_PUBLIC_ARTIFACT_BYTES || sha256(&bytes) != expected_sha256 {
        return Err("public precommit fetched content changed".to_string());
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::validate_public_url;

    #[test]
    fn public_artifact_url_requires_an_immutable_github_commit() {
        let good = format!(
            "https://raw.githubusercontent.com/trysniff/sniff/{}/bench/v3/protocol.json",
            "a".repeat(40)
        );
        assert!(validate_public_url(&good).is_ok());
        for bad in [
            "https://raw.githubusercontent.com/trysniff/sniff/main/protocol.json".to_string(),
            format!(
                "https://example.com/trysniff/sniff/{}/protocol.json",
                "a".repeat(40)
            ),
            format!("{good}?raw=1"),
            format!("{good}#fragment"),
            format!("{}%2fescape", good),
        ] {
            assert!(validate_public_url(&bad).is_err(), "accepted {bad}");
        }
    }
}
