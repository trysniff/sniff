#[path = "benchmark_history_v3_source_binding_schema.rs"]
mod schema;

pub use schema::*;

use super::{
    HistoricalV3Language, HistoricalV3Protocol, SourceFrameCollectionManifest,
    validate_historical_v3_protocol, validate_source_frame_manifest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

const PRIOR_IDENTITY_SEAL_CONTRACT: &str = "sniffbench-historical-v3-prior-identities-v1";
const SOURCE_BINDING_AUDIT_CONTRACT: &str = "sniffbench-historical-v3-source-binding-v1";

pub struct HistoricalV3SourceFrameArtifact<'a> {
    pub manifest: &'a SourceFrameCollectionManifest,
    pub artifact_root: &'a Path,
    pub frame: &'a [u8],
}

pub fn prepare_historical_v3_prior_identity_seal(
    mut inputs: Vec<HistoricalV3PriorArtifactBinding>,
) -> Result<HistoricalV3PriorBenchmarkIdentitySeal, String> {
    for input in &mut inputs {
        input.repositories = input
            .repositories
            .iter()
            .map(|repository| canonical_github_repository(repository))
            .collect::<Result<Vec<_>, _>>()?;
        input.repositories.sort();
    }
    inputs.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let mut canonical_repositories = inputs
        .iter()
        .flat_map(|input| input.repositories.iter().cloned())
        .collect::<Vec<_>>();
    canonical_repositories.sort();
    canonical_repositories.dedup();

    let mut seal = HistoricalV3PriorBenchmarkIdentitySeal {
        schema_version: HISTORICAL_V3_SOURCE_BINDING_AUDIT_SCHEMA_VERSION,
        seal_contract: PRIOR_IDENTITY_SEAL_CONTRACT.to_string(),
        inputs,
        repositories: canonical_repositories,
        seal_sha256: String::new(),
    };
    validate_prior_identity_seal_fields(&seal)?;
    seal.seal_sha256 = compute_prior_identity_seal_sha256(&seal)?;
    Ok(seal)
}

pub fn validate_historical_v3_prior_identity_seal(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
) -> Result<(), String> {
    validate_prior_identity_seal_fields(seal)?;
    require_sha256("historical-v3 prior identity seal", &seal.seal_sha256)?;
    if seal.seal_sha256 != compute_prior_identity_seal_sha256(seal)? {
        return Err("historical-v3 prior identity seal commitment changed".to_string());
    }
    Ok(())
}

pub fn bind_historical_v3_source_frames(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    artifacts: &[HistoricalV3SourceFrameArtifact<'_>],
) -> Result<HistoricalV3SourceBindingAudit, String> {
    validate_historical_v3_protocol(protocol)?;
    validate_historical_v3_prior_identity_seal(prior_identities)?;
    if protocol.prior_benchmark_identity_seal_sha256 != prior_identities.seal_sha256 {
        return Err("historical-v3 protocol is bound to another prior identity seal".to_string());
    }
    if artifacts.len() != protocol.source_frames.len() {
        return Err("historical-v3 source artifact count changed".to_string());
    }

    let excluded = prior_identities
        .repositories
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut frames = Vec::with_capacity(artifacts.len());
    for ((expected, artifact), language) in protocol
        .source_frames
        .iter()
        .zip(artifacts)
        .zip(protocol.languages.iter().copied())
    {
        validate_source_frame_manifest(artifact.manifest, artifact.artifact_root, artifact.frame)?;
        if expected.language != language
            || expected.frame_id != artifact.manifest.policy.frame_id
            || expected.policy_sha256 != artifact.manifest.policy_sha256
            || expected.manifest_sha256 != artifact.manifest.manifest_sha256
            || expected.frame_sha256 != artifact.manifest.frame_sha256
            || expected.repository_count != artifact.manifest.repository_count
            || github_language(language) != artifact.manifest.policy.language
        {
            return Err("historical-v3 source-frame binding changed".to_string());
        }

        let repositories = parse_source_frame(artifact.frame)?;
        if repositories.len() != expected.repository_count {
            return Err("historical-v3 source frame repository census changed".to_string());
        }
        let eligible = repositories
            .iter()
            .filter(|repository| !excluded.contains(repository.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let excluded_prior_repository_count = repositories.len() - eligible.len();
        frames.push(HistoricalV3BoundSourceFrame {
            language,
            frame_id: expected.frame_id.clone(),
            repository_count: repositories.len(),
            eligible_repository_count: eligible.len(),
            excluded_prior_repository_count,
            eligible_repositories_sha256: json_sha256(&eligible)?,
        });
    }

    let mut audit = HistoricalV3SourceBindingAudit {
        schema_version: HISTORICAL_V3_PRIOR_IDENTITY_SEAL_SCHEMA_VERSION,
        audit_contract: SOURCE_BINDING_AUDIT_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        prior_benchmark_identity_seal_sha256: prior_identities.seal_sha256.clone(),
        frames,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = compute_source_binding_audit_sha256(&audit)?;
    Ok(audit)
}

pub fn validate_historical_v3_source_binding_audit(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    artifacts: &[HistoricalV3SourceFrameArtifact<'_>],
    audit: &HistoricalV3SourceBindingAudit,
) -> Result<(), String> {
    validate_historical_v3_protocol(protocol)?;
    validate_historical_v3_prior_identity_seal(prior_identities)?;
    require_sha256("historical-v3 source binding audit", &audit.audit_sha256)?;
    if audit.schema_version != HISTORICAL_V3_SOURCE_BINDING_AUDIT_SCHEMA_VERSION
        || audit.audit_contract != SOURCE_BINDING_AUDIT_CONTRACT
        || audit.protocol_sha256 != protocol.protocol_sha256
        || audit.prior_benchmark_identity_seal_sha256 != prior_identities.seal_sha256
        || audit.frames.len() != protocol.languages.len()
        || audit.audit_sha256 != compute_source_binding_audit_sha256(audit)?
    {
        return Err("historical-v3 source binding audit changed".to_string());
    }

    let expected = bind_historical_v3_source_frames(protocol, prior_identities, artifacts)?;
    if audit != &expected {
        return Err(
            "historical-v3 source binding audit does not replay from its frames".to_string(),
        );
    }

    for ((frame, expected), language) in audit
        .frames
        .iter()
        .zip(&protocol.source_frames)
        .zip(protocol.languages.iter().copied())
    {
        require_sha256(
            "historical-v3 eligible repository census",
            &frame.eligible_repositories_sha256,
        )?;
        if frame.language != language
            || frame.frame_id != expected.frame_id
            || frame.repository_count != expected.repository_count
            || frame.eligible_repository_count + frame.excluded_prior_repository_count
                != frame.repository_count
        {
            return Err("historical-v3 source binding audit frame changed".to_string());
        }
    }
    Ok(())
}

fn validate_prior_identity_seal_fields(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
) -> Result<(), String> {
    if seal.schema_version != HISTORICAL_V3_PRIOR_IDENTITY_SEAL_SCHEMA_VERSION
        || seal.seal_contract != PRIOR_IDENTITY_SEAL_CONTRACT
        || seal.inputs.is_empty()
        || seal.repositories.is_empty()
    {
        return Err("historical-v3 prior identity seal uses an unsupported contract".to_string());
    }
    let mut previous_input = None;
    for input in &seal.inputs {
        if input.artifact_id.trim().is_empty()
            || previous_input.is_some_and(|previous| previous >= input.artifact_id.as_str())
        {
            return Err(
                "historical-v3 prior identity inputs are not unique and ordered".to_string(),
            );
        }
        require_sha256("historical-v3 prior identity input", &input.artifact_sha256)?;
        if input.repositories.is_empty()
            || input.repositories.windows(2).any(|pair| pair[0] >= pair[1])
            || input.repositories.iter().any(|repository| {
                canonical_github_repository(repository).as_deref() != Ok(repository.as_str())
            })
        {
            return Err(
                "historical-v3 prior identity input repositories are not canonical, unique, and ordered"
                    .to_string(),
            );
        }
        previous_input = Some(input.artifact_id.as_str());
    }

    let mut previous_repository = None;
    for repository in &seal.repositories {
        if canonical_github_repository(repository)? != *repository
            || previous_repository.is_some_and(|previous| previous >= repository.as_str())
        {
            return Err(
                "historical-v3 prior repositories are not canonical, unique, and ordered"
                    .to_string(),
            );
        }
        previous_repository = Some(repository.as_str());
    }
    Ok(())
}

fn parse_source_frame(frame: &[u8]) -> Result<Vec<String>, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(frame);
    if reader
        .headers()
        .map_err(|error| error.to_string())?
        .iter()
        .ne(["repo", "metadata"])
    {
        return Err("historical-v3 source frame header changed".to_string());
    }
    let mut repositories = Vec::new();
    let mut repository_ids = Vec::new();
    let mut identities = HashSet::new();
    for record in reader.records() {
        let record =
            record.map_err(|error| format!("invalid historical-v3 source frame: {error}"))?;
        if record.len() != 2 {
            return Err("historical-v3 source frame row shape changed".to_string());
        }
        let repository = canonical_github_repository(&record[0])?;
        if !identities.insert(repository.clone()) {
            return Err("historical-v3 source frame repeats a repository identity".to_string());
        }
        let repository_id = record[1]
            .split(';')
            .find_map(|field| field.strip_prefix("github_repository_id="))
            .ok_or_else(|| "historical-v3 source frame omits repository ID".to_string())?
            .parse::<u64>()
            .map_err(|_| "historical-v3 source frame has an invalid repository ID".to_string())?;
        if repository_id == 0 {
            return Err("historical-v3 source frame has a zero repository ID".to_string());
        }
        repository_ids.push(repository_id);
        repositories.push(repository);
    }
    if repository_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(
            "historical-v3 source frame repository IDs are not unique and ordered".to_string(),
        );
    }
    Ok(repositories)
}

fn canonical_github_repository(value: &str) -> Result<String, String> {
    let mut normalized = value.trim().trim_end_matches('/');
    for prefix in ["https://github.com/", "http://github.com/", "github.com/"] {
        if let Some(stripped) = normalized.strip_prefix(prefix) {
            normalized = stripped;
            break;
        }
    }
    normalized = normalized.strip_suffix(".git").unwrap_or(normalized);
    let parts = normalized.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(format!("invalid historical-v3 GitHub repository: {value}"));
    }
    Ok(parts.join("/").to_ascii_lowercase())
}

fn github_language(language: HistoricalV3Language) -> &'static str {
    match language {
        HistoricalV3Language::Go => "Go",
        HistoricalV3Language::JavaScript => "JavaScript",
        HistoricalV3Language::Kotlin => "Kotlin",
        HistoricalV3Language::Python => "Python",
        HistoricalV3Language::Rust => "Rust",
        HistoricalV3Language::TypeScript => "TypeScript",
    }
}

fn compute_prior_identity_seal_sha256(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct Commitment<'a> {
        schema_version: u32,
        seal_contract: &'a str,
        inputs: &'a [HistoricalV3PriorArtifactBinding],
        repositories: &'a [String],
    }
    json_sha256(&Commitment {
        schema_version: seal.schema_version,
        seal_contract: &seal.seal_contract,
        inputs: &seal.inputs,
        repositories: &seal.repositories,
    })
}

fn compute_source_binding_audit_sha256(
    audit: &HistoricalV3SourceBindingAudit,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct Commitment<'a> {
        schema_version: u32,
        audit_contract: &'a str,
        protocol_sha256: &'a str,
        prior_benchmark_identity_seal_sha256: &'a str,
        frames: &'a [HistoricalV3BoundSourceFrame],
    }
    json_sha256(&Commitment {
        schema_version: audit.schema_version,
        audit_contract: &audit.audit_contract,
        protocol_sha256: &audit.protocol_sha256,
        prior_benchmark_identity_seal_sha256: &audit.prior_benchmark_identity_seal_sha256,
        frames: &audit.frames,
    })
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 source artifact: {error}"))
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not a lowercase SHA-256"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_history_v3_source_binding_tests.rs"]
mod tests;
