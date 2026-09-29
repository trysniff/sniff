use super::{
    HISTORICAL_V3_PUBLIC_ID_CENSUS_AUDIT_SCHEMA_VERSION,
    HISTORICAL_V3_PUBLIC_ID_CENSUS_PROTOCOL_SCHEMA_VERSION, HistoricalV3BoundSourceFrame,
    HistoricalV3Language, HistoricalV3PriorBenchmarkIdentitySeal, HistoricalV3Protocol,
    HistoricalV3SourceBindingAudit, HistoricalV3SourceKind, PublicIdCensusManifest,
    parse_historical_v3_source_frame, read_public_id_census_artifact,
    validate_historical_v3_prior_identity_seal, validate_historical_v3_protocol,
    validate_public_id_census_manifest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

const CENSUS_AUDIT_CONTRACT: &str = "sniffbench-historical-v3-public-id-census-source-binding-v3";
const MAX_FRAME_BYTES: u64 = 512 * 1024 * 1024;

pub struct HistoricalV3PublicIdCensusArtifact<'a> {
    pub manifest: &'a PublicIdCensusManifest,
    pub artifact_root: &'a Path,
}

pub fn bind_historical_v3_public_id_census_frames(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    artifact: &HistoricalV3PublicIdCensusArtifact<'_>,
) -> Result<HistoricalV3SourceBindingAudit, String> {
    validate_historical_v3_protocol(protocol)?;
    if protocol.schema_version != HISTORICAL_V3_PUBLIC_ID_CENSUS_PROTOCOL_SCHEMA_VERSION
        || protocol.source_kind != Some(HistoricalV3SourceKind::PublicIdCensus)
    {
        return Err("historical-v3 census binder requires an explicit v8 source".to_string());
    }
    validate_historical_v3_prior_identity_seal(prior_identities)?;
    if protocol.prior_benchmark_identity_seal_sha256 != prior_identities.seal_sha256 {
        return Err("historical-v3 census protocol changed its prior identity seal".to_string());
    }
    validate_public_id_census_manifest(artifact.manifest, artifact.artifact_root)?;
    if artifact.manifest.policy.repository_created_after_utc
        != protocol.repository_created_after_utc
    {
        return Err("historical-v3 census creation cutoff changed".to_string());
    }

    let excluded = prior_identities
        .repositories
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut frames = Vec::with_capacity(protocol.languages.len());
    for ((expected, source), language) in protocol
        .source_frames
        .iter()
        .zip(&artifact.manifest.frames)
        .zip(protocol.languages.iter().copied())
    {
        if expected.language != language
            || source.language != github_language(language)
            || expected.frame_id != source.frame_id
            || expected.policy_sha256 != artifact.manifest.policy_sha256
            || expected.manifest_sha256 != artifact.manifest.manifest_sha256
            || expected.frame_sha256 != source.artifact_sha256
            || expected.repository_count != source.repository_count
        {
            return Err("historical-v3 census frame binding changed".to_string());
        }
        let bytes = read_public_id_census_artifact(
            artifact.artifact_root,
            &source.artifact_path,
            MAX_FRAME_BYTES,
        )?;
        if format!("{:x}", Sha256::digest(&bytes)) != source.artifact_sha256 {
            return Err("historical-v3 census frame changed after manifest replay".to_string());
        }
        let repositories = parse_historical_v3_source_frame(&bytes)?;
        if repositories.len() != source.repository_count
            || repositories
                .iter()
                .any(|repository| repository.created_at <= protocol.repository_created_after_utc)
        {
            return Err("historical-v3 census frame violates its repository census".to_string());
        }
        let eligible = repositories
            .iter()
            .filter(|repository| !excluded.contains(repository.name_with_owner.as_str()))
            .map(|repository| repository.name_with_owner.as_str())
            .collect::<Vec<_>>();
        frames.push(HistoricalV3BoundSourceFrame {
            language,
            frame_id: source.frame_id.clone(),
            repository_count: repositories.len(),
            eligible_repository_count: eligible.len(),
            excluded_prior_repository_count: repositories.len() - eligible.len(),
            eligible_repositories_sha256: json_sha256(&eligible)?,
        });
    }

    let mut audit = HistoricalV3SourceBindingAudit {
        schema_version: HISTORICAL_V3_PUBLIC_ID_CENSUS_AUDIT_SCHEMA_VERSION,
        audit_contract: CENSUS_AUDIT_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        prior_benchmark_identity_seal_sha256: prior_identities.seal_sha256.clone(),
        source_kind: Some(HistoricalV3SourceKind::PublicIdCensus),
        source_manifest_sha256: Some(artifact.manifest.manifest_sha256.clone()),
        resolvable_population: None,
        prior_identity_proof_status: None,
        frames,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = census_audit_sha256(&audit)?;
    Ok(audit)
}

pub fn validate_historical_v3_public_id_census_audit(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    artifact: &HistoricalV3PublicIdCensusArtifact<'_>,
    audit: &HistoricalV3SourceBindingAudit,
) -> Result<(), String> {
    if audit.schema_version != HISTORICAL_V3_PUBLIC_ID_CENSUS_AUDIT_SCHEMA_VERSION
        || audit.audit_contract != CENSUS_AUDIT_CONTRACT
        || audit.source_kind != Some(HistoricalV3SourceKind::PublicIdCensus)
        || audit.source_manifest_sha256.as_deref()
            != Some(artifact.manifest.manifest_sha256.as_str())
        || audit.resolvable_population.is_some()
        || audit.prior_identity_proof_status.is_some()
        || audit.audit_sha256 != census_audit_sha256(audit)?
    {
        return Err("historical-v3 census binding audit changed".to_string());
    }
    if bind_historical_v3_public_id_census_frames(protocol, prior_identities, artifact)? != *audit {
        return Err("historical-v3 census binding audit does not replay".to_string());
    }
    Ok(())
}

fn census_audit_sha256(audit: &HistoricalV3SourceBindingAudit) -> Result<String, String> {
    json_sha256(&(
        audit.schema_version,
        &audit.audit_contract,
        &audit.protocol_sha256,
        &audit.prior_benchmark_identity_seal_sha256,
        audit.source_kind,
        &audit.source_manifest_sha256,
        &audit.frames,
    ))
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to commit historical-v3 census binding: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
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

#[cfg(test)]
#[path = "benchmark_history_v3_census_binding_tests.rs"]
pub(crate) mod tests;
