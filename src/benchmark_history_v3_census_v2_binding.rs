use super::{
    HISTORICAL_V3_PUBLIC_ID_CENSUS_V2_AUDIT_SCHEMA_VERSION,
    HISTORICAL_V3_PUBLIC_ID_CENSUS_V2_PROTOCOL_SCHEMA_VERSION, HistoricalV3BoundSourceFrame,
    HistoricalV3Language, HistoricalV3PriorBenchmarkIdentitySeal,
    HistoricalV3PriorIdentityProofStatus, HistoricalV3Protocol,
    HistoricalV3ResolvablePopulationAudit, HistoricalV3SourceBindingAudit, HistoricalV3SourceKind,
    PublicIdCensusV2Manifest, parse_historical_v3_source_frame, read_public_id_census_artifact,
    validate_historical_v3_prior_identity_seal, validate_historical_v3_protocol,
    validate_public_id_census_v2_manifest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

const AUDIT_CONTRACT: &str = "sniffbench-historical-v3-public-id-census-v2-source-binding-v4";
const MAX_FRAME_BYTES: u64 = 512 * 1024 * 1024;

pub struct HistoricalV3PublicIdCensusV2Artifact<'a> {
    pub manifest: &'a PublicIdCensusV2Manifest,
    pub artifact_root: &'a Path,
}

pub fn bind_historical_v3_public_id_census_v2_frames(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    artifact: &HistoricalV3PublicIdCensusV2Artifact<'_>,
) -> Result<HistoricalV3SourceBindingAudit, String> {
    validate_historical_v3_protocol(protocol)?;
    if protocol.schema_version != HISTORICAL_V3_PUBLIC_ID_CENSUS_V2_PROTOCOL_SCHEMA_VERSION
        || protocol.source_kind != Some(HistoricalV3SourceKind::PublicIdCensusV2)
    {
        return Err("historical-v3 census v2 binder requires an explicit v9 source".to_string());
    }
    validate_historical_v3_prior_identity_seal(prior_identities)?;
    if protocol.prior_benchmark_identity_seal_sha256 != prior_identities.seal_sha256 {
        return Err("historical-v3 census v2 protocol changed its prior identity seal".to_string());
    }
    validate_public_id_census_v2_manifest(artifact.manifest, artifact.artifact_root)?;
    let policy = &artifact.manifest.policy;
    if policy.repository_created_after_utc != protocol.repository_created_after_utc
        || policy.created_at_or_after_utc != "2026-08-08T00:00:00Z"
        || policy.created_before_utc != "2026-08-15T00:00:00Z"
    {
        return Err("historical-v3 census v2 creation window changed".to_string());
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
            return Err("historical-v3 census v2 frame binding changed".to_string());
        }
        let bytes = read_public_id_census_artifact(
            artifact.artifact_root,
            &source.artifact_path,
            MAX_FRAME_BYTES,
        )?;
        if format!("{:x}", Sha256::digest(&bytes)) != source.artifact_sha256 {
            return Err("historical-v3 census v2 frame changed after manifest replay".to_string());
        }
        let repositories = parse_historical_v3_source_frame(&bytes)?;
        if repositories.len() != source.repository_count
            || repositories
                .iter()
                .any(|repository| repository.created_at <= protocol.repository_created_after_utc)
        {
            return Err("historical-v3 census v2 frame violates its repository census".to_string());
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

    let manifest = artifact.manifest;
    let mut audit = HistoricalV3SourceBindingAudit {
        schema_version: HISTORICAL_V3_PUBLIC_ID_CENSUS_V2_AUDIT_SCHEMA_VERSION,
        audit_contract: AUDIT_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        prior_benchmark_identity_seal_sha256: prior_identities.seal_sha256.clone(),
        source_kind: Some(HistoricalV3SourceKind::PublicIdCensusV2),
        source_manifest_sha256: Some(manifest.manifest_sha256.clone()),
        resolvable_population: Some(HistoricalV3ResolvablePopulationAudit {
            listed_repository_count: manifest.listed_repository_count,
            resolved_in_window_count: manifest.resolved_in_window_count,
            resolved_ineligible_count: manifest.resolved_ineligible_count,
            probe_only_null_count: manifest.probe_only_null_count,
            crawled_null_count: manifest.crawled_null_count,
            name_disagreement_count: manifest.name_disagreement_count,
            null_ledger_artifact_sha256: manifest.null_ledger_artifact_sha256.clone(),
        }),
        prior_identity_proof_status: Some(HistoricalV3PriorIdentityProofStatus::NameOnlyUnproven),
        frames,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = audit_sha256(&audit)?;
    Ok(audit)
}

pub fn validate_historical_v3_public_id_census_v2_audit(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    artifact: &HistoricalV3PublicIdCensusV2Artifact<'_>,
    audit: &HistoricalV3SourceBindingAudit,
) -> Result<(), String> {
    if audit.schema_version != HISTORICAL_V3_PUBLIC_ID_CENSUS_V2_AUDIT_SCHEMA_VERSION
        || audit.audit_contract != AUDIT_CONTRACT
        || audit.source_kind != Some(HistoricalV3SourceKind::PublicIdCensusV2)
        || audit.source_manifest_sha256.as_deref()
            != Some(artifact.manifest.manifest_sha256.as_str())
        || audit.resolvable_population.is_none()
        || audit.prior_identity_proof_status
            != Some(HistoricalV3PriorIdentityProofStatus::NameOnlyUnproven)
        || audit.audit_sha256 != audit_sha256(audit)?
    {
        return Err("historical-v3 census v2 binding audit changed".to_string());
    }
    if bind_historical_v3_public_id_census_v2_frames(protocol, prior_identities, artifact)?
        != *audit
    {
        return Err("historical-v3 census v2 binding audit does not replay".to_string());
    }
    Ok(())
}

fn audit_sha256(audit: &HistoricalV3SourceBindingAudit) -> Result<String, String> {
    json_sha256(&(
        audit.schema_version,
        &audit.audit_contract,
        &audit.protocol_sha256,
        &audit.prior_benchmark_identity_seal_sha256,
        audit.source_kind,
        &audit.source_manifest_sha256,
        &audit.resolvable_population,
        audit.prior_identity_proof_status,
        &audit.frames,
    ))
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to commit historical-v3 census v2 binding: {error}"))?;
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
#[path = "benchmark_history_v3_census_v2_binding_tests.rs"]
mod tests;
