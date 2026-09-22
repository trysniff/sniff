use super::{
    CHECKPOINT_CONTRACT, GRAPHQL_QUERY, HISTORICAL_V3_CANDIDATE_CHECKPOINT_SCHEMA_VERSION,
    HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION,
    HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3CandidateCollectionManifest, HistoricalV3CandidatePageCheckpoint,
    HistoricalV3CandidatePageRequest, HistoricalV3Protocol, HistoricalV3SourceBindingAudit,
    MANIFEST_CONTRACT, REQUEST_CONTRACT, parse_candidate_page, parse_utc_second,
    prepare_historical_v3_stream_task, validate_historical_v3_stream_task,
};
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(super) fn seal_page_request(
    mut request: HistoricalV3CandidatePageRequest,
) -> Result<HistoricalV3CandidatePageRequest, String> {
    request.request_sha256.clear();
    validate_page_request_fields(&request)?;
    request.request_sha256 = json_sha256(&request)?;
    Ok(request)
}

pub(super) fn seal_page_checkpoint(
    request: HistoricalV3CandidatePageRequest,
    response: &[u8],
) -> Result<HistoricalV3CandidatePageCheckpoint, String> {
    parse_candidate_page(&request, response)?;
    let mut checkpoint = HistoricalV3CandidatePageCheckpoint {
        schema_version: HISTORICAL_V3_CANDIDATE_CHECKPOINT_SCHEMA_VERSION,
        checkpoint_contract: CHECKPOINT_CONTRACT.to_string(),
        request,
        response_sha256: sha256(response),
        response_base64: base64::engine::general_purpose::STANDARD.encode(response),
        checkpoint_sha256: String::new(),
    };
    checkpoint.checkpoint_sha256 = json_sha256(&checkpoint)?;
    Ok(checkpoint)
}

pub(super) fn validate_page_checkpoint(
    request: &HistoricalV3CandidatePageRequest,
    checkpoint: &HistoricalV3CandidatePageCheckpoint,
) -> Result<(), String> {
    validate_page_request(request)?;
    if checkpoint.schema_version != HISTORICAL_V3_CANDIDATE_CHECKPOINT_SCHEMA_VERSION
        || checkpoint.checkpoint_contract != CHECKPOINT_CONTRACT
        || &checkpoint.request != request
    {
        return Err("historical-v3 page checkpoint contract changed".to_string());
    }
    require_sha256("historical-v3 response", &checkpoint.response_sha256)?;
    require_sha256(
        "historical-v3 page checkpoint",
        &checkpoint.checkpoint_sha256,
    )?;
    let response = decode_response(checkpoint)?;
    if checkpoint.response_sha256 != sha256(&response) {
        return Err("historical-v3 raw response commitment changed".to_string());
    }
    let mut committed = checkpoint.clone();
    committed.checkpoint_sha256.clear();
    if checkpoint.checkpoint_sha256 != json_sha256(&committed)? {
        return Err("historical-v3 page checkpoint commitment changed".to_string());
    }
    parse_candidate_page(request, &response)?;
    Ok(())
}

pub(crate) fn seal_collection_manifest(
    mut manifest: HistoricalV3CandidateCollectionManifest,
) -> Result<HistoricalV3CandidateCollectionManifest, String> {
    manifest.manifest_sha256.clear();
    manifest.manifest_sha256 = json_sha256(&manifest)?;
    Ok(manifest)
}

pub(super) fn validate_manifest_fields(
    protocol: &HistoricalV3Protocol,
    source_binding_audit: &HistoricalV3SourceBindingAudit,
    manifest: &HistoricalV3CandidateCollectionManifest,
) -> Result<(), String> {
    validate_historical_v3_candidate_manifest_commitment(protocol, manifest)?;
    if manifest.source_binding_audit_sha256 != source_binding_audit.audit_sha256 {
        return Err("historical-v3 candidate source binding changed".to_string());
    }
    Ok(())
}

pub fn validate_historical_v3_candidate_manifest_commitment(
    protocol: &HistoricalV3Protocol,
    manifest: &HistoricalV3CandidateCollectionManifest,
) -> Result<(), String> {
    require_sha256(
        "historical-v3 candidate manifest",
        &manifest.manifest_sha256,
    )?;
    require_sha256(
        "historical-v3 candidate source binding",
        &manifest.source_binding_audit_sha256,
    )?;
    if manifest.schema_version != HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION
        || manifest.manifest_contract != MANIFEST_CONTRACT
        || manifest.protocol_sha256 != protocol.protocol_sha256
        || manifest.query_document_sha256 != sha256(GRAPHQL_QUERY.as_bytes())
    {
        return Err("historical-v3 candidate manifest contract changed".to_string());
    }
    let mut committed = manifest.clone();
    committed.manifest_sha256.clear();
    if manifest.manifest_sha256 != json_sha256(&committed)? {
        return Err("historical-v3 candidate manifest commitment changed".to_string());
    }
    validate_historical_v3_stream_task(protocol, &manifest.stream_task)?;
    if manifest.candidate_count != manifest.stream_task.candidates.len() {
        return Err("historical-v3 candidate manifest count changed".to_string());
    }
    let mut repositories = HashSet::new();
    for repository in &manifest.repositories {
        if repository.repository_id == 0
            || repository.name_with_owner.trim().is_empty()
            || !repositories.insert((repository.language, repository.repository_id))
        {
            return Err("historical-v3 candidate repository census changed".to_string());
        }
    }
    if manifest.stream_task.candidates.iter().any(|candidate| {
        !repositories.contains(&(
            candidate.identity.language,
            candidate.identity.repository_id,
        ))
    }) {
        return Err("historical-v3 candidate repository identity is absent".to_string());
    }
    Ok(())
}

pub fn validate_historical_v3_candidate_collection_commitment(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
) -> Result<(), String> {
    validate_historical_v3_candidate_manifest_commitment(protocol, &collection.manifest)?;
    let expected = prepare_historical_v3_stream_task(protocol, collection.candidates.clone())?;
    if collection.candidates.len() != collection.manifest.candidate_count
        || expected != collection.manifest.stream_task
    {
        return Err("historical-v3 candidate collection payload changed".to_string());
    }
    Ok(())
}

pub(super) fn decode_page(
    checkpoint: &HistoricalV3CandidatePageCheckpoint,
) -> Result<super::ParsedCandidatePage, String> {
    let response = decode_response(checkpoint)?;
    parse_candidate_page(&checkpoint.request, &response)
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_page_request(request: &HistoricalV3CandidatePageRequest) -> Result<(), String> {
    validate_page_request_fields(request)?;
    require_sha256("historical-v3 page request", &request.request_sha256)?;
    let mut committed = request.clone();
    committed.request_sha256.clear();
    if request.request_sha256 != json_sha256(&committed)? {
        return Err("historical-v3 page request commitment changed".to_string());
    }
    Ok(())
}

fn validate_page_request_fields(request: &HistoricalV3CandidatePageRequest) -> Result<(), String> {
    if request.schema_version != HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION
        || request.request_contract != REQUEST_CONTRACT
        || request.page_number == 0
        || (request.page_number == 1) != request.after_cursor.is_none()
        || request.partition.repository_id == 0
        || request.partition.name_with_owner.trim().is_empty()
        || request.partition.path.trim().is_empty()
    {
        return Err("historical-v3 page request uses an unsupported contract".to_string());
    }
    require_sha256("historical-v3 request protocol", &request.protocol_sha256)?;
    require_sha256(
        "historical-v3 request source binding",
        &request.source_binding_audit_sha256,
    )?;
    require_sha256(
        "historical-v3 GraphQL document",
        &request.query_document_sha256,
    )?;
    if request.query_document_sha256 != sha256(GRAPHQL_QUERY.as_bytes())
        || parse_utc_second(&request.partition.merged_at_or_after_utc)?
            > parse_utc_second(&request.partition.merged_at_or_before_utc)?
    {
        return Err("historical-v3 page request query changed".to_string());
    }
    Ok(())
}

fn decode_response(checkpoint: &HistoricalV3CandidatePageCheckpoint) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(&checkpoint.response_base64)
        .map_err(|error| format!("invalid historical-v3 raw response encoding: {error}"))
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v3 candidate artifact: {error}"))
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
