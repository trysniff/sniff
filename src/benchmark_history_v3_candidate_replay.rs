use super::{
    HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3CandidateIdentity, HistoricalV3CandidatePageRequest,
    HistoricalV3CandidatePartition, HistoricalV3CandidatePartitionRecord,
    HistoricalV3PriorBenchmarkIdentitySeal, HistoricalV3Protocol, HistoricalV3SourceBindingAudit,
    HistoricalV3SourceFrameArtifact, MAX_SEARCH_RESULTS, PAGE_SIZE, REQUEST_CONTRACT,
    candidate_repositories, decode_page, initial_partitions, prepare_historical_v3_stream_task,
    read_committed_page_checkpoint, seal_page_request, split_partition, validate_manifest_fields,
    validate_page_checkpoint,
};
use std::collections::HashSet;
use std::path::Path;

struct ReplayContext<'a> {
    protocol: &'a HistoricalV3Protocol,
    source_binding_audit: &'a HistoricalV3SourceBindingAudit,
    state_root: &'a Path,
    query_document_sha256: &'a str,
}

pub fn validate_historical_v3_candidate_collection(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    source_artifacts: &[HistoricalV3SourceFrameArtifact<'_>],
    source_binding_audit: &HistoricalV3SourceBindingAudit,
    state_root: &Path,
    collection: &HistoricalV3CandidateCollection,
) -> Result<(), String> {
    let expected_repositories = candidate_repositories(
        protocol,
        prior_identities,
        source_artifacts,
        source_binding_audit,
    )?;
    validate_manifest_fields(protocol, source_binding_audit, &collection.manifest)?;
    if collection.manifest.repositories != expected_repositories {
        return Err("historical-v3 candidate repository census changed".to_string());
    }

    let mut expected_partitions = initial_partitions(protocol, &expected_repositories)?;
    let mut checkpoint_sha256s = Vec::new();
    let mut candidates = Vec::new();
    let mut candidate_keys = HashSet::new();
    for record in &collection.manifest.partitions {
        let expected_partition = expected_partitions
            .pop_front()
            .ok_or_else(|| "historical-v3 candidate partition record is unexpected".to_string())?;
        match record {
            HistoricalV3CandidatePartitionRecord::Split {
                partition,
                issue_count,
                probe_request_sha256,
                left,
                right,
            } => {
                if partition != &expected_partition || *issue_count <= MAX_SEARCH_RESULTS {
                    return Err("historical-v3 candidate split record changed".to_string());
                }
                let checkpoint = read_committed_page_checkpoint(state_root, probe_request_sha256)?;
                validate_page_checkpoint(&checkpoint.request, &checkpoint)?;
                validate_first_request(
                    protocol,
                    source_binding_audit,
                    &expected_partition,
                    &collection.manifest.query_document_sha256,
                    &checkpoint.request,
                )?;
                if &checkpoint.request.request_sha256 != probe_request_sha256 {
                    return Err(
                        "historical-v3 candidate probe artifact identity changed".to_string()
                    );
                }
                let page = decode_page(&checkpoint)?;
                if page.issue_count != *issue_count {
                    return Err("historical-v3 candidate split count changed".to_string());
                }
                let (expected_left, expected_right) = split_partition(&expected_partition)?;
                if left.as_ref() != &expected_left || right.as_ref() != &expected_right {
                    return Err("historical-v3 candidate split tree changed".to_string());
                }
                checkpoint_sha256s.push(checkpoint.checkpoint_sha256);
                expected_partitions.push_front(expected_right);
                expected_partitions.push_front(expected_left);
            }
            HistoricalV3CandidatePartitionRecord::Complete {
                partition,
                issue_count,
                candidate_count,
                page_request_sha256s,
            } => {
                if partition != &expected_partition
                    || *issue_count > MAX_SEARCH_RESULTS
                    || page_request_sha256s.is_empty()
                {
                    return Err("historical-v3 candidate complete record changed".to_string());
                }
                let replayed = replay_complete_partition(
                    &ReplayContext {
                        protocol,
                        source_binding_audit,
                        state_root,
                        query_document_sha256: &collection.manifest.query_document_sha256,
                    },
                    &expected_partition,
                    *issue_count,
                    page_request_sha256s,
                    &mut checkpoint_sha256s,
                )?;
                if replayed.len() != *candidate_count {
                    return Err("historical-v3 candidate partition census changed".to_string());
                }
                for candidate in &replayed {
                    let key = (
                        candidate.language,
                        candidate.repository_id,
                        candidate.pull_request_number,
                    );
                    if !candidate_keys.insert(key) {
                        return Err("historical-v3 candidate PR identity is duplicated".to_string());
                    }
                }
                candidates.extend(replayed);
            }
        }
    }
    if !expected_partitions.is_empty()
        || checkpoint_sha256s != collection.manifest.page_checkpoint_sha256s
        || candidates != collection.candidates
        || candidates.len() != collection.manifest.candidate_count
    {
        return Err("historical-v3 candidate collection does not replay".to_string());
    }
    let expected_task = prepare_historical_v3_stream_task(protocol, candidates)?;
    if expected_task != collection.manifest.stream_task {
        return Err("historical-v3 candidate stream task does not replay".to_string());
    }
    Ok(())
}

fn replay_complete_partition(
    context: &ReplayContext<'_>,
    partition: &HistoricalV3CandidatePartition,
    issue_count: usize,
    request_sha256s: &[String],
    checkpoint_sha256s: &mut Vec<String>,
) -> Result<Vec<HistoricalV3CandidateIdentity>, String> {
    let mut candidates = Vec::new();
    let mut previous_cursor = None;
    for (offset, request_sha256) in request_sha256s.iter().enumerate() {
        let checkpoint = read_committed_page_checkpoint(context.state_root, request_sha256)?;
        validate_page_checkpoint(&checkpoint.request, &checkpoint)?;
        let expected = seal_page_request(HistoricalV3CandidatePageRequest {
            schema_version: HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION,
            request_contract: REQUEST_CONTRACT.to_string(),
            protocol_sha256: context.protocol.protocol_sha256.clone(),
            source_binding_audit_sha256: context.source_binding_audit.audit_sha256.clone(),
            query_document_sha256: context.query_document_sha256.to_string(),
            partition: partition.clone(),
            page_number: offset + 1,
            after_cursor: previous_cursor.clone(),
            request_sha256: String::new(),
        })?;
        if checkpoint.request != expected || &expected.request_sha256 != request_sha256 {
            return Err("historical-v3 candidate page chain changed".to_string());
        }
        let page = decode_page(&checkpoint)?;
        if page.issue_count != issue_count
            || page.candidates.len() > PAGE_SIZE
            || page.has_next_page != (offset + 1 < request_sha256s.len())
        {
            return Err("historical-v3 candidate page chain is incomplete".to_string());
        }
        previous_cursor = page.end_cursor.clone();
        candidates.extend(page.candidates);
        checkpoint_sha256s.push(checkpoint.checkpoint_sha256);
    }
    if candidates.len() != issue_count {
        return Err("historical-v3 candidate page count changed".to_string());
    }
    Ok(candidates)
}

fn validate_first_request(
    protocol: &HistoricalV3Protocol,
    source_binding_audit: &HistoricalV3SourceBindingAudit,
    partition: &HistoricalV3CandidatePartition,
    query_document_sha256: &str,
    request: &HistoricalV3CandidatePageRequest,
) -> Result<(), String> {
    let expected = seal_page_request(HistoricalV3CandidatePageRequest {
        schema_version: HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION,
        request_contract: REQUEST_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        source_binding_audit_sha256: source_binding_audit.audit_sha256.clone(),
        query_document_sha256: query_document_sha256.to_string(),
        partition: partition.clone(),
        page_number: 1,
        after_cursor: None,
        request_sha256: String::new(),
    })?;
    if request != &expected {
        return Err("historical-v3 candidate probe request changed".to_string());
    }
    Ok(())
}
