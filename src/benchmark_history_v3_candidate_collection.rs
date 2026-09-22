#[path = "benchmark_history_v3_candidate_collection_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_candidate_query.rs"]
mod query;

use query::{GRAPHQL_QUERY, ParsedCandidatePage, parse_candidate_page, request_body};

#[path = "benchmark_history_v3_candidate_store.rs"]
mod store;

pub use store::{GithubHistoricalV3CandidateTransport, HistoricalV3CandidatePageTransport};

#[path = "benchmark_history_v3_candidate_source.rs"]
mod source;

use source::{candidate_repositories, initial_partitions, split_partition};

#[path = "benchmark_history_v3_candidate_commitment.rs"]
mod commitment;

use commitment::{
    decode_page, seal_collection_manifest, seal_page_checkpoint, seal_page_request, sha256,
    validate_manifest_fields, validate_page_checkpoint,
};

#[path = "benchmark_history_v3_candidate_replay.rs"]
mod replay;

pub use replay::validate_historical_v3_candidate_collection;

use super::history_v3_source_binding::{
    HistoricalV3SourceFrameArtifact, HistoricalV3SourceRepositoryIdentity,
    parse_historical_v3_source_frame, validate_historical_v3_source_binding_audit,
};
use super::history_v3_time::{format_utc_second, parse_utc_second, split_inclusive_utc_range};
use super::{
    HistoricalV3CandidateIdentity, HistoricalV3Language, HistoricalV3PriorBenchmarkIdentitySeal,
    HistoricalV3Protocol, HistoricalV3SourceBindingAudit, HistoricalV3StreamTask,
    prepare_historical_v3_stream_task, validate_historical_v3_protocol,
};
use std::collections::HashSet;
use std::path::Path;

use store::{load_page_checkpoint, persist_page_checkpoint, read_committed_page_checkpoint};

const REQUEST_CONTRACT: &str = "sniffbench-historical-v3-candidate-request-v1";
const CHECKPOINT_CONTRACT: &str = "sniffbench-historical-v3-candidate-checkpoint-v1";
const MANIFEST_CONTRACT: &str = "sniffbench-historical-v3-candidate-manifest-v1";
const MAX_SEARCH_RESULTS: usize = 1_000;
const PAGE_SIZE: usize = 100;

pub async fn collect_historical_v3_candidates<T: HistoricalV3CandidatePageTransport>(
    protocol: &HistoricalV3Protocol,
    prior_identities: &HistoricalV3PriorBenchmarkIdentitySeal,
    source_artifacts: &[HistoricalV3SourceFrameArtifact<'_>],
    source_binding_audit: &HistoricalV3SourceBindingAudit,
    state_root: &Path,
    transport: &mut T,
) -> Result<HistoricalV3CandidateCollection, String> {
    let repositories = candidate_repositories(
        protocol,
        prior_identities,
        source_artifacts,
        source_binding_audit,
    )?;
    let query_document_sha256 = sha256(GRAPHQL_QUERY.as_bytes());
    let mut queue = initial_partitions(protocol, &repositories)?;
    let mut partitions = Vec::new();
    let mut checkpoint_sha256s = Vec::new();
    let mut candidates = Vec::new();
    let mut candidate_keys = HashSet::new();

    while let Some(partition) = queue.pop_front() {
        let first_request = seal_page_request(HistoricalV3CandidatePageRequest {
            schema_version: HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION,
            request_contract: REQUEST_CONTRACT.to_string(),
            protocol_sha256: protocol.protocol_sha256.clone(),
            source_binding_audit_sha256: source_binding_audit.audit_sha256.clone(),
            query_document_sha256: query_document_sha256.clone(),
            partition: partition.clone(),
            page_number: 1,
            after_cursor: None,
            request_sha256: String::new(),
        })?;
        let (first_checkpoint, first_page) =
            load_or_fetch_page(state_root, &first_request, transport).await?;
        checkpoint_sha256s.push(first_checkpoint.checkpoint_sha256.clone());

        if first_page.issue_count > MAX_SEARCH_RESULTS {
            let (left, right) = split_partition(&partition)?;
            partitions.push(HistoricalV3CandidatePartitionRecord::Split {
                partition,
                issue_count: first_page.issue_count,
                probe_request_sha256: first_request.request_sha256,
                left: Box::new(left.clone()),
                right: Box::new(right.clone()),
            });
            queue.push_front(right);
            queue.push_front(left);
            continue;
        }

        let issue_count = first_page.issue_count;
        let mut page_request_sha256s = vec![first_request.request_sha256];
        let mut partition_candidates = first_page.candidates.clone();
        let mut page = first_page;
        let mut page_number = 1;
        let mut cursors = HashSet::new();
        while page.has_next_page {
            let cursor = page
                .end_cursor
                .clone()
                .ok_or_else(|| "historical-v3 candidate cursor disappeared".to_string())?;
            if !cursors.insert(cursor.clone()) {
                return Err("historical-v3 candidate cursor repeated".to_string());
            }
            page_number += 1;
            if page_number > MAX_SEARCH_RESULTS.div_ceil(PAGE_SIZE) {
                return Err("historical-v3 candidate partition exceeded 1,000 results".to_string());
            }
            let request = seal_page_request(HistoricalV3CandidatePageRequest {
                schema_version: HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION,
                request_contract: REQUEST_CONTRACT.to_string(),
                protocol_sha256: protocol.protocol_sha256.clone(),
                source_binding_audit_sha256: source_binding_audit.audit_sha256.clone(),
                query_document_sha256: query_document_sha256.clone(),
                partition: partition.clone(),
                page_number,
                after_cursor: Some(cursor),
                request_sha256: String::new(),
            })?;
            let (checkpoint, next_page) =
                load_or_fetch_page(state_root, &request, transport).await?;
            if next_page.issue_count != issue_count {
                return Err(
                    "historical-v3 candidate issue count changed during pagination".to_string(),
                );
            }
            checkpoint_sha256s.push(checkpoint.checkpoint_sha256);
            page_request_sha256s.push(request.request_sha256);
            partition_candidates.extend(next_page.candidates.iter().cloned());
            page = next_page;
        }
        if partition_candidates.len() != issue_count {
            return Err(
                "historical-v3 candidate pagination did not reproduce issueCount".to_string(),
            );
        }
        for candidate in &partition_candidates {
            let key = (
                candidate.language,
                candidate.repository_id,
                candidate.pull_request_number,
            );
            if !candidate_keys.insert(key) {
                return Err("historical-v3 candidate PR identity is duplicated".to_string());
            }
        }
        partitions.push(HistoricalV3CandidatePartitionRecord::Complete {
            partition,
            issue_count,
            candidate_count: partition_candidates.len(),
            page_request_sha256s,
        });
        candidates.extend(partition_candidates);
    }

    let stream_task = prepare_historical_v3_stream_task(protocol, candidates.clone())?;
    let manifest = seal_collection_manifest(HistoricalV3CandidateCollectionManifest {
        schema_version: HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION,
        manifest_contract: MANIFEST_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        source_binding_audit_sha256: source_binding_audit.audit_sha256.clone(),
        query_document_sha256,
        repositories,
        partitions,
        page_checkpoint_sha256s: checkpoint_sha256s,
        candidate_count: candidates.len(),
        stream_task,
        manifest_sha256: String::new(),
    })?;
    let collection = HistoricalV3CandidateCollection {
        manifest,
        candidates,
    };
    validate_historical_v3_candidate_collection(
        protocol,
        prior_identities,
        source_artifacts,
        source_binding_audit,
        state_root,
        &collection,
    )?;
    Ok(collection)
}

async fn load_or_fetch_page<T: HistoricalV3CandidatePageTransport>(
    state_root: &Path,
    request: &HistoricalV3CandidatePageRequest,
    transport: &mut T,
) -> Result<(HistoricalV3CandidatePageCheckpoint, ParsedCandidatePage), String> {
    let checkpoint = if let Some(checkpoint) = load_page_checkpoint(state_root, request)? {
        checkpoint
    } else {
        let response = transport.fetch(request).await?;
        let checkpoint = seal_page_checkpoint(request.clone(), &response)?;
        persist_page_checkpoint(state_root, request, &checkpoint)?;
        checkpoint
    };
    let page = decode_page(&checkpoint)?;
    if page.candidates.len() > PAGE_SIZE {
        return Err("historical-v3 GraphQL page exceeded 100 results".to_string());
    }
    Ok((checkpoint, page))
}

#[cfg(test)]
#[path = "benchmark_history_v3_candidate_collection_tests.rs"]
mod tests;
