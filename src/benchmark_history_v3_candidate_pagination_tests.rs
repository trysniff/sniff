use super::*;
use crate::benchmark::release::history_v3_source_binding::tests as source_fixture;

struct PaginationTransport {
    pages: usize,
    repeat_cursor: bool,
}

impl HistoricalV3CandidatePageTransport for PaginationTransport {
    fn fetch<'a>(
        &'a mut self,
        request: &'a HistoricalV3CandidatePageRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            if request.partition.language != HistoricalV3Language::Go {
                return Ok(response_for(request, 0, None, false, None));
            }
            let cursor = if self.repeat_cursor {
                "repeated".to_string()
            } else {
                format!("page-{}", request.page_number)
            };
            Ok(response_for(
                request,
                self.pages,
                Some(request.page_number as u64),
                request.page_number < self.pages,
                Some(&cursor),
            ))
        })
    }
}

// Recommit every affected layer so replay cannot reject only a stale digest.
fn replace_go_pages(
    state: &Path,
    protocol: &HistoricalV3Protocol,
    collection: &mut HistoricalV3CandidateCollection,
    pages: usize,
    repeat_cursor: bool,
) {
    let partition = collection
        .manifest
        .partitions
        .iter_mut()
        .find(|record| {
            matches!(record, HistoricalV3CandidatePartitionRecord::Complete {
            partition, ..
        } if partition.language == HistoricalV3Language::Go)
        })
        .unwrap();
    let HistoricalV3CandidatePartitionRecord::Complete {
        partition,
        issue_count,
        candidate_count,
        page_request_sha256s,
    } = partition
    else {
        unreachable!();
    };
    *issue_count = pages;
    *candidate_count = pages;
    page_request_sha256s.clear();
    let mut after_cursor = None;
    for page_number in 1..=pages {
        let request = seal_page_request(HistoricalV3CandidatePageRequest {
            schema_version: HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION,
            request_contract: REQUEST_CONTRACT.to_string(),
            protocol_sha256: protocol.protocol_sha256.clone(),
            source_binding_audit_sha256: collection.manifest.source_binding_audit_sha256.clone(),
            query_document_sha256: collection.manifest.query_document_sha256.clone(),
            partition: partition.clone(),
            page_number,
            after_cursor,
            request_sha256: String::new(),
        })
        .unwrap();
        let cursor = if repeat_cursor {
            "repeated".to_string()
        } else {
            format!("page-{page_number}")
        };
        let checkpoint = seal_page_checkpoint(
            request.clone(),
            &response_for(
                &request,
                pages,
                Some(page_number as u64),
                page_number < pages,
                Some(&cursor),
            ),
        )
        .unwrap();
        std::fs::write(
            state
                .join("pages")
                .join(format!("{}.json", request.request_sha256)),
            serde_json::to_vec(&checkpoint).unwrap(),
        )
        .unwrap();
        page_request_sha256s.push(request.request_sha256);
        after_cursor = Some(cursor);
    }
    collection.manifest.page_checkpoint_sha256s.clear();
    collection.candidates.clear();
    for record in &collection.manifest.partitions {
        let HistoricalV3CandidatePartitionRecord::Complete {
            page_request_sha256s,
            ..
        } = record
        else {
            unreachable!();
        };
        for request_sha256 in page_request_sha256s {
            let checkpoint = read_committed_page_checkpoint(state, request_sha256).unwrap();
            collection
                .candidates
                .extend(decode_page(&checkpoint).unwrap().candidates);
            collection
                .manifest
                .page_checkpoint_sha256s
                .push(checkpoint.checkpoint_sha256);
        }
    }
    collection.manifest.candidate_count = collection.candidates.len();
    collection.manifest.stream_task =
        prepare_historical_v3_stream_task(protocol, collection.candidates.clone()).unwrap();
    collection.manifest = seal_collection_manifest(collection.manifest.clone()).unwrap();
}

async fn assert_pagination_rejected(pages: usize, repeat_cursor: bool, message: &str) {
    let fixtures = source_fixture::fixtures();
    let prior = source_fixture::prior_identity_seal();
    let protocol = source_fixture::protocol(&prior, &fixtures);
    let artifacts = source_fixture::artifacts(&fixtures);
    let audit =
        crate::benchmark::release::history_v3_source_binding::bind_historical_v3_source_frames(
            &protocol, &prior, &artifacts,
        )
        .unwrap();
    let live_state = tempfile::tempdir().unwrap();
    let error = collect_historical_v3_candidates(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        live_state.path(),
        &mut PaginationTransport {
            pages,
            repeat_cursor,
        },
    )
    .await
    .unwrap_err();
    assert!(error.contains(message), "{error}");

    let state = tempfile::tempdir().unwrap();
    let mut collection = collect_historical_v3_candidates(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &mut CollectionTransport {
            calls: 0,
            split_root: false,
        },
    )
    .await
    .unwrap();
    replace_go_pages(
        state.path(),
        &protocol,
        &mut collection,
        pages,
        repeat_cursor,
    );
    validate_historical_v3_candidate_collection_commitment(&protocol, &collection).unwrap();
    let error = validate_historical_v3_candidate_collection(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &collection,
    )
    .unwrap_err();
    assert!(error.contains(message), "{error}");

    let manifest = state.path().join("candidate-manifest.json");
    assert!(
        write_historical_v3_candidate_collection_manifest_new(
            &manifest,
            &protocol,
            &prior,
            &artifacts,
            &audit,
            state.path(),
            &collection,
        )
        .unwrap_err()
        .contains(message)
    );
    assert!(!manifest.exists());
    std::fs::write(&manifest, serde_json::to_vec(&collection.manifest).unwrap()).unwrap();
    assert!(
        read_historical_v3_candidate_collection_manifest(
            &manifest,
            &protocol,
            &prior,
            &artifacts,
            &audit,
            state.path(),
        )
        .unwrap_err()
        .contains(message)
    );
}

#[tokio::test]
async fn rehashed_repeated_cursor_chain_is_rejected_by_collection_and_replay() {
    assert_pagination_rejected(3, true, "cursor repeated").await;
}

#[tokio::test]
async fn rehashed_eleven_page_chain_is_rejected_by_collection_and_replay() {
    assert_pagination_rejected(11, false, "exceeded 1,000 results").await;
}

async fn assert_valid_pagination(pages: usize, repeat_cursor: bool) {
    let fixtures = source_fixture::fixtures();
    let prior = source_fixture::prior_identity_seal();
    let protocol = source_fixture::protocol(&prior, &fixtures);
    let artifacts = source_fixture::artifacts(&fixtures);
    let audit =
        crate::benchmark::release::history_v3_source_binding::bind_historical_v3_source_frames(
            &protocol, &prior, &artifacts,
        )
        .unwrap();
    let state = tempfile::tempdir().unwrap();
    let collection = collect_historical_v3_candidates(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &mut PaginationTransport {
            pages,
            repeat_cursor,
        },
    )
    .await
    .unwrap();
    assert_eq!(collection.candidates.len(), pages);
    let manifest = state.path().join("valid-manifest.json");
    write_historical_v3_candidate_collection_manifest_new(
        &manifest,
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &collection,
    )
    .unwrap();
    assert_eq!(
        read_historical_v3_candidate_collection_manifest(
            &manifest,
            &protocol,
            &prior,
            &artifacts,
            &audit,
            state.path(),
        )
        .unwrap(),
        collection
    );
    let mut resumed = FakeTransport {
        responses: VecDeque::new(),
        calls: 0,
    };
    assert_eq!(
        collect_historical_v3_candidates(
            &protocol,
            &prior,
            &artifacts,
            &audit,
            state.path(),
            &mut resumed,
        )
        .await
        .unwrap(),
        collection
    );
    assert_eq!(resumed.calls, 0);
}

#[tokio::test]
async fn ten_distinct_cursor_pages_collect_replay_publish_and_resume() {
    assert_valid_pagination(10, false).await;
}

#[tokio::test]
async fn terminal_cursor_may_repeat_without_being_consumed() {
    assert_valid_pagination(2, true).await;
}
