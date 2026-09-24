use super::*;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;

fn request() -> HistoricalV3CandidatePageRequest {
    seal_page_request(HistoricalV3CandidatePageRequest {
        schema_version: HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION,
        request_contract: REQUEST_CONTRACT.to_string(),
        protocol_sha256: "1".repeat(64),
        source_binding_audit_sha256: "2".repeat(64),
        query_document_sha256: sha256(GRAPHQL_QUERY.as_bytes()),
        partition: HistoricalV3CandidatePartition {
            language: HistoricalV3Language::Rust,
            repository_id: 42,
            name_with_owner: "example/repository".to_string(),
            path: "root".to_string(),
            merged_at_or_after_utc: "2025-01-01T00:00:00Z".to_string(),
            merged_at_or_before_utc: "2025-12-31T23:59:59Z".to_string(),
        },
        page_number: 1,
        after_cursor: None,
        request_sha256: String::new(),
    })
    .unwrap()
}

fn response(issue_count: usize, has_next_page: bool, end_cursor: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "data": {
            "search": {
                "issueCount": issue_count,
                "pageInfo": {
                    "hasNextPage": has_next_page,
                    "endCursor": end_cursor,
                },
                "nodes": if issue_count == 0 { Vec::new() } else { vec![serde_json::json!({
                    "number": 7,
                    "createdAt": "2025-04-01T00:00:00Z",
                    "updatedAt": "2025-04-02T00:00:00Z",
                    "closedAt": "2025-04-02T00:00:00Z",
                    "mergedAt": "2025-04-02T00:00:00Z",
                    "baseRefOid": "a".repeat(40),
                    "headRefOid": "b".repeat(40),
                    "mergeCommit": { "oid": "c".repeat(40) },
                    "repository": {
                        "databaseId": 42,
                        "nameWithOwner": "Example/Repository",
                    }
                })] },
            }
        },
        "errors": [],
    }))
    .unwrap()
}

fn response_for(
    request: &HistoricalV3CandidatePageRequest,
    issue_count: usize,
    pull_request_number: Option<u64>,
    has_next_page: bool,
    end_cursor: Option<&str>,
) -> Vec<u8> {
    let nodes = pull_request_number
        .map(|number| {
            vec![serde_json::json!({
                "number": number,
                "createdAt": request.partition.merged_at_or_after_utc,
                "updatedAt": request.partition.merged_at_or_after_utc,
                "closedAt": request.partition.merged_at_or_after_utc,
                "mergedAt": request.partition.merged_at_or_after_utc,
                "baseRefOid": format!("{number:040x}"),
                "headRefOid": format!("{:040x}", number + 100),
                "mergeCommit": { "oid": format!("{:040x}", number + 200) },
                "repository": {
                    "databaseId": request.partition.repository_id,
                    "nameWithOwner": request.partition.name_with_owner,
                }
            })]
        })
        .unwrap_or_default();
    serde_json::to_vec(&serde_json::json!({
        "data": {
            "search": {
                "issueCount": issue_count,
                "pageInfo": {
                    "hasNextPage": has_next_page,
                    "endCursor": end_cursor,
                },
                "nodes": nodes,
            }
        },
        "errors": [],
    }))
    .unwrap()
}

struct FakeTransport {
    responses: VecDeque<Vec<u8>>,
    calls: usize,
}

struct FaultTransport {
    responses: VecDeque<Result<Vec<u8>, String>>,
    calls: usize,
}

struct CollectionTransport {
    calls: usize,
    split_root: bool,
}

impl HistoricalV3CandidatePageTransport for CollectionTransport {
    fn fetch<'a>(
        &'a mut self,
        request: &'a HistoricalV3CandidatePageRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls += 1;
            let is_go = request.partition.language == HistoricalV3Language::Go;
            if self.split_root && is_go && request.partition.path == "root" {
                return Ok(response_for(request, 1_001, Some(7), false, None));
            }
            if self.split_root && is_go && request.partition.path == "rootL" {
                return Ok(response_for(request, 1, Some(7), false, None));
            }
            if !self.split_root && is_go && request.page_number == 1 {
                return Ok(response_for(request, 2, Some(7), true, Some("next")));
            }
            if !self.split_root && is_go && request.page_number == 2 {
                return Ok(response_for(request, 2, Some(8), false, None));
            }
            Ok(response_for(request, 0, None, false, None))
        })
    }
}

impl HistoricalV3CandidatePageTransport for FakeTransport {
    fn fetch<'a>(
        &'a mut self,
        _request: &'a HistoricalV3CandidatePageRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls += 1;
            self.responses
                .pop_front()
                .ok_or_else(|| "unexpected synthetic fetch".to_string())
        })
    }
}

impl HistoricalV3CandidatePageTransport for FaultTransport {
    fn fetch<'a>(
        &'a mut self,
        _request: &'a HistoricalV3CandidatePageRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls += 1;
            self.responses
                .pop_front()
                .ok_or_else(|| "unexpected synthetic fetch".to_string())?
        })
    }
}

#[test]
fn graphql_document_requests_only_locked_metadata() {
    for forbidden in [
        "title",
        "body",
        "comments",
        "reviews",
        "reactions",
        "labels",
        "assignees",
        "author",
    ] {
        assert!(!GRAPHQL_QUERY.contains(forbidden));
    }
    for required in [
        "number",
        "createdAt",
        "updatedAt",
        "closedAt",
        "mergedAt",
        "baseRefOid",
        "headRefOid",
        "mergeCommit",
        "databaseId",
    ] {
        assert!(GRAPHQL_QUERY.contains(required));
    }
}

#[test]
fn response_parser_rejects_partition_escape_and_unrequested_fields() {
    let request = request();
    let parsed = parse_candidate_page(&request, &response(1, false, Some("done"))).unwrap();
    assert_eq!(parsed.candidates.len(), 1);
    assert_eq!(parsed.candidates[0].pull_request_number, 7);

    let mut escaped: serde_json::Value = serde_json::from_slice(&response(1, false, None)).unwrap();
    escaped["data"]["search"]["nodes"][0]["repository"]["databaseId"] = 99.into();
    assert!(
        parse_candidate_page(&request, &serde_json::to_vec(&escaped).unwrap())
            .unwrap_err()
            .contains("repository partition")
    );

    let mut forbidden: serde_json::Value =
        serde_json::from_slice(&response(1, false, None)).unwrap();
    forbidden["data"]["search"]["nodes"][0]["title"] = "not requested".into();
    assert!(parse_candidate_page(&request, &serde_json::to_vec(&forbidden).unwrap()).is_err());
}

#[tokio::test]
async fn committed_raw_page_resumes_without_refetching() {
    let root = tempfile::tempdir().unwrap();
    let request = request();
    let mut first = FakeTransport {
        responses: VecDeque::from([response(1, false, None)]),
        calls: 0,
    };
    let (checkpoint, page) = load_or_fetch_page(root.path(), &request, &mut first)
        .await
        .unwrap();
    assert_eq!(first.calls, 1);
    assert_eq!(page.candidates.len(), 1);

    let mut resumed = FakeTransport {
        responses: VecDeque::new(),
        calls: 0,
    };
    let (same_checkpoint, same_page) = load_or_fetch_page(root.path(), &request, &mut resumed)
        .await
        .unwrap();
    assert_eq!(resumed.calls, 0);
    assert_eq!(same_checkpoint, checkpoint);
    assert_eq!(same_page, page);
}

#[tokio::test]
async fn failed_transport_does_not_commit_a_page_and_retries_the_same_request() {
    let root = tempfile::tempdir().unwrap();
    let request = request();
    let mut transport = FaultTransport {
        responses: VecDeque::from([
            Err("synthetic transport unavailable".to_string()),
            Ok(response(1, false, None)),
        ]),
        calls: 0,
    };
    assert!(
        load_or_fetch_page(root.path(), &request, &mut transport)
            .await
            .unwrap_err()
            .contains("transport unavailable")
    );
    assert!(!root.path().join("pages").exists());
    let (_, page) = load_or_fetch_page(root.path(), &request, &mut transport)
        .await
        .unwrap();
    assert_eq!(transport.calls, 2);
    assert_eq!(page.candidates.len(), 1);
    assert!(
        root.path()
            .join("pages")
            .join(format!("{}.json", request.request_sha256))
            .is_file()
    );
}

#[tokio::test]
async fn truncated_response_cannot_commit_and_retries_the_same_request() {
    let root = tempfile::tempdir().unwrap();
    let request = request();
    let complete = response(1, false, None);
    let mut transport = FaultTransport {
        responses: VecDeque::from([Ok(complete[..complete.len() / 2].to_vec()), Ok(complete)]),
        calls: 0,
    };
    assert!(
        load_or_fetch_page(root.path(), &request, &mut transport)
            .await
            .is_err()
    );
    assert!(!root.path().join("pages").exists());
    let (_, page) = load_or_fetch_page(root.path(), &request, &mut transport)
        .await
        .unwrap();
    assert_eq!(transport.calls, 2);
    assert_eq!(page.candidates.len(), 1);
}

#[tokio::test]
async fn partial_pending_page_is_removed_before_retry() {
    let root = tempfile::tempdir().unwrap();
    let request = request();
    let pages = root.path().join("pages");
    std::fs::create_dir(&pages).unwrap();
    let pending = pages.join(format!("{}.pending", request.request_sha256));
    std::fs::write(&pending, b"{\"incomplete\":").unwrap();
    let mut transport = FakeTransport {
        responses: VecDeque::from([response(1, false, None)]),
        calls: 0,
    };
    let (_, page) = load_or_fetch_page(root.path(), &request, &mut transport)
        .await
        .unwrap();
    assert_eq!(transport.calls, 1);
    assert_eq!(page.candidates.len(), 1);
    assert!(!pending.exists());
    assert!(
        pages
            .join(format!("{}.json", request.request_sha256))
            .is_file()
    );
}

#[tokio::test]
async fn fully_written_pending_page_is_adopted_without_refetching() {
    let root = tempfile::tempdir().unwrap();
    let request = request();
    let checkpoint = seal_page_checkpoint(request.clone(), &response(1, false, None)).unwrap();
    let pages = root.path().join("pages");
    std::fs::create_dir(&pages).unwrap();
    let pending = pages.join(format!("{}.pending", request.request_sha256));
    std::fs::write(&pending, serde_json::to_vec(&checkpoint).unwrap()).unwrap();

    let mut transport = FakeTransport {
        responses: VecDeque::new(),
        calls: 0,
    };
    let (recovered, page) = load_or_fetch_page(root.path(), &request, &mut transport)
        .await
        .unwrap();
    assert_eq!(transport.calls, 0);
    assert_eq!(recovered, checkpoint);
    assert_eq!(page.candidates.len(), 1);
    assert!(!pending.exists());
    assert!(
        pages
            .join(format!("{}.json", request.request_sha256))
            .is_file()
    );
}

#[test]
fn raw_response_and_request_tampering_are_rejected() {
    let request = request();
    let checkpoint = seal_page_checkpoint(request.clone(), &response(1, false, None)).unwrap();
    validate_page_checkpoint(&request, &checkpoint).unwrap();

    let mut changed = checkpoint.clone();
    changed.response_base64.push('A');
    assert!(validate_page_checkpoint(&request, &changed).is_err());

    let mut changed_request = request.clone();
    changed_request.page_number = 2;
    assert!(validate_page_checkpoint(&changed_request, &checkpoint).is_err());
}

#[test]
fn over_limit_partition_splits_into_disjoint_inclusive_ranges() {
    let partition = request().partition;
    let (left, right) = split_partition(&partition).unwrap();
    assert_eq!(
        parse_utc_second(&left.merged_at_or_before_utc).unwrap() + 1,
        parse_utc_second(&right.merged_at_or_after_utc).unwrap()
    );
    assert_eq!(left.path, "rootL");
    assert_eq!(right.path, "rootR");
}

#[tokio::test]
async fn full_collection_replays_source_binding_pagination_and_resume() {
    use super::super::history_v3_source_binding::tests as source_fixture;

    let fixtures = source_fixture::fixtures();
    let prior = source_fixture::prior_identity_seal();
    let protocol = source_fixture::protocol(&prior, &fixtures);
    let artifacts = source_fixture::artifacts(&fixtures);
    let audit = super::super::history_v3_source_binding::bind_historical_v3_source_frames(
        &protocol, &prior, &artifacts,
    )
    .unwrap();
    let state = tempfile::tempdir().unwrap();
    let mut transport = CollectionTransport {
        calls: 0,
        split_root: false,
    };
    let collection = collect_historical_v3_candidates(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &mut transport,
    )
    .await
    .unwrap();
    assert_eq!(transport.calls, 7);
    assert_eq!(collection.candidates.len(), 2);
    assert_eq!(collection.manifest.repositories.len(), 6);
    assert_eq!(collection.manifest.partitions.len(), 6);
    validate_historical_v3_candidate_collection(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &collection,
    )
    .unwrap();

    let mut resumed = FakeTransport {
        responses: VecDeque::new(),
        calls: 0,
    };
    let resumed_collection = collect_historical_v3_candidates(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &mut resumed,
    )
    .await
    .unwrap();
    assert_eq!(resumed.calls, 0);
    assert_eq!(resumed_collection, collection);

    let manifest_path = state.path().join("collection-manifest.json");
    let pending_path = state.path().join(format!(
        ".collection-manifest.json.{}.pending",
        collection.manifest.manifest_sha256
    ));
    std::fs::write(&pending_path, b"{").unwrap();
    write_historical_v3_candidate_collection_manifest_new(
        &manifest_path,
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &collection,
    )
    .unwrap();
    assert!(!pending_path.exists());
    let loaded = read_historical_v3_candidate_collection_manifest(
        &manifest_path,
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
    )
    .unwrap();
    assert_eq!(loaded, collection);

    let recovered_path = state.path().join("recovered-manifest.json");
    let recovered_pending = state.path().join(format!(
        ".recovered-manifest.json.{}.pending",
        collection.manifest.manifest_sha256
    ));
    std::fs::write(
        &recovered_pending,
        serde_json::to_vec(&collection.manifest).unwrap(),
    )
    .unwrap();
    write_historical_v3_candidate_collection_manifest_new(
        &recovered_path,
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &collection,
    )
    .unwrap();
    assert!(!recovered_pending.exists());
    assert_eq!(
        read_historical_v3_candidate_collection_manifest(
            &recovered_path,
            &protocol,
            &prior,
            &artifacts,
            &audit,
            state.path(),
        )
        .unwrap(),
        collection
    );
    assert!(
        write_historical_v3_candidate_collection_manifest_new(
            &manifest_path,
            &protocol,
            &prior,
            &artifacts,
            &audit,
            state.path(),
            &collection,
        )
        .is_err()
    );

    let mut changed = collection.manifest.clone();
    changed.candidate_count += 1;
    std::fs::write(&manifest_path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(
        read_historical_v3_candidate_collection_manifest(
            &manifest_path,
            &protocol,
            &prior,
            &artifacts,
            &audit,
            state.path(),
        )
        .is_err()
    );

    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&collection.manifest).unwrap(),
    )
    .unwrap();
    let page = collection
        .manifest
        .partitions
        .iter()
        .find_map(|partition| match partition {
            HistoricalV3CandidatePartitionRecord::Complete {
                page_request_sha256s,
                ..
            } => page_request_sha256s.first(),
            HistoricalV3CandidatePartitionRecord::Split { .. } => None,
        })
        .unwrap();
    std::fs::remove_file(state.path().join("pages").join(format!("{page}.json"))).unwrap();
    assert!(
        read_historical_v3_candidate_collection_manifest(
            &manifest_path,
            &protocol,
            &prior,
            &artifacts,
            &audit,
            state.path(),
        )
        .is_err()
    );

    std::fs::write(&manifest_path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let error = read_historical_v3_candidate_collection_manifest(
        &manifest_path,
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
    )
    .unwrap_err();
    assert!(error.contains("manifest commitment changed"));
}

#[tokio::test]
async fn full_collection_commits_and_replays_the_split_tree() {
    use super::super::history_v3_source_binding::tests as source_fixture;

    let fixtures = source_fixture::fixtures();
    let prior = source_fixture::prior_identity_seal();
    let protocol = source_fixture::protocol(&prior, &fixtures);
    let artifacts = source_fixture::artifacts(&fixtures);
    let audit = super::super::history_v3_source_binding::bind_historical_v3_source_frames(
        &protocol, &prior, &artifacts,
    )
    .unwrap();
    let state = tempfile::tempdir().unwrap();
    let mut transport = CollectionTransport {
        calls: 0,
        split_root: true,
    };
    let collection = collect_historical_v3_candidates(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &mut transport,
    )
    .await
    .unwrap();
    assert_eq!(transport.calls, 8);
    assert_eq!(collection.candidates.len(), 1);
    assert!(matches!(
        collection.manifest.partitions.first(),
        Some(HistoricalV3CandidatePartitionRecord::Split {
            issue_count: 1_001,
            ..
        })
    ));
    validate_historical_v3_candidate_collection(
        &protocol,
        &prior,
        &artifacts,
        &audit,
        state.path(),
        &collection,
    )
    .unwrap();
}
