use super::*;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;

struct LocalCandidateTransport {
    base: String,
    head: String,
    merge: String,
    calls: usize,
}

impl HistoricalV3CandidatePageTransport for LocalCandidateTransport {
    fn fetch<'a>(
        &'a mut self,
        request: &'a HistoricalV3CandidatePageRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls += 1;
            let rust = request.partition.language == HistoricalV3Language::Rust;
            let nodes = if rust {
                vec![serde_json::json!({
                    "number": 7,
                    "createdAt": request.partition.merged_at_or_after_utc,
                    "updatedAt": request.partition.merged_at_or_after_utc,
                    "closedAt": request.partition.merged_at_or_after_utc,
                    "mergedAt": request.partition.merged_at_or_after_utc,
                    "baseRefOid": self.base,
                    "headRefOid": self.head,
                    "mergeCommit": { "oid": self.merge },
                    "repository": {
                        "databaseId": request.partition.repository_id,
                        "nameWithOwner": request.partition.name_with_owner,
                    },
                })]
            } else {
                Vec::new()
            };
            serde_json::to_vec(&serde_json::json!({
                "data": {
                    "repository": {
                        "databaseId": request.partition.repository_id,
                        "nameWithOwner": request.partition.name_with_owner,
                    },
                    "search": {
                        "issueCount": nodes.len(),
                        "pageInfo": { "hasNextPage": false, "endCursor": null },
                        "nodes": nodes,
                    },
                },
                "errors": [],
            }))
            .map_err(|error| error.to_string())
        })
    }
}

#[tokio::test]
async fn replayed_v2_frame_reaches_sealed_review_but_not_unproven_stop() {
    use super::history_v3_agent_review::tests::{PROMPT, response, reviewer};
    use super::history_v3_census_v2_binding::tests::fixture as census_fixture;
    use super::history_v3_label_review::tests::{PassingExecutor, decision_for_methods};
    use super::history_v3_semantic_census::tests as semantic_fixture;
    use super::history_v3_test_recipe::tests::prepare_qualified_rank;

    let (source_root, manifest, prior, mut protocol) = census_fixture();
    protocol
        .model_review_policy
        .as_mut()
        .unwrap()
        .approved_prompt_sha256 = format!("{:x}", Sha256::digest(PROMPT));
    let protocol = seal_historical_v3_protocol(protocol).unwrap();
    let source = HistoricalV3PublicIdCensusV2Artifact {
        manifest: &manifest,
        artifact_root: source_root.path(),
    };
    let binding =
        bind_historical_v3_public_id_census_v2_frames(&protocol, &prior, &source).unwrap();
    let population = binding.resolvable_population.as_ref().unwrap();
    assert_eq!(population.resolved_in_window_count, 6);
    assert_eq!(population.crawled_null_count, 1);

    let git = semantic_fixture::fixture();
    let (base, head, merge) = git.candidate_commits();
    let mut transport = LocalCandidateTransport {
        base: base.to_string(),
        head: head.to_string(),
        merge: merge.to_string(),
        calls: 0,
    };
    let state = tempfile::tempdir().unwrap();
    let collection = collect_historical_v3_candidates_from_census_v2(
        &protocol,
        &prior,
        &source,
        &binding,
        state.path(),
        &mut transport,
    )
    .await
    .unwrap();
    assert_eq!(transport.calls, 6);
    assert_eq!(collection.candidates.len(), 1);
    assert_eq!(
        collection.candidates[0].language,
        HistoricalV3Language::Rust
    );
    assert_eq!(collection.candidates[0].pull_request_number, 7);
    assert_eq!(collection.candidates[0].base_commit, base);
    assert_eq!(collection.candidates[0].head_commit, head);
    assert_eq!(collection.candidates[0].merge_commit, merge);

    let collection_path = state.path().join("candidate-manifest.json");
    write_historical_v3_candidate_collection_manifest_new_from_census_v2(
        &collection_path,
        &protocol,
        &prior,
        &source,
        &binding,
        state.path(),
        &collection,
    )
    .unwrap();
    assert_eq!(
        read_historical_v3_candidate_collection_manifest_from_census_v2(
            &collection_path,
            &protocol,
            &prior,
            &source,
            &binding,
            state.path(),
        )
        .unwrap(),
        collection
    );

    let journal_root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    prepare_qualified_rank(
        &protocol,
        &collection,
        &git,
        journal_root.path(),
        workspace.path(),
    )
    .await;
    run_historical_v3_test_recipe_stage(&protocol, &collection, 1, journal_root.path()).unwrap();
    run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal_root.path(),
        workspace.path(),
        &PassingExecutor,
    )
    .unwrap();
    let source_review = run_historical_v3_source_review_stage(
        &protocol,
        &collection,
        1,
        journal_root.path(),
        workspace.path(),
    )
    .unwrap();
    let bundle = &source_review.artifact;
    assert!(!bundle.methods.is_empty());

    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let journal = HistoricalV3RankJournal::open(journal_root.path(), &identity).unwrap();
    let history = journal.history();
    let materialization: HistoricalV3Materialization = history[0].read_artifact().unwrap().unwrap();
    let source_census: HistoricalV3SourceCensus = history[1].read_artifact().unwrap().unwrap();
    let semantic_census: HistoricalV3SemanticCensus = history[2].read_artifact().unwrap().unwrap();
    let qualification: HistoricalV3MechanicalQualification =
        history[3].read_artifact().unwrap().unwrap();
    let recipe: HistoricalV3TestRecipe = history[4].read_artifact().unwrap().unwrap();
    let execution: HistoricalV3IdenticalTests = history[5].read_artifact().unwrap().unwrap();
    let inputs = HistoricalV3SourceReviewInputs {
        protocol: &protocol,
        collection: &collection,
        materialization: &materialization,
        source_census: &source_census,
        semantic_census: &semantic_census,
        qualification: &qualification,
        recipe: &recipe,
        execution: &execution,
    };
    let assignment = prepare_historical_v3_agent_assignment(&inputs, bundle, PROMPT).unwrap();
    let decision = decision_for_methods(&bundle.methods, HistoricalV3ReviewerVerdict::Clean);
    let first = seal_historical_v3_agent_review(
        &inputs,
        bundle,
        PROMPT,
        response(
            reviewer(&assignment.agent_ids[0], "offline-a"),
            decision.clone(),
        ),
    )
    .unwrap();
    let second = seal_historical_v3_agent_review(
        &inputs,
        bundle,
        PROMPT,
        response(reviewer(&assignment.agent_ids[1], "offline-b"), decision),
    )
    .unwrap();
    let audit =
        audit_historical_v3_agent_reviews(&inputs, bundle, PROMPT, &assignment, &first, &second)
            .unwrap();
    validate_historical_v3_agent_audit(
        &inputs,
        bundle,
        PROMPT,
        &assignment,
        &first,
        &second,
        &audit,
    )
    .unwrap();
    assert!(audit.tier_agreement);

    let stop_error = prepare_historical_v3_stop_artifact(
        &protocol,
        &collection,
        HistoricalV3Language::Rust,
        &[],
    )
    .unwrap_err();
    assert!(stop_error.contains("requires proven prior-cohort repository IDs"));
}
