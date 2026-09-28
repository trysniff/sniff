use super::super::history_v3_identical_tests::tests::{passing_events, prepared_rank};
use super::super::history_v3_rank_journal::{materialized_roots, rank_workspace};
use super::super::intentional_boundary_source_census::intentional_boundary_file_records_typed;
use super::super::{
    HistoricalV3ExecutionSide, HistoricalV3IdenticalTestExclusionReason,
    HistoricalV3IdenticalTestExecutionError, HistoricalV3IdenticalTestExecutionRequest,
    HistoricalV3IdenticalTestExecutor, HistoricalV3IdenticalTestOutcome, HistoricalV3RankJournal,
    HistoricalV3RawIdenticalTestExecution, HistoricalV3SourceReviewInputs,
    IntentionalBoundarySemanticCallFacts, IntentionalBoundarySemanticDispatch,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticOccurrenceRole,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticReferenceTarget,
    IntentionalBoundarySemanticRelationshipFacts, IntentionalBoundarySemanticRelationshipKind,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSourceReference,
    historical_v3_rank_identity, run_historical_v3_identical_tests_stage,
};
use super::{
    run_historical_v3_source_review_stage, validate_historical_v3_source_review_bundle,
    verify_historical_v3_source_review_rank,
};
use sha2::Digest;
use std::fs;

struct PassingExecutor;

impl HistoricalV3IdenticalTestExecutor for PassingExecutor {
    fn recover(&self, _identity: &str) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        Ok(())
    }

    fn execute(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        Ok(HistoricalV3RawIdenticalTestExecution {
            image_digest: request.recipe.image_digest.clone(),
            toolchain_manifest_sha256: request.recipe.toolchain_manifest_sha256.clone(),
            dependency_store_sha256: request.recipe.dependency_store_sha256.clone(),
            events: passing_events(request.recipe),
            outcome: HistoricalV3IdenticalTestOutcome::Passed,
        })
    }
}

struct ExcludingExecutor;

impl HistoricalV3IdenticalTestExecutor for ExcludingExecutor {
    fn recover(&self, _identity: &str) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        Ok(())
    }

    fn execute(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        let mut events = passing_events(request.recipe);
        let mut event = events.remove(0);
        event.exit_code = Some(1);
        Ok(HistoricalV3RawIdenticalTestExecution {
            image_digest: request.recipe.image_digest.clone(),
            toolchain_manifest_sha256: request.recipe.toolchain_manifest_sha256.clone(),
            dependency_store_sha256: request.recipe.dependency_store_sha256.clone(),
            events: vec![event],
            outcome: HistoricalV3IdenticalTestOutcome::Excluded {
                reason: HistoricalV3IdenticalTestExclusionReason::PreparationFailed {
                    side: HistoricalV3ExecutionSide::Base,
                    command_index: 0,
                },
            },
        })
    }
}

#[tokio::test]
async fn commits_blind_bundle_rejects_rehashed_semantic_tamper_and_resumes_without_git() {
    let (fixture, protocol, collection, journal, workspace, _) = prepared_rank().await;
    let execution = run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &PassingExecutor,
    )
    .unwrap();
    assert!(
        verify_historical_v3_source_review_rank(&protocol, &collection, 1, journal.path(),)
            .is_err()
    );
    let first = run_historical_v3_source_review_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    let proof =
        verify_historical_v3_source_review_rank(&protocol, &collection, 1, journal.path()).unwrap();
    assert_eq!(proof.bundle(), first.artifact.as_ref());
    assert_eq!(
        proof.inputs(&protocol, &collection).qualification.rank,
        proof.rank().clone()
    );
    assert!(!first.resumed);
    assert!(first.artifact.source_only);
    assert!(!first.artifact.repository_identity_included);
    assert!(!first.artifact.change_metadata_included);
    assert!(!first.artifact.sniff_output_included);
    assert!(!first.artifact.prior_labels_included);
    assert!(!first.artifact.methods.is_empty());
    assert!(first.artifact.context.resolved_context_complete);
    let encoded = serde_json::to_string(&first.artifact).unwrap();
    assert!(!encoded.contains("name_with_owner"));
    assert!(!encoded.contains("pull_request_number"));
    assert!(!encoded.contains("retained_stdout_base64"));
    assert!(!encoded.contains("retained_stderr_base64"));

    let mut tampered = (*first.artifact).clone();
    tampered.methods[0].semantic.symbol_name = "forged".to_string();
    tampered = super::commitment::seal_source_review_bundle(tampered).unwrap();
    let inputs = super::store::read_inputs(
        HistoricalV3RankJournal::open(
            journal.path(),
            &historical_v3_rank_identity(&protocol, &collection, 1).unwrap(),
        )
        .unwrap()
        .history(),
    )
    .unwrap();
    let review_inputs = HistoricalV3SourceReviewInputs {
        protocol: &protocol,
        collection: &collection,
        materialization: &inputs.materialization,
        source_census: &inputs.source_census,
        semantic_census: &inputs.semantic_census,
        qualification: &inputs.qualification,
        recipe: &inputs.recipe,
        execution: &inputs.execution,
    };
    assert!(
        validate_historical_v3_source_review_bundle(&review_inputs, &tampered)
            .unwrap_err()
            .contains("method changed")
    );

    let mut tampered_context = (*first.artifact).clone();
    tampered_context.context.resolved_context_complete = false;
    tampered_context = super::commitment::seal_source_review_bundle(tampered_context).unwrap();
    assert!(
        validate_historical_v3_source_review_bundle(&review_inputs, &tampered_context)
            .unwrap_err()
            .contains("context selection changed")
    );

    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let destination = rank_workspace(workspace.path(), &identity).unwrap();
    fs::rename(
        destination.join("repository/.git"),
        destination.join("repository/.git-disabled"),
    )
    .unwrap();
    let resumed = run_historical_v3_source_review_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    assert!(resumed.resumed);
    assert_eq!(resumed.artifact, first.artifact);
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    assert_eq!(persisted.history().len(), 7);
    assert_eq!(persisted.next_stage(), None);
    assert!(matches!(
        execution,
        super::super::HistoricalV3IdenticalTestsStageRun::Passed { .. }
    ));
    drop(fixture);
}

#[tokio::test]
async fn selects_and_validates_resolved_caller_and_contract_context() {
    let (_fixture, protocol, collection, journal, workspace, _) = prepared_rank().await;
    run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &PassingExecutor,
    )
    .unwrap();
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let history = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    let inputs = super::store::read_inputs(history.history()).unwrap();
    let mut semantics = inputs.semantic_census.clone();
    let mut sources = inputs.source_census.clone();
    let roots = materialized_roots(&rank_workspace(workspace.path(), &identity).unwrap());
    let mut base_records = intentional_boundary_file_records_typed(
        &roots.base_root,
        &inputs.source_census.base.inventory,
        &inputs.source_census.base.source_census,
    )
    .unwrap();
    let mut merge_records = intentional_boundary_file_records_typed(
        &roots.merge_root,
        &inputs.source_census.merge.inventory,
        &inputs.source_census.merge.source_census,
    )
    .unwrap();
    for (snapshot, source, records) in [
        (&mut semantics.base, &mut sources.base, &mut base_records),
        (&mut semantics.merge, &mut sources.merge, &mut merge_records),
    ] {
        let methods = &mut snapshot.semantic_census.methods;
        let total = methods
            .iter()
            .position(|method| method.symbol_name == "total")
            .unwrap();
        let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } =
            &methods[total].status
        else {
            panic!("total must resolve")
        };
        let total_id = symbol.symbol_id.clone();
        let mut caller_symbol = (**symbol).clone();
        caller_symbol.symbol_id = "fixture::consumer".to_string();
        caller_symbol.display_name = Some("consumer".to_string());
        let mut caller = methods[total].clone();
        caller.parser_unit_id = "fixture::consumer-parser".to_string();
        caller.symbol_name = "consumer".to_string();
        caller.start_line = 5;
        caller.end_line = 5;
        caller.status = IntentionalBoundarySemanticMethodStatus::Resolved {
            symbol: Box::new(caller_symbol),
            joined_definition: None,
        };
        caller.calls.clear();
        caller.relationships.clear();
        methods.push(caller);
        let mut parsed = records[0].methods[0].clone();
        parsed.name = "consumer".to_string();
        parsed.source = "pub fn consumer() -> i32 { total() }".to_string();
        parsed.start_line = 5;
        parsed.end_line = 5;
        records[0].methods.push(parsed.clone());
        let mut source_method = source.source_census.source_files[0].methods[0].clone();
        source_method.parser_unit_id = "fixture::consumer-parser".to_string();
        source_method.symbol_name = "consumer".to_string();
        source_method.start_line = 5;
        source_method.end_line = 5;
        source_method.source_sha256 =
            format!("{:x}", sha2::Sha256::digest(parsed.source.as_bytes()));
        source.source_census.source_files[0]
            .methods
            .push(source_method);
        let location = super::super::IntentionalBoundarySemanticRange {
            repository_path: methods[total].repository_path.clone(),
            start_line_zero_based: 4,
            start_character_zero_based: 0,
            end_line_zero_based: 4,
            end_character_zero_based: 1,
        };
        methods[total]
            .calls
            .push(IntentionalBoundarySemanticCallFacts {
                caller: "fixture::consumer".to_string(),
                callee: IntentionalBoundarySemanticResolution::Resolved {
                    value: total_id.clone(),
                },
                callsite: location,
                dispatch: IntentionalBoundarySemanticDispatch::Static,
            });
        methods[total]
            .relationships
            .push(IntentionalBoundarySemanticRelationshipFacts {
                source: total_id,
                target: "fixture::consumer".to_string(),
                kind: IntentionalBoundarySemanticRelationshipKind::Definition,
            });
    }
    let context = super::context::build_context(
        &inputs.qualification,
        &sources,
        &semantics,
        &base_records,
        &merge_records,
    )
    .unwrap();
    assert!(context.resolved_context_complete);
    assert_eq!(context.items.len(), 4);
    assert_eq!(context.sources.len(), 2);
    assert!(context.sources.iter().all(|source| matches!(source,
                super::HistoricalV3ReviewContextSource::Method { method }
                    if method.symbol_name == "consumer")));
    assert!(
        context
            .items
            .iter()
            .any(|item| item.role == super::HistoricalV3ReviewContextRole::DirectCaller)
    );
    assert!(
        context
            .items
            .iter()
            .any(|item| item.role == super::HistoricalV3ReviewContextRole::ContractDefinition)
    );
    super::context::validate_context(&context, &inputs.qualification, &sources, &semantics)
        .unwrap();
    let mut tampered = context.clone();
    let super::HistoricalV3ReviewContextSource::Method { method } = &mut tampered.sources[0] else {
        panic!("expected method context")
    };
    method.source = "pub fn consumer() -> i32 { 0 }".to_string();
    assert!(
        super::context::validate_context(&tampered, &inputs.qualification, &sources, &semantics)
            .is_err()
    );
    let owner_id = "fixture::owner-type".to_string();
    let owner_location = super::super::IntentionalBoundarySemanticRange {
        repository_path: sources.base.source_census.source_files[0]
            .repository_path
            .clone(),
        start_line_zero_based: 0,
        start_character_zero_based: 0,
        end_line_zero_based: 0,
        end_character_zero_based: 3,
    };
    semantics.base.semantic_census.source_references.push(
        IntentionalBoundarySemanticSourceReference {
            indexer: semantics.base.semantic_census.methods[0].indexer,
            location: owner_location,
            roles: vec![IntentionalBoundarySemanticOccurrenceRole::Definition],
            target: IntentionalBoundarySemanticResolution::Resolved {
                value: IntentionalBoundarySemanticReferenceTarget {
                    symbol_id: owner_id.clone(),
                    provider_identity: owner_id.clone(),
                    display_name: Some("Owner".to_string()),
                    provider_kind: "type".to_string(),
                    origin: IntentionalBoundarySemanticOrigin::Repository,
                },
            },
        },
    );
    let total = semantics
        .base
        .semantic_census
        .methods
        .iter_mut()
        .find(|method| method.symbol_name == "total")
        .unwrap();
    let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } = &mut total.status else {
        panic!("total must resolve")
    };
    symbol.owner = Some(IntentionalBoundarySemanticResolution::Resolved { value: owner_id });
    let with_owner = super::context::build_context(
        &inputs.qualification,
        &sources,
        &semantics,
        &base_records,
        &merge_records,
    )
    .unwrap();
    assert!(with_owner.resolved_context_complete);
    assert!(with_owner.sources.iter().any(|source| matches!(source,
        super::HistoricalV3ReviewContextSource::File { source, .. }
            if source == &base_records[0].source)));
    super::context::validate_context(&with_owner, &inputs.qualification, &sources, &semantics)
        .unwrap();
    let definition = semantics
        .base
        .semantic_census
        .source_references
        .last()
        .unwrap()
        .clone();
    for offset in 1..5 {
        let mut repeated = definition.clone();
        repeated.location.start_character_zero_based = offset;
        repeated.location.end_character_zero_based = offset + 1;
        semantics
            .base
            .semantic_census
            .source_references
            .push(repeated);
    }
    let mut declaration = definition;
    let IntentionalBoundarySemanticResolution::Resolved { value } = &mut declaration.target else {
        panic!("expected resolved definition")
    };
    value.symbol_id = "fixture::consumer".to_string();
    declaration.location.start_character_zero_based = 6;
    declaration.location.end_character_zero_based = 7;
    semantics
        .base
        .semantic_census
        .source_references
        .push(declaration);
    let repeated = super::context::build_context(
        &inputs.qualification,
        &sources,
        &semantics,
        &base_records,
        &merge_records,
    )
    .unwrap();
    assert!(repeated.resolved_context_complete);
    assert_eq!(repeated.sources.len(), 3);
    assert!(
        repeated
            .items
            .iter()
            .filter(|item| item.definition.is_some())
            .count()
            >= 6
    );
    assert!(
        repeated
            .items
            .iter()
            .any(|item| item.target_symbol_id == "fixture::consumer" && item.definition.is_some())
    );
    super::context::validate_context(&repeated, &inputs.qualification, &sources, &semantics)
        .unwrap();
    let mut invalid_range = semantics
        .base
        .semantic_census
        .source_references
        .last()
        .unwrap()
        .clone();
    invalid_range.location.start_character_zero_based = 9_999;
    invalid_range.location.end_character_zero_based = 10_000;
    semantics
        .base
        .semantic_census
        .source_references
        .push(invalid_range);
    assert!(
        super::context::build_context(
            &inputs.qualification,
            &sources,
            &semantics,
            &base_records,
            &merge_records,
        )
        .unwrap_err()
        .contains("range escapes frozen source")
    );
    semantics.base.semantic_census.source_references.pop();
    let mut forged_file = with_owner.clone();
    let file_index = forged_file
        .sources
        .iter()
        .position(|item| matches!(item, super::HistoricalV3ReviewContextSource::File { .. }))
        .unwrap();
    let super::HistoricalV3ReviewContextSource::File { source, .. } =
        &mut forged_file.sources[file_index]
    else {
        panic!("expected file context")
    };
    source.push_str("\nforged");
    assert!(
        super::context::validate_context(&forged_file, &inputs.qualification, &sources, &semantics)
            .is_err()
    );
    let total = semantics
        .base
        .semantic_census
        .methods
        .iter_mut()
        .find(|method| method.symbol_name == "total")
        .unwrap();
    let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } = &total.status else {
        panic!("total must resolve")
    };
    let total_id = symbol.symbol_id.clone();
    total
        .relationships
        .push(IntentionalBoundarySemanticRelationshipFacts {
            source: total_id,
            target: "fixture::missing_contract".to_string(),
            kind: IntentionalBoundarySemanticRelationshipKind::Definition,
        });
    let incomplete = super::context::build_context(
        &inputs.qualification,
        &sources,
        &semantics,
        &base_records,
        &merge_records,
    )
    .unwrap();
    assert!(!incomplete.resolved_context_complete);
    assert!(
        incomplete
            .gaps
            .iter()
            .any(|gap| gap.reason == super::HistoricalV3ReviewContextGapReason::NoVerifiableSource)
    );
}

#[tokio::test]
async fn excluded_identical_tests_cannot_publish_a_source_review_bundle() {
    let (_fixture, protocol, collection, journal, workspace, _) = prepared_rank().await;
    run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &ExcludingExecutor,
    )
    .unwrap();
    let error = run_historical_v3_source_review_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap_err();
    assert!(error.detail.contains("requires completed identical tests"));
}
