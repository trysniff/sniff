use super::super::history_v3_identical_tests::tests::{passing_events, prepared_rank};
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3IdenticalTestExecutionError,
    HistoricalV3IdenticalTestExecutionRequest, HistoricalV3IdenticalTestExecutor,
    HistoricalV3IdenticalTestOutcome, HistoricalV3IdenticalTests, HistoricalV3LabelStatus,
    HistoricalV3Materialization, HistoricalV3MechanicalQualification, HistoricalV3Protocol,
    HistoricalV3RankJournal, HistoricalV3RawIdenticalTestExecution, HistoricalV3ReviewDecision,
    HistoricalV3Reviewer, HistoricalV3ReviewerVerdict, HistoricalV3SemanticCensus,
    HistoricalV3SourceCensus, HistoricalV3SourceReviewBundle, HistoricalV3SourceReviewInputs,
    HistoricalV3SourceSide, HistoricalV3TestRecipe, historical_v3_rank_identity,
    run_historical_v3_identical_tests_stage, run_historical_v3_source_review_stage,
};
use super::{
    HistoricalV3LabelWorksheet, HistoricalV3SourceCitation, audit_historical_v3_label_reviews,
    prepare_historical_v3_label_review, read_historical_v3_label_worksheet,
    validate_historical_v3_label_audit, validate_historical_v3_label_review,
    write_historical_v3_label_worksheet_new,
};
use crate::product_contract::SlopPattern;

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

pub(crate) struct ReviewFixture {
    protocol: HistoricalV3Protocol,
    collection: HistoricalV3CandidateCollection,
    materialization: HistoricalV3Materialization,
    source_census: HistoricalV3SourceCensus,
    semantic_census: HistoricalV3SemanticCensus,
    qualification: HistoricalV3MechanicalQualification,
    recipe: HistoricalV3TestRecipe,
    execution: HistoricalV3IdenticalTests,
    pub(crate) bundle: HistoricalV3SourceReviewBundle,
}

impl ReviewFixture {
    pub(crate) fn inputs(&self) -> HistoricalV3SourceReviewInputs<'_> {
        HistoricalV3SourceReviewInputs {
            protocol: &self.protocol,
            collection: &self.collection,
            materialization: &self.materialization,
            source_census: &self.source_census,
            semantic_census: &self.semantic_census,
            qualification: &self.qualification,
            recipe: &self.recipe,
            execution: &self.execution,
        }
    }

    pub(crate) fn worksheet(
        &self,
        reviewer_id: &str,
        verdict: HistoricalV3ReviewerVerdict,
    ) -> HistoricalV3LabelWorksheet {
        let mut worksheet =
            prepare_historical_v3_label_review(&self.inputs(), &self.bundle).unwrap();
        worksheet.reviewer = Some(reviewer(reviewer_id));
        worksheet.task.decision = decision(&worksheet, verdict);
        worksheet
    }
}

#[tokio::test]
async fn prepares_blank_source_only_task_and_writes_it_create_new() {
    let fixture = review_fixture().await;
    let worksheet = prepare_historical_v3_label_review(&fixture.inputs(), &fixture.bundle).unwrap();
    assert!(worksheet.reviewer.is_none());
    assert_eq!(worksheet.task.decision, HistoricalV3ReviewDecision::blank());
    let encoded = serde_json::to_string(&worksheet).unwrap();
    assert!(!encoded.contains("name_with_owner"));
    assert!(!encoded.contains("pull_request_number"));
    assert!(!encoded.contains("retained_stdout_base64"));

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("review.json");
    write_historical_v3_label_worksheet_new(&path, &worksheet).unwrap();
    assert_eq!(
        read_historical_v3_label_worksheet(&path).unwrap(),
        worksheet
    );
    assert!(
        write_historical_v3_label_worksheet_new(&path, &worksheet)
            .unwrap_err()
            .contains("failed to create")
    );
}

#[tokio::test]
async fn accepts_only_two_distinct_human_reviews_over_the_immutable_task() {
    let fixture = review_fixture().await;
    let first = fixture.worksheet("reviewer-a", HistoricalV3ReviewerVerdict::Slop);
    let second = fixture.worksheet("reviewer-b", HistoricalV3ReviewerVerdict::Slop);
    validate_historical_v3_label_review(&fixture.inputs(), &fixture.bundle, &first).unwrap();
    let audit = audit_historical_v3_label_reviews(
        &fixture.inputs(),
        &fixture.bundle,
        &[first.clone(), second.clone()],
    )
    .unwrap();
    assert_eq!(audit.status, HistoricalV3LabelStatus::Accepted);
    assert_eq!(audit.labels.len(), 2);
    validate_historical_v3_label_audit(
        &fixture.inputs(),
        &fixture.bundle,
        &[first.clone(), second.clone()],
        &audit,
    )
    .unwrap();
    let mut tampered_audit = audit;
    tampered_audit.status = HistoricalV3LabelStatus::Rejected;
    assert!(
        validate_historical_v3_label_audit(
            &fixture.inputs(),
            &fixture.bundle,
            &[first.clone(), second.clone()],
            &tampered_audit,
        )
        .unwrap_err()
        .contains("audit changed")
    );

    let mut tampered = first.clone();
    tampered.task.methods[0].source.push_str("\nforged");
    assert!(
        validate_historical_v3_label_review(&fixture.inputs(), &fixture.bundle, &tampered)
            .unwrap_err()
            .contains("immutable source task")
    );

    let mut assisted = first.clone();
    assisted.reviewer.as_mut().unwrap().model_assistance_used = true;
    assert!(
        validate_historical_v3_label_review(&fixture.inputs(), &fixture.bundle, &assisted)
            .unwrap_err()
            .contains("human-only")
    );

    let mut repeated = second;
    repeated.reviewer.as_mut().unwrap().reviewer_id = " REVIEWER-A ".to_string();
    assert!(
        audit_historical_v3_label_reviews(&fixture.inputs(), &fixture.bundle, &[first, repeated],)
            .unwrap_err()
            .contains("repeats a reviewer")
    );
}

#[tokio::test]
async fn preserves_typed_non_slop_consensus_and_real_disputes() {
    let fixture = review_fixture().await;
    let clean_a = fixture.worksheet("reviewer-a", HistoricalV3ReviewerVerdict::Clean);
    let clean_b = fixture.worksheet("reviewer-b", HistoricalV3ReviewerVerdict::Clean);
    let rejected = audit_historical_v3_label_reviews(
        &fixture.inputs(),
        &fixture.bundle,
        &[clean_a.clone(), clean_b],
    )
    .unwrap();
    assert_eq!(rejected.status, HistoricalV3LabelStatus::Rejected);
    assert!(
        rejected
            .labels
            .iter()
            .all(|label| { label.decision.verdict == Some(HistoricalV3ReviewerVerdict::Clean) })
    );

    let boundary = fixture.worksheet(
        "reviewer-b",
        HistoricalV3ReviewerVerdict::IntentionalBoundary,
    );
    let disputed =
        audit_historical_v3_label_reviews(&fixture.inputs(), &fixture.bundle, &[clean_a, boundary])
            .unwrap();
    assert_eq!(disputed.status, HistoricalV3LabelStatus::Disputed);
    assert_eq!(
        disputed.labels[0].decision.verdict,
        Some(HistoricalV3ReviewerVerdict::Clean)
    );
    assert_eq!(
        disputed.labels[1].decision.verdict,
        Some(HistoricalV3ReviewerVerdict::IntentionalBoundary)
    );
}

pub(crate) async fn review_fixture() -> ReviewFixture {
    let (_git, protocol, collection, journal, workspace, _) = prepared_rank().await;
    run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &PassingExecutor,
    )
    .unwrap();
    let source_review = run_historical_v3_source_review_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let journal = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    let history = journal.history();
    ReviewFixture {
        protocol,
        collection,
        materialization: history[0].read_artifact().unwrap().unwrap(),
        source_census: history[1].read_artifact().unwrap().unwrap(),
        semantic_census: history[2].read_artifact().unwrap().unwrap(),
        qualification: history[3].read_artifact().unwrap().unwrap(),
        recipe: history[4].read_artifact().unwrap().unwrap(),
        execution: history[5].read_artifact().unwrap().unwrap(),
        bundle: *source_review.artifact,
    }
}

fn reviewer(reviewer_id: &str) -> HistoricalV3Reviewer {
    HistoricalV3Reviewer {
        reviewer_id: reviewer_id.to_string(),
        years_experience: 5,
        affiliation: "independent".to_string(),
        independent_from_sniff: true,
        sniff_output_hidden: true,
        repository_identity_hidden: true,
        change_metadata_hidden: true,
        other_reviewer_labels_hidden: true,
        complete_source_context_inspected: true,
        behavior_evidence_inspected: true,
        model_assistance_used: false,
        attestation: "I reviewed the complete blinded source and behavior evidence.".to_string(),
    }
}

fn decision(
    worksheet: &HistoricalV3LabelWorksheet,
    verdict: HistoricalV3ReviewerVerdict,
) -> HistoricalV3ReviewDecision {
    let mut citations = worksheet
        .task
        .methods
        .iter()
        .filter(|method| {
            method.side == HistoricalV3SourceSide::Base
                || method.side == HistoricalV3SourceSide::Merge
        })
        .map(|method| HistoricalV3SourceCitation {
            side: method.side,
            repository_path: method.repository_path.clone(),
            parser_unit_id: method.parser_unit_id.clone(),
            start_line: method.start_line,
            end_line: method.end_line,
            quote: method.source.lines().collect::<Vec<_>>().join("\n"),
        })
        .collect::<Vec<_>>();
    citations.sort();
    citations.dedup_by_key(|citation| citation.side);
    let mut decision = HistoricalV3ReviewDecision {
        verdict: Some(verdict),
        pattern: Some(SlopPattern::None),
        other_pattern: String::new(),
        mechanism: "The before and after method machinery was compared directly.".to_string(),
        before_contains_unnecessary_machinery: Some(false),
        after_removes_that_machinery: None,
        removal_not_relocated: None,
        simpler_counterfactual_matches: None,
        public_surface_preserved: Some(true),
        behavior_preserved: Some(true),
        simpler_counterfactual: String::new(),
        boundary_justification: String::new(),
        rationale: "The cited source and committed behavior evidence support this verdict."
            .to_string(),
        missing_evidence: Vec::new(),
        citations,
    };
    match verdict {
        HistoricalV3ReviewerVerdict::Slop => {
            decision.pattern = Some(SlopPattern::NeedlessIndirection);
            decision.before_contains_unnecessary_machinery = Some(true);
            decision.after_removes_that_machinery = Some(true);
            decision.removal_not_relocated = Some(true);
            decision.simpler_counterfactual_matches = Some(true);
            decision.simpler_counterfactual =
                "Use the direct operation shown in the after-state.".to_string();
        }
        HistoricalV3ReviewerVerdict::IntentionalBoundary => {
            decision.boundary_justification =
                "The wrapper is the stable public boundary exercised by callers.".to_string();
        }
        HistoricalV3ReviewerVerdict::Clean => {}
        HistoricalV3ReviewerVerdict::Ambiguous
        | HistoricalV3ReviewerVerdict::InsufficientContext => {
            decision.missing_evidence = vec!["runtime contract is not observable".to_string()];
            decision.behavior_preserved = None;
        }
    }
    decision
}
