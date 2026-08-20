use super::*;

#[test]
fn prepares_a_blank_source_bound_task() {
    let fixture = ReviewFixture::new();
    let worksheet = fixture.blank();
    assert!(worksheet.reviewer.is_none());
    assert!(worksheet.task.decision.verdict.is_none());
    assert_eq!(worksheet.task.changed_methods.len(), 2);
    assert!(
        worksheet
            .task
            .changed_methods
            .iter()
            .all(|method| !method.source.trim().is_empty())
    );
}

#[test]
fn two_matching_acceptances_create_consensus() {
    let fixture = ReviewFixture::new();
    let first = fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, "");
    let second = fixture.accepted("reviewer-b", SlopPattern::NeedlessIndirection, "");
    let audit = fixture.audit(&[first, second]);
    assert_eq!(audit.status, HistoricalV2LabelStatus::Accepted);
    validate_historical_v2_label_audit(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &[
            fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
            fixture.accepted("reviewer-b", SlopPattern::NeedlessIndirection, ""),
        ],
        &audit,
    )
    .unwrap();
}

#[test]
fn accept_and_reject_remain_disputed() {
    let fixture = ReviewFixture::new();
    let audit = fixture.audit(&[
        fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
        fixture.rejected("reviewer-b"),
    ]);
    assert_eq!(audit.status, HistoricalV2LabelStatus::Disputed);
}

#[test]
fn two_rejections_close_the_slot_without_reinterpreting_reasons() {
    let fixture = ReviewFixture::new();
    let audit = fixture.audit(&[
        fixture.rejected("reviewer-a"),
        fixture.rejected("reviewer-b"),
    ]);
    assert_eq!(audit.status, HistoricalV2LabelStatus::Rejected);
}

#[test]
fn different_accepted_patterns_remain_disputed() {
    let fixture = ReviewFixture::new();
    let audit = fixture.audit(&[
        fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
        fixture.accepted("reviewer-b", SlopPattern::CeremonialLogic, ""),
    ]);
    assert_eq!(audit.status, HistoricalV2LabelStatus::Disputed);
}

#[test]
fn rejects_acceptance_with_an_unmet_protocol_criterion() {
    let fixture = ReviewFixture::new();
    let mut worksheet = fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, "");
    worksheet.task.decision.behavior_preserved = Some(false);
    let error = fixture.validate(&worksheet).unwrap_err();
    assert!(
        error.contains("acceptance requires every criterion"),
        "{error}"
    );
}

#[test]
fn rejects_a_reviewer_who_used_model_assistance() {
    let fixture = ReviewFixture::new();
    let mut worksheet = fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, "");
    worksheet.reviewer.as_mut().unwrap().model_assistance_used = true;
    let error = fixture.validate(&worksheet).unwrap_err();
    assert!(error.contains("human-only"), "{error}");
}

#[test]
fn rejects_a_pattern_that_contradicts_the_before_mechanism() {
    let fixture = ReviewFixture::new();
    let mut worksheet = fixture.rejected("reviewer-a");
    worksheet.task.decision.exact_before_slop_mechanism = Some(true);
    let error = fixture.validate(&worksheet).unwrap_err();
    assert!(
        error.contains("contradicts the before-mechanism"),
        "{error}"
    );
}

#[test]
fn rejects_invented_source_citations() {
    let fixture = ReviewFixture::new();
    let mut worksheet = fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, "");
    worksheet.task.decision.citations[0].repository_path = "src/invented.rs".to_string();
    let error = fixture.validate(&worksheet).unwrap_err();
    assert!(error.contains("invents a source path"), "{error}");
}

#[test]
fn other_pattern_consensus_uses_a_normalized_explicit_mechanism() {
    let fixture = ReviewFixture::new();
    let audit = fixture.audit(&[
        fixture.accepted(
            "reviewer-a",
            SlopPattern::Other,
            "Repeated empty-state dance",
        ),
        fixture.accepted(
            "reviewer-b",
            SlopPattern::Other,
            " repeated  empty-state DANCE ",
        ),
    ]);
    assert_eq!(audit.status, HistoricalV2LabelStatus::Accepted);
}

#[test]
fn reviewer_identity_aliases_are_not_independent() {
    let fixture = ReviewFixture::new();
    let worksheets = vec![
        fixture.accepted("Reviewer A", SlopPattern::NeedlessIndirection, ""),
        fixture.accepted("  reviewer   a  ", SlopPattern::NeedlessIndirection, ""),
    ];
    let error = audit_historical_v2_label_reviews(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &worksheets,
    )
    .unwrap_err();
    assert!(error.contains("repeats a reviewer"), "{error}");
}

pub(crate) struct ReviewFixture {
    pub(crate) root: tempfile::TempDir,
    pub(crate) protocol: ValidatedHistoricalV2Protocol,
    pub(crate) bundle: HistoricalV2SourceReviewBundle,
    before_line: String,
    after_line: String,
}

impl ReviewFixture {
    pub(crate) fn new() -> Self {
        let protocol = validate_historical_v2_protocol(include_bytes!(
            "../sniffbench/historical-v2-protocol.json"
        ))
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let before = "fn simplify(value: i32) -> i32 {\n    let prepared = value + 1;\n    prepared * 2\n}\n";
        let after = "fn simplify(value: i32) -> i32 {\n    (value + 1) * 2\n}\n";
        let before_method = parsed_method(before);
        let after_method = parsed_method(after);
        let snapshots = vec![
            snapshot(
                root.path(),
                HistoricalV2ReviewSnapshotSide::Before,
                '1',
                before,
            ),
            snapshot(
                root.path(),
                HistoricalV2ReviewSnapshotSide::After,
                '2',
                after,
            ),
        ];
        let mut changed_methods = vec![
            review_method(HistoricalRevisionSide::Parent, before_method),
            review_method(HistoricalRevisionSide::Commit, after_method),
        ];
        changed_methods.sort();
        let behavior = HistoricalV2ReviewBehaviorEvidence {
            test_plan_sha256: "a".repeat(64),
            execution_sha256: "b".repeat(64),
            events: vec![
                test_event(HistoricalV2ExecutionSide::Base),
                test_event(HistoricalV2ExecutionSide::Patched),
            ],
        };
        let mut bundle = HistoricalV2SourceReviewBundle {
            schema_version: HISTORICAL_V2_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION,
            bundle_contract: "sniffbench-historical-v2-source-review-v1".to_string(),
            protocol_sha256: protocol.protocol_sha256.clone(),
            selection_sha256: "c".repeat(64),
            assessment_identity_sha256: "d".repeat(64),
            terminal_checkpoint_sha256: "e".repeat(64),
            review_item_id: format!("hvr-v1:{}", "f".repeat(64)),
            language: "rust".to_string(),
            source_only: true,
            sniff_output_included: false,
            dataset_judgments_included: false,
            public_surface_preserved: true,
            public_surface_delta_sha256: "1".repeat(64),
            snapshots,
            changed_methods,
            behavior,
            bundle_sha256: String::new(),
        };
        bundle.bundle_sha256 = source_bundle_sha256(&bundle);
        let mut manifest = serde_json::to_vec_pretty(&bundle).unwrap();
        manifest.push(b'\n');
        fs::write(root.path().join("manifest.json"), manifest).unwrap();
        Self {
            root,
            protocol,
            bundle,
            before_line: "    let prepared = value + 1;".to_string(),
            after_line: "    (value + 1) * 2".to_string(),
        }
    }

    fn blank(&self) -> HistoricalV2LabelWorksheet {
        prepare_historical_v2_label_review(&self.protocol, self.root.path(), &self.bundle).unwrap()
    }

    pub(crate) fn accepted(
        &self,
        reviewer_id: &str,
        pattern: SlopPattern,
        other_pattern: &str,
    ) -> HistoricalV2LabelWorksheet {
        let mut worksheet = self.blank();
        worksheet.reviewer = Some(reviewer(reviewer_id));
        worksheet.task.decision = HistoricalV2ReviewDecision {
            verdict: Some(HistoricalV2ReviewerVerdict::Accept),
            pattern: Some(pattern),
            other_pattern: other_pattern.to_string(),
            mechanism: "the temporary only forwards one expression".to_string(),
            exact_before_slop_mechanism: Some(true),
            exact_after_removal: Some(true),
            simpler_counterfactual_matches: Some(true),
            public_surface_preserved: Some(true),
            behavior_preserved: Some(true),
            simpler_counterfactual: "inline prepared into the return expression".to_string(),
            rationale: "the historical edit removes the named indirection".to_string(),
            citations: self.citations(),
        };
        worksheet
    }

    pub(crate) fn rejected(&self, reviewer_id: &str) -> HistoricalV2LabelWorksheet {
        let mut worksheet = self.blank();
        worksheet.reviewer = Some(reviewer(reviewer_id));
        worksheet.task.decision = HistoricalV2ReviewDecision {
            verdict: Some(HistoricalV2ReviewerVerdict::Reject),
            pattern: Some(SlopPattern::None),
            other_pattern: String::new(),
            mechanism: "the local documents an intentional intermediate value".to_string(),
            exact_before_slop_mechanism: Some(false),
            exact_after_removal: Some(true),
            simpler_counterfactual_matches: Some(true),
            public_surface_preserved: Some(true),
            behavior_preserved: Some(true),
            simpler_counterfactual: "the historical inline is smaller but not a slop repair"
                .to_string(),
            rationale: "size reduction alone is not a concrete slop mechanism".to_string(),
            citations: self.citations(),
        };
        worksheet
    }

    fn citations(&self) -> Vec<HistoricalV2SourceCitation> {
        vec![
            HistoricalV2SourceCitation {
                side: HistoricalV2ReviewSnapshotSide::Before,
                repository_path: "src/lib.rs".to_string(),
                start_line: 2,
                end_line: 2,
                quote: self.before_line.clone(),
            },
            HistoricalV2SourceCitation {
                side: HistoricalV2ReviewSnapshotSide::After,
                repository_path: "src/lib.rs".to_string(),
                start_line: 2,
                end_line: 2,
                quote: self.after_line.clone(),
            },
        ]
    }

    fn validate(&self, worksheet: &HistoricalV2LabelWorksheet) -> Result<(), String> {
        validate_historical_v2_label_review(
            &self.protocol,
            self.root.path(),
            &self.bundle,
            worksheet,
        )
    }

    pub(crate) fn audit(
        &self,
        worksheets: &[HistoricalV2LabelWorksheet],
    ) -> HistoricalV2LabelAudit {
        audit_historical_v2_label_reviews(
            &self.protocol,
            self.root.path(),
            &self.bundle,
            worksheets,
        )
        .unwrap()
    }
}

fn reviewer(reviewer_id: &str) -> HistoricalV2Reviewer {
    HistoricalV2Reviewer {
        reviewer_id: reviewer_id.to_string(),
        years_experience: 8,
        affiliation: "independent".to_string(),
        independent_from_sniff: true,
        sniff_output_hidden: true,
        dataset_judgments_hidden: true,
        other_reviewer_labels_hidden: true,
        complete_source_context_inspected: true,
        behavior_evidence_inspected: true,
        model_assistance_used: false,
        attestation: "I completed this review independently from exact source.".to_string(),
    }
}

fn snapshot(
    root: &Path,
    side: HistoricalV2ReviewSnapshotSide,
    identity: char,
    source: &str,
) -> HistoricalV2ReviewSourceSnapshot {
    let content_sha256 = sha256(source.as_bytes());
    let relative = format!("objects/{}/{}.blob", &content_sha256[..2], content_sha256);
    let path = root.join(&relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
    HistoricalV2ReviewSourceSnapshot {
        side,
        revision: identity.to_string().repeat(40),
        tree_oid: identity.to_string().repeat(40),
        inventory_sha256: identity.to_string().repeat(64),
        source_snapshot_sha256: identity.to_string().repeat(64),
        tracked_entry_count: 1,
        artifacts: vec![HistoricalV2ReviewSourceArtifact {
            repository_path: "src/lib.rs".to_string(),
            mode: "100644".to_string(),
            kind: BoundaryGitEntryKind::RegularBlob,
            object_id: identity.to_string().repeat(40),
            byte_length: Some(source.len() as u64),
            artifact_path: Some(relative),
            content_sha256: Some(content_sha256),
        }],
    }
}

fn parsed_method(source: &str) -> crate::types::MethodRecord {
    crate::parser::parse_source_checked("src/lib.rs", source.as_bytes())
        .unwrap()
        .methods
        .into_iter()
        .next()
        .unwrap()
}

fn review_method(
    side: HistoricalRevisionSide,
    method: crate::types::MethodRecord,
) -> HistoricalV2ReviewChangedMethod {
    HistoricalV2ReviewChangedMethod {
        side,
        language: "rust".to_string(),
        repository_path: "src/lib.rs".to_string(),
        symbol_name: method.name,
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: sha256(method.source.as_bytes()),
    }
}

fn test_event(side: HistoricalV2ExecutionSide) -> HistoricalV2ExecutionCommandEvidence {
    HistoricalV2ExecutionCommandEvidence {
        side,
        phase: HistoricalV2ExecutionPhase::Test,
        command_index: 0,
        command_sha256: "2".repeat(64),
        exit_code: Some(0),
        timed_out: false,
        duration_millis: 1,
        stdout_sha256: "3".repeat(64),
        stderr_sha256: "4".repeat(64),
        retained_stdout: String::new(),
        retained_stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn source_bundle_sha256(bundle: &HistoricalV2SourceReviewBundle) -> String {
    hash_json(&(
        bundle.schema_version,
        &bundle.bundle_contract,
        &bundle.protocol_sha256,
        &bundle.selection_sha256,
        &bundle.assessment_identity_sha256,
        &bundle.terminal_checkpoint_sha256,
        &bundle.review_item_id,
        &bundle.language,
        bundle.source_only,
        bundle.sniff_output_included,
        bundle.dataset_judgments_included,
        bundle.public_surface_preserved,
        &bundle.public_surface_delta_sha256,
        &bundle.snapshots,
        &bundle.changed_methods,
        &bundle.behavior,
    ))
    .unwrap()
}
