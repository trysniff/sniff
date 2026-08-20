use super::*;

pub(super) struct SourceFixture {
    pub(super) path: String,
    pub(super) before: &'static str,
    pub(super) after: &'static str,
}

pub(super) fn source_fixture(language: &str, slot_number: usize) -> SourceFixture {
    let (file_name, before, after) = match language {
        "go" => (
            "src/simplify.go",
            "package sample\nfunc simplify(value int) int {\n    prepared := value + 1\n    return prepared * 2\n}\n",
            "package sample\nfunc simplify(value int) int {\n    return (value + 1) * 2\n}\n",
        ),
        "javascript" => (
            "src/simplify.js",
            "function simplify(value) {\n  const prepared = value + 1;\n  return prepared * 2;\n}\n",
            "function simplify(value) {\n  return (value + 1) * 2;\n}\n",
        ),
        "kotlin" => (
            "src/Simplify.kt",
            "fun simplify(value: Int): Int {\n    val prepared = value + 1\n    return prepared * 2\n}\n",
            "fun simplify(value: Int): Int {\n    return (value + 1) * 2\n}\n",
        ),
        "python" => (
            "src/simplify.py",
            "def simplify(value):\n    prepared = value + 1\n    return prepared * 2\n",
            "def simplify(value):\n    return (value + 1) * 2\n",
        ),
        "rust" => (
            "src/simplify.rs",
            "fn simplify(value: i32) -> i32 {\n    let prepared = value + 1;\n    prepared * 2\n}\n",
            "fn simplify(value: i32) -> i32 {\n    (value + 1) * 2\n}\n",
        ),
        "typescript" => (
            "src/simplify.ts",
            "function simplify(value: number): number {\n  const prepared = value + 1;\n  return prepared * 2;\n}\n",
            "function simplify(value: number): number {\n  return (value + 1) * 2;\n}\n",
        ),
        _ => panic!("unsupported historical-v2 fixture language {language}"),
    };
    SourceFixture {
        path: format!("src/slot-{slot_number:03}/{file_name}"),
        before,
        after,
    }
}

pub(super) fn source_bundle(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    language: &str,
    slot_number: usize,
    source: &SourceFixture,
) -> HistoricalV2SourceReviewBundle {
    let before = snapshot(
        bundle_root,
        &source.path,
        source.before,
        HistoricalV2ReviewSnapshotSide::Before,
        slot_number,
    );
    let after = snapshot(
        bundle_root,
        &source.path,
        source.after,
        HistoricalV2ReviewSnapshotSide::After,
        slot_number,
    );
    let mut changed_methods = vec![
        changed_method(&source.path, source.before, HistoricalRevisionSide::Parent),
        changed_method(&source.path, source.after, HistoricalRevisionSide::Commit),
    ];
    changed_methods.sort();
    HistoricalV2SourceReviewBundle {
        schema_version: HISTORICAL_V2_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION,
        bundle_contract: "sniffbench-historical-v2-source-review-v1".to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        selection_sha256: SELECTION_SHA256.to_string(),
        assessment_identity_sha256: hash_text(&format!("assessment-{language}-{slot_number}")),
        terminal_checkpoint_sha256: hash_text(&format!("terminal-{language}-{slot_number}")),
        review_item_id: format!(
            "hvr-v1:{}",
            hash_text(&format!("review-{language}-{slot_number}"))
        ),
        language: language.to_string(),
        source_only: true,
        sniff_output_included: false,
        dataset_judgments_included: false,
        public_surface_preserved: true,
        public_surface_delta_sha256: hash_text(&format!("surface-{language}-{slot_number}")),
        snapshots: vec![before, after],
        changed_methods,
        behavior: HistoricalV2ReviewBehaviorEvidence {
            test_plan_sha256: hash_text(&format!("plan-{language}-{slot_number}")),
            execution_sha256: hash_text(&format!("execution-{language}-{slot_number}")),
            events: vec![
                passing_test(HistoricalV2ExecutionSide::Base),
                passing_test(HistoricalV2ExecutionSide::Patched),
            ],
        },
        bundle_sha256: String::new(),
    }
}

pub(super) fn reviewer_worksheets(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    slot_number: usize,
    source: &SourceFixture,
) -> Vec<HistoricalV2LabelWorksheet> {
    ["a", "b"]
        .into_iter()
        .map(|suffix| {
            let mut worksheet = prepare_historical_v2_label_review(protocol, bundle_root, bundle)
                .expect("prepare historical-v2 fixture review");
            worksheet.reviewer = Some(reviewer(format!(
                "fixture-{slot_number}-{suffix}-{}",
                bundle.language
            )));
            worksheet.task.decision = accepted_decision(bundle, source);
            worksheet
        })
        .collect()
}

pub(super) fn accepted_outcome_parts(
    bundle: &HistoricalV2SourceReviewBundle,
    audit: &HistoricalV2LabelAudit,
    label: &HistoricalV2FinalLabel,
) -> HistoricalV2ReleaseSlotOutcome {
    let HistoricalV2FinalLabelOutcome::Accepted {
        basis,
        pattern,
        other_pattern,
    } = &label.outcome
    else {
        panic!("historical-v2 fixture final label must be accepted");
    };
    HistoricalV2ReleaseSlotOutcome::Accepted {
        terminal_checkpoint_sha256: bundle.terminal_checkpoint_sha256.clone(),
        review_item_id: bundle.review_item_id.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        final_label_sha256: label.final_sha256.clone(),
        basis: *basis,
        pattern: *pattern,
        other_pattern: other_pattern.clone(),
    }
}

fn snapshot(
    bundle_root: &Path,
    repository_path: &str,
    source: &str,
    side: HistoricalV2ReviewSnapshotSide,
    slot_number: usize,
) -> HistoricalV2ReviewSourceSnapshot {
    let content_sha256 = file_sha256(source.as_bytes());
    let artifact_path = format!("objects/{}/{}.blob", &content_sha256[..2], content_sha256);
    let path = bundle_root.join(&artifact_path);
    fs::create_dir_all(path.parent().expect("fixture object parent"))
        .expect("create fixture object directory");
    fs::write(path, source).expect("write fixture source object");
    let identity = format!("{side:?}-{slot_number}-{content_sha256}");
    HistoricalV2ReviewSourceSnapshot {
        side,
        revision: hash_text(&format!("revision-{identity}"))[..40].to_string(),
        tree_oid: hash_text(&format!("tree-{identity}"))[..40].to_string(),
        inventory_sha256: hash_text(&format!("inventory-{identity}")),
        source_snapshot_sha256: hash_text(&format!("snapshot-{identity}")),
        tracked_entry_count: 1,
        artifacts: vec![HistoricalV2ReviewSourceArtifact {
            repository_path: repository_path.to_string(),
            mode: "100644".to_string(),
            kind: BoundaryGitEntryKind::RegularBlob,
            object_id: hash_text(&format!("object-{identity}"))[..40].to_string(),
            byte_length: Some(source.len() as u64),
            artifact_path: Some(artifact_path),
            content_sha256: Some(content_sha256),
        }],
    }
}

fn changed_method(
    repository_path: &str,
    source: &str,
    side: HistoricalRevisionSide,
) -> HistoricalV2ReviewChangedMethod {
    let parsed = crate::parser::parse_source_checked(repository_path, source.as_bytes())
        .expect("parse historical-v2 fixture source");
    let method = parsed
        .methods
        .iter()
        .find(|method| method.name == "simplify")
        .expect("find historical-v2 fixture method");
    HistoricalV2ReviewChangedMethod {
        side,
        language: parsed.language,
        repository_path: repository_path.to_string(),
        symbol_name: method.name.clone(),
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: file_sha256(method.source.as_bytes()),
    }
}

fn accepted_decision(
    bundle: &HistoricalV2SourceReviewBundle,
    source: &SourceFixture,
) -> HistoricalV2ReviewDecision {
    let before = bundle
        .changed_methods
        .iter()
        .find(|method| method.side == HistoricalRevisionSide::Parent)
        .expect("find before fixture method");
    let after = bundle
        .changed_methods
        .iter()
        .find(|method| method.side == HistoricalRevisionSide::Commit)
        .expect("find after fixture method");
    HistoricalV2ReviewDecision {
        verdict: Some(HistoricalV2ReviewerVerdict::Accept),
        pattern: Some(SlopPattern::NeedlessIndirection),
        other_pattern: String::new(),
        mechanism: "a temporary local only forwards one expression".to_string(),
        exact_before_slop_mechanism: Some(true),
        exact_after_removal: Some(true),
        simpler_counterfactual_matches: Some(true),
        public_surface_preserved: Some(true),
        behavior_preserved: Some(true),
        simpler_counterfactual: "inline the temporary expression".to_string(),
        rationale: "the historical edit removes only needless local indirection".to_string(),
        citations: vec![
            citation(
                before,
                source.before,
                HistoricalV2ReviewSnapshotSide::Before,
            ),
            citation(after, source.after, HistoricalV2ReviewSnapshotSide::After),
        ],
    }
}

fn citation(
    method: &HistoricalV2ReviewChangedMethod,
    source: &str,
    side: HistoricalV2ReviewSnapshotSide,
) -> HistoricalV2SourceCitation {
    HistoricalV2SourceCitation {
        side,
        repository_path: method.repository_path.clone(),
        start_line: method.start_line,
        end_line: method.end_line,
        quote: source
            .lines()
            .skip(method.start_line - 1)
            .take(method.end_line - method.start_line + 1)
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn reviewer(reviewer_id: String) -> HistoricalV2Reviewer {
    HistoricalV2Reviewer {
        reviewer_id,
        years_experience: 8,
        affiliation: "independent fixture".to_string(),
        independent_from_sniff: true,
        sniff_output_hidden: true,
        dataset_judgments_hidden: true,
        other_reviewer_labels_hidden: true,
        complete_source_context_inspected: true,
        behavior_evidence_inspected: true,
        model_assistance_used: false,
        attestation: "Fixture review completed independently from exact source.".to_string(),
    }
}

fn passing_test(side: HistoricalV2ExecutionSide) -> HistoricalV2ExecutionCommandEvidence {
    HistoricalV2ExecutionCommandEvidence {
        side,
        phase: HistoricalV2ExecutionPhase::Test,
        command_index: 0,
        command_sha256: hash_text(&format!("command-{side:?}")),
        exit_code: Some(0),
        timed_out: false,
        duration_millis: 1,
        stdout_sha256: hash_text(&format!("stdout-{side:?}")),
        stderr_sha256: hash_text(&format!("stderr-{side:?}")),
        retained_stdout: String::new(),
        retained_stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn hash_text(value: &str) -> String {
    file_sha256(value.as_bytes())
}
