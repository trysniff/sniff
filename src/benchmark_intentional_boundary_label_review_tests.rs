use super::*;
use std::fs;
use tempfile::TempDir;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");

pub(crate) fn protocol() -> ValidatedIntentionalBoundaryProtocol {
    validate_intentional_boundary_protocol(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
}

pub(crate) fn source_bundle() -> (TempDir, IntentionalBoundarySourceBundle) {
    let protocol = protocol();
    let root = tempfile::tempdir().unwrap();
    let artifact_path =
        "artifacts/1111111111111111111111111111111111111111111111111111111111111111/00000000.blob";
    let source = "pub fn launch() -> u8 {\n    7\n}\n";
    let path = root.path().join(artifact_path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, source).unwrap();
    let parsed = crate::parser::parse_source_checked("src/main.rs", source.as_bytes()).unwrap();
    let method = &parsed.methods[0];
    let source_repository_id = format!("ibr-v1:{}", "1".repeat(64));
    let repository = IntentionalBoundarySourceRepository {
        source_repository_id: source_repository_id.clone(),
        repository: "github.com/example/review".to_string(),
        revision: "a".repeat(40),
        inventory_sha256: "2".repeat(64),
        source_census_sha256: "3".repeat(64),
        tracked_entry_count: 1,
        artifacts: vec![IntentionalBoundarySourceArtifact {
            repository_path: "src/main.rs".to_string(),
            mode: "100644".to_string(),
            kind: BoundaryGitEntryKind::RegularBlob,
            object_id: "b".repeat(40),
            byte_length: Some(source.len() as u64),
            artifact_path: Some(artifact_path.to_string()),
            content_sha256: Some(sha256(source.as_bytes())),
        }],
    };
    let review_item = IntentionalBoundarySourceReviewItem {
        review_item_id: format!("ibi-v1:{}", "4".repeat(64)),
        source_repository_id,
        repository: repository.repository.clone(),
        revision: repository.revision.clone(),
        repository_path: "src/main.rs".to_string(),
        source_artifact_path: artifact_path.to_string(),
        language: parsed.language,
        symbol_name: method.name.clone(),
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: sha256(method.source.as_bytes()),
    };
    let mut bundle = IntentionalBoundarySourceBundle {
        schema_version: INTENTIONAL_BOUNDARY_SOURCE_BUNDLE_SCHEMA_VERSION,
        bundle_contract: "sniffbench-intentional-boundary-source-only-v1".to_string(),
        protocol_sha256: protocol.protocol_sha256,
        policy_sha256: "5".repeat(64),
        frame_task_sha256: "6".repeat(64),
        candidate_frame_sha256: "7".repeat(64),
        selection_sha256: "8".repeat(64),
        selected_slot_count: 1,
        unfilled_slot_count: 15,
        repositories: vec![repository],
        review_items: vec![review_item],
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = hash_json(&(
        bundle.schema_version,
        &bundle.bundle_contract,
        &bundle.protocol_sha256,
        &bundle.policy_sha256,
        &bundle.frame_task_sha256,
        &bundle.candidate_frame_sha256,
        &bundle.selection_sha256,
        bundle.selected_slot_count,
        bundle.unfilled_slot_count,
        &bundle.repositories,
        &bundle.review_items,
    ));
    let mut manifest = serde_json::to_vec_pretty(&bundle).unwrap();
    manifest.push(b'\n');
    fs::write(root.path().join("manifest.json"), manifest).unwrap();
    (root, bundle)
}

pub(crate) fn completed(
    root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    reviewer_id: &str,
    tier: FindingTier,
    intentional_boundary: bool,
) -> IntentionalBoundaryLabelWorksheet {
    let mut worksheet = prepare_intentional_boundary_label_review(root, bundle).unwrap();
    worksheet.reviewer = Some(IntentionalBoundaryLabelReviewer {
        reviewer_id: reviewer_id.to_string(),
        years_experience: 7,
        affiliation: format!("Independent {reviewer_id}"),
        independent_from_sniff: true,
        sniff_output_hidden: true,
        other_reviewer_labels_hidden: true,
        complete_source_context_inspected: true,
        attestation: "I reviewed the complete committed source bundle independently.".to_string(),
    });
    worksheet.items[0].decision = IntentionalBoundaryLabelDecision {
        tier: Some(tier),
        intentional_boundary: Some(intentional_boundary),
        rationale: "The runtime invokes this committed entry surface.".to_string(),
        citations: vec![IntentionalBoundarySourceCitation {
            repository_path: "src/main.rs".to_string(),
            start_line: 1,
            end_line: 3,
            quote: "pub fn launch() -> u8 {\n    7\n}".to_string(),
        }],
    };
    worksheet
}

#[test]
fn two_independent_clean_boundary_reviews_accept_the_fixed_item() {
    let (root, bundle) = source_bundle();
    let first = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    let second = completed(root.path(), &bundle, "reviewer-b", FindingTier::Clean, true);

    let audit = audit_intentional_boundary_label_reviews(
        &protocol(),
        root.path(),
        &bundle,
        &[first.clone(), second.clone()],
    )
    .unwrap();

    assert_eq!(audit.accepted_count, 1);
    assert_eq!(audit.rejected_count, 0);
    assert_eq!(audit.disputed_count, 0);
    assert_eq!(
        audit.items[0].status,
        IntentionalBoundaryLabelStatus::Accepted
    );
    validate_intentional_boundary_label_audit(
        &protocol(),
        root.path(),
        &bundle,
        &[first, second],
        &audit,
    )
    .unwrap();
}

#[test]
fn progress_distinguishes_a_blank_task_from_a_valid_completed_review() {
    let (root, bundle) = source_bundle();
    let blank = prepare_intentional_boundary_label_review(root.path(), &bundle).unwrap();
    let blank_progress =
        inspect_intentional_boundary_label_review_progress(root.path(), &bundle, &blank).unwrap();
    assert_eq!(blank_progress.total_items, 1);
    assert_eq!(blank_progress.completed_items, 0);
    assert_eq!(blank_progress.pending_items, 1);
    assert!(!blank_progress.reviewer_complete);
    assert!(!blank_progress.complete);

    let completed = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    let completed_progress =
        inspect_intentional_boundary_label_review_progress(root.path(), &bundle, &completed)
            .unwrap();
    assert_eq!(completed_progress.completed_items, 1);
    assert_eq!(completed_progress.pending_items, 0);
    assert!(completed_progress.reviewer_complete);
    assert!(completed_progress.complete);
}

#[test]
fn progress_rejects_completed_decisions_with_inexact_source_evidence() {
    let (root, bundle) = source_bundle();
    let mut review = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    review.items[0].decision.citations[0]
        .quote
        .push_str(" invented");

    assert!(
        inspect_intentional_boundary_label_review_progress(root.path(), &bundle, &review)
            .unwrap_err()
            .contains("not exact source")
    );
}

#[test]
fn disagreement_is_preserved_and_matching_non_boundary_labels_close_the_item() {
    let (root, bundle) = source_bundle();
    let accepted = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    let rejected = completed(
        root.path(),
        &bundle,
        "reviewer-b",
        FindingTier::Clean,
        false,
    );
    let disputed = audit_intentional_boundary_label_reviews(
        &protocol(),
        root.path(),
        &bundle,
        &[accepted, rejected.clone()],
    )
    .unwrap();
    assert_eq!(disputed.disputed_count, 1);
    assert_eq!(
        disputed.items[0].status,
        IntentionalBoundaryLabelStatus::Disputed
    );

    let matching = completed(
        root.path(),
        &bundle,
        "reviewer-c",
        FindingTier::Clean,
        false,
    );
    let closed = audit_intentional_boundary_label_reviews(
        &protocol(),
        root.path(),
        &bundle,
        &[rejected, matching],
    )
    .unwrap();
    assert_eq!(closed.rejected_count, 1);
    assert_eq!(
        closed.items[0].status,
        IntentionalBoundaryLabelStatus::Rejected
    );
}

#[test]
fn review_validation_rejects_unblinded_reviewers_and_inexact_evidence() {
    let (root, bundle) = source_bundle();
    let mut review = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    review
        .reviewer
        .as_mut()
        .unwrap()
        .other_reviewer_labels_hidden = false;
    assert!(
        validate_intentional_boundary_label_review(root.path(), &bundle, &review)
            .unwrap_err()
            .contains("blind")
    );

    let mut review = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    review.items[0].decision.citations[0]
        .quote
        .push_str(" invented");
    assert!(
        validate_intentional_boundary_label_review(root.path(), &bundle, &review)
            .unwrap_err()
            .contains("not exact source")
    );

    let mut review = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    review.items[0].method_source.push_str("// changed\n");
    assert!(
        validate_intentional_boundary_label_review(root.path(), &bundle, &review)
            .unwrap_err()
            .contains("changed source item")
    );
}

#[test]
fn audit_rejects_reused_reviewer_identity_and_tampering() {
    let (root, bundle) = source_bundle();
    let first = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    let duplicate = completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true);
    assert!(
        audit_intentional_boundary_label_reviews(
            &protocol(),
            root.path(),
            &bundle,
            &[first.clone(), duplicate],
        )
        .unwrap_err()
        .contains("repeats reviewer")
    );

    let second = completed(root.path(), &bundle, "reviewer-b", FindingTier::Clean, true);
    let mut audit = audit_intentional_boundary_label_reviews(
        &protocol(),
        root.path(),
        &bundle,
        &[first.clone(), second.clone()],
    )
    .unwrap();
    audit.items[0].status = IntentionalBoundaryLabelStatus::Rejected;
    assert!(
        validate_intentional_boundary_label_audit(
            &protocol(),
            root.path(),
            &bundle,
            &[first, second],
            &audit,
        )
        .unwrap_err()
        .contains("changed")
    );
}

fn hash_json(value: &impl Serialize) -> String {
    sha256(&serde_json::to_vec(value).unwrap())
}
