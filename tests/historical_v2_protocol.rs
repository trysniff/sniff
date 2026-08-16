use sniff::benchmark::{HistoricalV2Protocol, validate_historical_v2_protocol};

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");

fn parsed_protocol() -> HistoricalV2Protocol {
    serde_json::from_slice(PROTOCOL).expect("committed historical-v2 protocol must parse")
}

fn validate_mutation(protocol: &HistoricalV2Protocol) -> String {
    let bytes = serde_json::to_vec(protocol).expect("mutated protocol must serialize");
    validate_historical_v2_protocol(&bytes).expect_err("mutated protocol must fail closed")
}

#[test]
fn validates_committed_historical_v2_protocol() {
    let validated = validate_historical_v2_protocol(PROTOCOL).unwrap();

    assert_eq!(validated.protocol.selection.supported_languages.len(), 6);
    assert_eq!(validated.protocol.selection.total_slots, 768);
    assert_eq!(validated.protocol.review.minimum_accepted_per_language, 40);
    assert_eq!(validated.protocol.review.minimum_total_accepted, 240);
    assert_eq!(validated.protocol_sha256.len(), 64);
}

#[test]
fn rejects_dataset_or_selection_projection_drift() {
    let mut protocol = parsed_protocol();
    protocol.dataset.shards[0].lfs_sha256 = "0".repeat(64);
    assert!(validate_mutation(&protocol).contains("dataset or field-projection"));

    let mut protocol = parsed_protocol();
    protocol
        .dataset
        .projected_selection_fields
        .push("problem_statement".to_string());
    assert!(validate_mutation(&protocol).contains("dataset or field-projection"));

    let mut protocol = parsed_protocol();
    protocol.dataset.unlisted_fields_fail_closed = false;
    assert!(validate_mutation(&protocol).contains("dataset or field-projection"));
}

#[test]
fn rejects_fixed_slot_or_blinding_drift() {
    let mut protocol = parsed_protocol();
    protocol.selection.slots_per_language = 127;
    assert!(validate_mutation(&protocol).contains("fixed-slot selection"));

    let mut protocol = parsed_protocol();
    protocol.selection.backfill_forbidden = false;
    assert!(validate_mutation(&protocol).contains("fixed-slot selection"));

    let mut protocol = parsed_protocol();
    protocol.selection.model_access_forbidden = false;
    assert!(validate_mutation(&protocol).contains("fixed-slot selection"));

    let mut protocol = parsed_protocol();
    protocol.no_fallbacks = false;
    assert!(validate_mutation(&protocol).contains("identity or fallback"));

    let mut protocol = parsed_protocol();
    protocol.precommit_parent_revision = "0".repeat(40);
    protocol.selection.ranking_seed = "0".repeat(40);
    assert!(validate_mutation(&protocol).contains("identity or fallback"));
}

#[test]
fn rejects_repository_assessment_drift() {
    let mut protocol = parsed_protocol();
    protocol.assessment.same_test_recipe_on_both_revisions = false;
    assert!(validate_mutation(&protocol).contains("repository assessment"));

    let mut protocol = parsed_protocol();
    protocol.assessment.hardened_sandbox_required = false;
    assert!(validate_mutation(&protocol).contains("repository assessment"));

    let mut protocol = parsed_protocol();
    protocol.assessment.public_surface_must_be_preserved = false;
    assert!(validate_mutation(&protocol).contains("repository assessment"));
}

#[test]
fn rejects_independent_review_drift() {
    let mut protocol = parsed_protocol();
    protocol.review.independent_reviewers = 1;
    assert!(validate_mutation(&protocol).contains("independent-review"));

    let mut protocol = parsed_protocol();
    protocol.review.minimum_accepted_per_language = 39;
    assert!(validate_mutation(&protocol).contains("independent-review"));

    let mut protocol = parsed_protocol();
    protocol.review.rejected_label_closes_slot = false;
    assert!(validate_mutation(&protocol).contains("independent-review"));
}
