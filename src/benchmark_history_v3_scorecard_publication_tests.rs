use super::*;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const RESPONSE: &[u8] =
    include_bytes!("../sniffbench/historical-v3-scorecard-publication-response.json");
const FRAME_BLOB: &str = "01e0927123bd7e8ffcf2ec313ccf1404fe4c5229";

#[test]
fn git_blob_oid_uses_the_git_object_header() {
    assert_eq!(
        git_blob_oid(b""),
        "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    );
}

#[test]
fn pinned_source_capture_is_before_cutoff_and_matches_policy() {
    assert_eq!(sha256(POLICY), POLICY_SHA256);
    assert_eq!(sha256(RESPONSE), RESPONSE_SHA256);
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(POLICY).unwrap();
    assert_eq!(
        policy.historical_simplification.sampling_frame_blob,
        FRAME_BLOB
    );
    let response = serde_json::from_slice(RESPONSE).unwrap();
    assert_eq!(
        validate_publication_response(&response, FRAME_BLOB).unwrap(),
        "2026-08-07T18:26:23Z"
    );
}

#[test]
fn rejects_changed_event_head_blob_and_late_timestamp() {
    let original: Value = serde_json::from_slice(RESPONSE).unwrap();
    for (pointer, changed) in [
        ("/data/node/id", serde_json::json!("wrong-event")),
        (
            "/data/node/afterCommit/oid",
            serde_json::json!("wrong-head"),
        ),
        ("/data/node/pullRequest/number", serde_json::json!(4978)),
        (
            "/data/node/pullRequest/repository/nameWithOwner",
            serde_json::json!("another/repo"),
        ),
        (
            "/data/repository/object/oid",
            serde_json::json!("wrong-blob"),
        ),
    ] {
        let mut response = original.clone();
        *response.pointer_mut(pointer).unwrap() = changed;
        assert!(
            validate_publication_response(&response, FRAME_BLOB)
                .unwrap_err()
                .contains("changed"),
            "{pointer}"
        );
    }
    let mut late = original.clone();
    *late.pointer_mut("/data/node/createdAt").unwrap() =
        serde_json::json!(HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC);
    assert!(
        validate_publication_response(&late, FRAME_BLOB)
            .unwrap_err()
            .contains("not before")
    );
}

#[test]
#[ignore = "requires the exact original Scorecard CSV source file"]
fn verifies_real_scorecard_publication_witness() {
    let frame_path = std::env::var_os("SNIFF_SCORECARD_FRAME_PATH")
        .expect("set SNIFF_SCORECARD_FRAME_PATH to the frozen Scorecard CSV");
    let frame = std::fs::read(frame_path).unwrap();
    let witness = derive_scorecard_frame_publication_witness(POLICY, &frame, RESPONSE).unwrap();
    assert_eq!(witness.published_at_utc, "2026-08-07T18:26:23Z");
    assert_eq!(witness.frame_blob_oid, FRAME_BLOB);
    validate_scorecard_frame_publication_witness(POLICY, &frame, RESPONSE, &witness).unwrap();
    let mut changed = witness;
    changed.published_at_utc = "2026-08-07T18:26:24Z".to_string();
    assert!(
        validate_scorecard_frame_publication_witness(POLICY, &frame, RESPONSE, &changed)
            .unwrap_err()
            .contains("does not replay")
    );
}
