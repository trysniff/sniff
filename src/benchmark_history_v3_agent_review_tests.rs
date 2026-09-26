use super::super::history_v3_label_review::tests::review_fixture;
use super::*;

const PROMPT: &[u8] = b"Review the sealed source and behavior evidence without Sniff output.";

fn reviewer(agent_id: &str, run_id: &str) -> HistoricalV3AgentReviewer {
    HistoricalV3AgentReviewer {
        agent_id: agent_id.to_string(),
        provider: "example-provider".to_string(),
        model: "example-model".to_string(),
        model_version: None,
        run_id: run_id.to_string(),
        prompt_sha256: format!("{:x}", Sha256::digest(PROMPT)),
        fresh_context: true,
        sniff_output_hidden: true,
        repository_identity_hidden: true,
        change_metadata_hidden: true,
        other_reviews_hidden: true,
        complete_source_context_inspected: true,
        behavior_evidence_inspected: true,
        attestation: "I read only the sealed source and behavior evidence.".to_string(),
    }
}

#[tokio::test]
async fn agent_reviews_bind_source_and_preserve_disagreement_without_human_labels() {
    let fixture = review_fixture().await;
    let slop = fixture
        .worksheet("human-fixture", HistoricalV3ReviewerVerdict::Slop)
        .task
        .decision;
    let clean = fixture
        .worksheet("human-fixture", HistoricalV3ReviewerVerdict::Clean)
        .task
        .decision;
    let first = seal_historical_v3_agent_review(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        reviewer("agent-a", "run-a"),
        slop,
    )
    .unwrap();
    let second = seal_historical_v3_agent_review(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        reviewer("agent-b", "run-b"),
        clean,
    )
    .unwrap();
    let audit = audit_historical_v3_agent_reviews(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        &first,
        &second,
    )
    .unwrap();
    assert!(!audit.tier_agreement);
    assert!(!audit.slop_pattern_agreement);
    assert_eq!(
        audit.labels[0].decision.verdict,
        Some(HistoricalV3ReviewerVerdict::Slop)
    );
    assert_eq!(
        audit.labels[1].decision.verdict,
        Some(HistoricalV3ReviewerVerdict::Clean)
    );
    validate_historical_v3_agent_audit(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        &first,
        &second,
        &audit,
    )
    .unwrap();
    let mut tampered = audit;
    tampered.tier_agreement = true;
    tampered.audit_sha256 = tampered.computed_sha256().unwrap();
    assert!(
        validate_historical_v3_agent_audit(
            &fixture.inputs(),
            &fixture.bundle,
            PROMPT,
            &first,
            &second,
            &tampered,
        )
        .is_err()
    );
}

#[tokio::test]
async fn agent_review_rejects_forged_citation_reused_run_and_missing_revision_field() {
    let fixture = review_fixture().await;
    let decision = fixture
        .worksheet("human-fixture", HistoricalV3ReviewerVerdict::Slop)
        .task
        .decision;
    let first = seal_historical_v3_agent_review(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        reviewer("agent-a", "run-a"),
        decision.clone(),
    )
    .unwrap();
    assert!(
        validate_historical_v3_agent_review(
            &fixture.inputs(),
            &fixture.bundle,
            b"different prompt",
            &first,
        )
        .is_err()
    );
    let mut raw_value = serde_json::to_value(&first).unwrap();
    raw_value["reviewer"]
        .as_object_mut()
        .unwrap()
        .remove("model_version");
    assert!(serde_json::from_value::<HistoricalV3AgentReviewSubmission>(raw_value).is_err());

    let mut forged = first.clone();
    forged.decision.citations[0].quote = "invented source quote".to_string();
    forged.submission_sha256 = forged.computed_sha256().unwrap();
    assert!(
        validate_historical_v3_agent_review(&fixture.inputs(), &fixture.bundle, PROMPT, &forged,)
            .is_err()
    );

    let second = seal_historical_v3_agent_review(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        reviewer("agent-b", "run-a"),
        decision,
    )
    .unwrap();
    assert!(
        audit_historical_v3_agent_reviews(
            &fixture.inputs(),
            &fixture.bundle,
            PROMPT,
            &first,
            &second,
        )
        .unwrap_err()
        .contains("repeats")
    );
}
