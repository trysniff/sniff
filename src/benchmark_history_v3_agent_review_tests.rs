use super::super::history_v3_label_review::tests::{
    decision_for_methods, review_fixture, review_fixture_with_protocol,
};
use super::*;

const PROMPT: &[u8] = b"Review the sealed source and behavior evidence without Sniff output.";

async fn agent_fixture() -> super::super::history_v3_label_review::tests::ReviewFixture {
    review_fixture_with_protocol(|mut protocol| {
        protocol.schema_version = super::super::HISTORICAL_V3_MODEL_PROTOCOL_SCHEMA_VERSION;
        protocol.protocol_contract =
            "sniffbench-historical-v3-model-judged-protocol-v7".to_string();
        protocol.human_review_policy = None;
        protocol.model_review_policy = Some(super::super::HistoricalV3ModelReviewPolicy {
            source_only_review: true,
            independent_reviewers: 2,
            approved_prompt_sha256: sha256(PROMPT),
            prompt_public_url: "https://raw.githubusercontent.com/trysniff/sniff/0000000000000000000000000000000000000000/sniffbench/HISTORICAL_V3_AGENT_REVIEW_PROMPT.md".to_string(),
            exact_presented_material_record_required: true,
            invocation_response_record_required: true,
            disagreements_remain_unresolved: true,
            human_gold_claim_forbidden: true,
        });
        protocol.model_access_forbidden = false;
        super::super::seal_historical_v3_protocol(protocol).unwrap()
    })
    .await
}

fn response(reviewer: HistoricalV3AgentReviewer, decision: HistoricalV3ReviewDecision) -> String {
    serde_json::to_string(&HistoricalV3AgentModelOutput { reviewer, decision }).unwrap()
}

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
    let fixture = agent_fixture().await;
    let slop = decision_for_methods(&fixture.bundle.methods, HistoricalV3ReviewerVerdict::Slop);
    let clean = decision_for_methods(&fixture.bundle.methods, HistoricalV3ReviewerVerdict::Clean);
    let first = seal_historical_v3_agent_review(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        response(reviewer("agent-a", "run-a"), slop),
    )
    .unwrap();
    let second = seal_historical_v3_agent_review(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        response(reviewer("agent-b", "run-b"), clean),
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
    let fixture = agent_fixture().await;
    let decision = decision_for_methods(&fixture.bundle.methods, HistoricalV3ReviewerVerdict::Slop);
    let first = seal_historical_v3_agent_review(
        &fixture.inputs(),
        &fixture.bundle,
        PROMPT,
        response(reviewer("agent-a", "run-a"), decision.clone()),
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
        response(reviewer("agent-b", "run-a"), decision),
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

    let mut altered_invocation = first.clone();
    altered_invocation
        .invocation_request
        .push_str(" injected Sniff output");
    altered_invocation.invocation_request_sha256 =
        sha256(altered_invocation.invocation_request.as_bytes());
    altered_invocation.submission_sha256 = altered_invocation.computed_sha256().unwrap();
    assert!(
        validate_historical_v3_agent_review(
            &fixture.inputs(),
            &fixture.bundle,
            PROMPT,
            &altered_invocation,
        )
        .is_err()
    );

    let mut altered_response = first.clone();
    altered_response.raw_response = altered_response
        .raw_response
        .replace("example-provider", "other-provider");
    altered_response.raw_response_sha256 = sha256(altered_response.raw_response.as_bytes());
    altered_response.submission_sha256 = altered_response.computed_sha256().unwrap();
    assert!(
        validate_historical_v3_agent_review(
            &fixture.inputs(),
            &fixture.bundle,
            PROMPT,
            &altered_response,
        )
        .is_err()
    );

    let human_fixture = review_fixture().await;
    let human_decision = decision_for_methods(
        &human_fixture.bundle.methods,
        HistoricalV3ReviewerVerdict::Clean,
    );
    assert!(
        seal_historical_v3_agent_review(
            &human_fixture.inputs(),
            &human_fixture.bundle,
            PROMPT,
            response(reviewer("agent-a", "run-a"), human_decision),
        )
        .unwrap_err()
        .contains("model-judged protocol authority")
    );
}
