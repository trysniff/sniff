use super::super::history_v3_agent_review::tests::{
    PROMPT, agent_fixture, assignment, response, reviewer,
};
use super::super::history_v3_label_review::tests::decision_for_methods;
use super::super::history_v3_label_review::tests::review_fixture;
use super::super::{
    HistoricalV3NextStep, HistoricalV3OrderedRankOutcome, HistoricalV3ReplayProgress,
    HistoricalV3ReviewDisposition, HistoricalV3ReviewerVerdict, audit_historical_v3_agent_reviews,
    audit_historical_v3_label_reviews, historical_v3_agent_invocation_request,
    historical_v3_agent_slot_card, prepare_historical_v3_label_resolution,
    prepare_historical_v3_stop_artifact, replay_historical_v3_ordered_progress,
    resolve_historical_v3_label, seal_historical_v3_agent_review,
    verify_historical_v3_stop_from_disk, write_historical_v3_final_label_new,
    write_historical_v3_label_audit_new, write_historical_v3_label_worksheet_new,
    write_historical_v3_resolution_worksheet_new, write_historical_v3_stop_artifact_new,
};
use super::{
    HistoricalV3ReviewRecordPaths, verify_historical_v3_agent_review_from_disk,
    verify_historical_v3_final_review_from_disk,
};

#[tokio::test]
async fn replays_review_from_journal_and_all_committed_human_records() {
    let fixture = review_fixture().await;
    let inputs = fixture.inputs();
    let worksheets = [
        fixture.worksheet("reviewer-a", HistoricalV3ReviewerVerdict::Slop),
        fixture.worksheet("reviewer-b", HistoricalV3ReviewerVerdict::Slop),
    ];
    let audit = audit_historical_v3_label_reviews(&inputs, &fixture.bundle, &worksheets).unwrap();
    let resolution =
        prepare_historical_v3_label_resolution(&inputs, &fixture.bundle, &worksheets, &audit)
            .unwrap();
    let label =
        resolve_historical_v3_label(&inputs, &fixture.bundle, &worksheets, &audit, &resolution)
            .unwrap();
    let root = tempfile::tempdir().unwrap();
    let paths = HistoricalV3ReviewRecordPaths::new(root.path(), &inputs.qualification.rank);
    std::fs::create_dir_all(paths.audit.parent().unwrap()).unwrap();
    write_historical_v3_label_worksheet_new(&paths.reviewer_one, &worksheets[0]).unwrap();
    write_historical_v3_label_worksheet_new(&paths.reviewer_two, &worksheets[1]).unwrap();
    write_historical_v3_label_audit_new(&paths.audit, &audit).unwrap();
    assert!(
        verify_historical_v3_final_review_from_disk(
            inputs.protocol,
            inputs.collection,
            1,
            fixture.journal_path(),
            root.path(),
        )
        .is_err()
    );
    write_historical_v3_resolution_worksheet_new(&paths.resolution, &resolution).unwrap();
    write_historical_v3_final_label_new(&paths.final_label, &label).unwrap();
    let proof = verify_historical_v3_final_review_from_disk(
        inputs.protocol,
        inputs.collection,
        1,
        fixture.journal_path(),
        root.path(),
    )
    .unwrap();
    assert_eq!(
        proof.record().disposition,
        HistoricalV3ReviewDisposition::Accepted
    );
    assert_eq!(proof.rank(), &inputs.qualification.rank);
    let language = inputs.qualification.rank.language();
    let outcomes = [HistoricalV3OrderedRankOutcome::Reviewed(proof)];
    let stop = prepare_historical_v3_stop_artifact(
        inputs.protocol,
        inputs.collection,
        language,
        &outcomes,
    )
    .unwrap();
    let stop_path = root.path().join("stop.json");
    write_historical_v3_stop_artifact_new(&stop_path, &stop).unwrap();
    assert_eq!(
        verify_historical_v3_stop_from_disk(
            inputs.protocol,
            inputs.collection,
            language,
            fixture.journal_path(),
            root.path(),
            &stop_path,
        )
        .unwrap(),
        stop
    );
    let mut altered = audit;
    altered.audit_sha256 = "0".repeat(64);
    std::fs::write(&paths.audit, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(
        verify_historical_v3_final_review_from_disk(
            inputs.protocol,
            inputs.collection,
            1,
            fixture.journal_path(),
            root.path(),
        )
        .is_err()
    );
    assert!(
        verify_historical_v3_stop_from_disk(
            inputs.protocol,
            inputs.collection,
            language,
            fixture.journal_path(),
            root.path(),
            &stop_path,
        )
        .is_err()
    );
}

#[tokio::test]
async fn model_review_replays_raw_submissions_and_audit_without_human_records() {
    let fixture = agent_fixture().await;
    let inputs = fixture.inputs();
    let assignment = assignment(&fixture);
    let decision = decision_for_methods(&fixture.bundle.methods, HistoricalV3ReviewerVerdict::Slop);
    let first = seal_historical_v3_agent_review(
        &inputs,
        &fixture.bundle,
        PROMPT,
        response(
            reviewer(&assignment.agent_ids[0], "run-a"),
            decision.clone(),
        ),
    )
    .unwrap();
    let second = seal_historical_v3_agent_review(
        &inputs,
        &fixture.bundle,
        PROMPT,
        response(reviewer(&assignment.agent_ids[1], "run-b"), decision),
    )
    .unwrap();
    let audit = audit_historical_v3_agent_reviews(
        &inputs,
        &fixture.bundle,
        PROMPT,
        &assignment,
        &first,
        &second,
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let paths = HistoricalV3ReviewRecordPaths::new(root.path(), &inputs.qualification.rank);
    std::fs::create_dir_all(paths.agent_audit.parent().unwrap()).unwrap();
    let stop_path = root.path().join("stop.json");
    let progress = || {
        replay_historical_v3_ordered_progress(
            inputs.protocol,
            inputs.collection,
            inputs.qualification.rank.language(),
            fixture.journal_path(),
            root.path(),
            &stop_path,
        )
    };
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::AgentReview,
            ..
        }
    ));
    let invocation = historical_v3_agent_invocation_request(PROMPT, &fixture.bundle).unwrap();
    std::fs::write(
        &paths.agent_assignment,
        serde_json::to_vec(&assignment).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::AgentReview,
            ..
        }
    ));
    let first_card = historical_v3_agent_slot_card(&assignment, invocation.as_bytes(), 1).unwrap();
    let second_card = historical_v3_agent_slot_card(&assignment, invocation.as_bytes(), 2).unwrap();
    std::fs::write(&paths.agent_one_card, first_card.as_bytes()).unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::AgentReview,
            ..
        }
    ));
    std::fs::write(&paths.agent_two_card, second_card.as_bytes()).unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::AgentReview,
            ..
        }
    ));
    std::fs::write(&paths.agent_invocation, invocation.as_bytes()).unwrap();
    std::fs::write(&paths.agent_one, serde_json::to_vec(&first).unwrap()).unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::AgentReview,
            ..
        }
    ));
    std::fs::write(&paths.agent_two, serde_json::to_vec(&second).unwrap()).unwrap();
    std::fs::write(&paths.agent_audit, serde_json::to_vec(&audit).unwrap()).unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::AwaitingStopPublication { .. }
    ));
    let proof = verify_historical_v3_agent_review_from_disk(
        inputs.protocol,
        inputs.collection,
        1,
        fixture.journal_path(),
        root.path(),
    )
    .unwrap();
    assert_eq!(
        proof.record().disposition,
        HistoricalV3ReviewDisposition::Accepted
    );
    let outcomes = [HistoricalV3OrderedRankOutcome::AgentReviewed(proof)];
    let stop = prepare_historical_v3_stop_artifact(
        inputs.protocol,
        inputs.collection,
        inputs.qualification.rank.language(),
        &outcomes,
    )
    .unwrap();
    assert_eq!(stop.schema_version, 2);
    write_historical_v3_stop_artifact_new(&stop_path, &stop).unwrap();
    assert_eq!(
        verify_historical_v3_stop_from_disk(
            inputs.protocol,
            inputs.collection,
            inputs.qualification.rank.language(),
            fixture.journal_path(),
            root.path(),
            &stop_path,
        )
        .unwrap(),
        stop
    );
    std::fs::write(&paths.agent_invocation, b"{}").unwrap();
    assert!(
        verify_historical_v3_agent_review_from_disk(
            inputs.protocol,
            inputs.collection,
            1,
            fixture.journal_path(),
            root.path(),
        )
        .is_err()
    );
    std::fs::write(&paths.agent_invocation, invocation.as_bytes()).unwrap();
    let mut altered = audit.clone();
    altered.audit_sha256 = "0".repeat(64);
    std::fs::write(&paths.agent_audit, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(progress().is_err());
    assert!(
        verify_historical_v3_stop_from_disk(
            inputs.protocol,
            inputs.collection,
            inputs.qualification.rank.language(),
            fixture.journal_path(),
            root.path(),
            &stop_path,
        )
        .is_err()
    );
    std::fs::write(&paths.agent_audit, serde_json::to_vec(&audit).unwrap()).unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::Terminal { .. }
    ));
    std::fs::write(&paths.agent_one_card, b"{}").unwrap();
    assert!(progress().is_err());
    std::fs::write(&paths.agent_one_card, first_card.as_bytes()).unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::Terminal { .. }
    ));
    std::fs::remove_file(&paths.agent_two_card).unwrap();
    assert!(progress().is_err());
    std::fs::write(&paths.agent_two_card, second_card.as_bytes()).unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::Terminal { .. }
    ));
    std::fs::write(&paths.agent_assignment, b"{}").unwrap();
    assert!(progress().is_err());
    std::fs::write(
        &paths.agent_assignment,
        serde_json::to_vec(&assignment).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        progress().unwrap(),
        HistoricalV3ReplayProgress::Terminal { .. }
    ));
    std::fs::write(&paths.reviewer_one, b"{}").unwrap();
    assert!(
        verify_historical_v3_stop_from_disk(
            inputs.protocol,
            inputs.collection,
            inputs.qualification.rank.language(),
            fixture.journal_path(),
            root.path(),
            &stop_path,
        )
        .is_err()
    );
}
