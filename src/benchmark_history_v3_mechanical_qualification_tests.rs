use super::super::history_v3_rank_journal::rank_workspace;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::{
    HistoricalV3MechanicalExclusionReason, HistoricalV3MechanicalQualificationStageRun,
    HistoricalV3RankJournal, HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind,
    HistoricalV3RankStage, HistoricalV3SimplificationKind, historical_v3_rank_identity,
};
use super::runtime::run_historical_v3_mechanical_qualification_stage_with;
use super::{
    run_historical_v3_mechanical_qualification_stage,
    validate_historical_v3_mechanical_qualification,
};
use std::fs;

#[tokio::test]
async fn qualifies_exact_reduction_rejects_rehashed_tamper_and_resumes_without_git() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    semantic_fixture::prepare_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    semantic_fixture::prepare_semantic_rank(
        &protocol,
        &collection,
        journal.path(),
        workspace.path(),
    )
    .await;

    let first =
        run_historical_v3_mechanical_qualification_stage(&protocol, &collection, 1, journal.path())
            .unwrap();
    let HistoricalV3MechanicalQualificationStageRun::Qualified {
        artifact,
        resumed: false,
    } = first
    else {
        panic!("the synthetic production reduction must qualify");
    };
    assert_eq!(
        artifact.evidence.simplifications,
        [HistoricalV3SimplificationKind::ProductionLineReduction]
    );
    assert_eq!(artifact.evidence.changed_methods.len(), 2);
    assert!(artifact.evidence.public_surface.preserved);

    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    let inputs = super::store::read_inputs(persisted.history()).unwrap();
    let mut tampered = (*artifact).clone();
    tampered.evidence.changed_methods.clear();
    tampered = super::commitment::seal_qualification(tampered).unwrap();
    let error = validate_historical_v3_mechanical_qualification(
        &protocol,
        &collection,
        &inputs.materialization,
        &inputs.source_census,
        &inputs.semantic_census,
        &tampered,
    )
    .unwrap_err();
    assert!(error.contains("changed"));
    drop(persisted);

    let destination = rank_workspace(workspace.path(), &identity).unwrap();
    fs::rename(
        destination.join("repository/.git"),
        destination.join("repository/.git-disabled"),
    )
    .unwrap();
    let resumed =
        run_historical_v3_mechanical_qualification_stage(&protocol, &collection, 1, journal.path())
            .unwrap();
    assert!(matches!(
        resumed,
        HistoricalV3MechanicalQualificationStageRun::Qualified { resumed: true, .. }
    ));
}

#[tokio::test]
async fn commits_formatting_only_as_a_typed_terminal_exclusion() {
    let fixture = semantic_fixture::fixture_with_source(
        "src/lib.rs",
        "pub fn total()->i32{1}\n",
        "pub fn total() ->i32 {1}\n",
    );
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    semantic_fixture::prepare_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    semantic_fixture::prepare_semantic_rank(
        &protocol,
        &collection,
        journal.path(),
        workspace.path(),
    )
    .await;

    let outcome =
        run_historical_v3_mechanical_qualification_stage(&protocol, &collection, 1, journal.path())
            .unwrap();
    let HistoricalV3MechanicalQualificationStageRun::Excluded { artifact, .. } = outcome else {
        panic!("format-only source must be excluded");
    };
    assert!(artifact.evidence.formatting_only);
    assert!(
        artifact
            .reasons
            .contains(&HistoricalV3MechanicalExclusionReason::FormattingOnly)
    );
    let proof = super::super::verify_historical_v3_terminal_exclusion(
        &protocol,
        &collection,
        1,
        journal.path(),
    )
    .unwrap();
    assert_eq!(
        proof.stage(),
        super::super::HistoricalV3RankStage::MechanicalQualification
    );
}

#[tokio::test]
async fn commits_test_only_change_as_a_typed_terminal_exclusion() {
    let fixture = semantic_fixture::fixture_with_source(
        "tests/total.rs",
        "pub fn total() -> i32 {\n    let value = 1;\n    value\n}\n",
        "pub fn total() -> i32 { 2 }\n",
    );
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    semantic_fixture::prepare_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    semantic_fixture::prepare_semantic_rank(
        &protocol,
        &collection,
        journal.path(),
        workspace.path(),
    )
    .await;

    let outcome =
        run_historical_v3_mechanical_qualification_stage(&protocol, &collection, 1, journal.path())
            .unwrap();
    let HistoricalV3MechanicalQualificationStageRun::Excluded { artifact, .. } = outcome else {
        panic!("test-only source must be excluded");
    };
    assert!(
        artifact
            .reasons
            .contains(&HistoricalV3MechanicalExclusionReason::TestOnly)
    );
    assert!(
        artifact
            .reasons
            .contains(&HistoricalV3MechanicalExclusionReason::NoChangedProductionMethods)
    );
}

#[tokio::test]
async fn operational_failure_leaves_mechanical_rank_open_for_retry() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    semantic_fixture::prepare_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    semantic_fixture::prepare_semantic_rank(
        &protocol,
        &collection,
        journal.path(),
        workspace.path(),
    )
    .await;

    let error = run_historical_v3_mechanical_qualification_stage_with(
        &protocol,
        &collection,
        1,
        journal.path(),
        |_| {
            Err(HistoricalV3RankJournalError {
                stage: HistoricalV3RankStage::MechanicalQualification,
                kind: HistoricalV3RankJournalErrorKind::InfrastructureUnavailable,
                detail: "synthetic mechanical infrastructure outage".to_string(),
            })
        },
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
    );
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    assert_eq!(persisted.history().len(), 3);
    assert_eq!(
        persisted.next_stage(),
        Some(HistoricalV3RankStage::MechanicalQualification)
    );
    drop(persisted);

    let retried =
        run_historical_v3_mechanical_qualification_stage(&protocol, &collection, 1, journal.path())
            .unwrap();
    assert!(matches!(
        retried,
        HistoricalV3MechanicalQualificationStageRun::Qualified { resumed: false, .. }
    ));
}
