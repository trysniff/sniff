use super::super::history_v3_mechanical_qualification::run_historical_v3_mechanical_qualification_stage;
use super::super::history_v3_rank_journal::rank_workspace;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3Protocol, HistoricalV3RankJournal,
    HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind, HistoricalV3RankStage,
    HistoricalV3TestRecipeExclusionReason, HistoricalV3TestRecipeSelector,
    HistoricalV3TestRecipeStageRun, historical_v3_rank_identity,
};
use super::runtime::run_historical_v3_test_recipe_stage_with;
use super::{run_historical_v3_test_recipe_stage, validate_historical_v3_test_recipe};
use std::fs;
use std::path::Path;

#[tokio::test]
async fn selects_bound_cargo_recipe_rejects_rehashed_tamper_and_resumes_without_git() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    prepare_qualified_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    )
    .await;

    let first =
        run_historical_v3_test_recipe_stage(&protocol, &collection, 1, journal.path()).unwrap();
    let HistoricalV3TestRecipeStageRun::Selected {
        artifact,
        resumed: false,
    } = first
    else {
        panic!("the unchanged Cargo recipe must be selected");
    };
    assert_eq!(artifact.selector, HistoricalV3TestRecipeSelector::Cargo);
    assert_eq!(artifact.inputs.len(), 2);
    assert_eq!(artifact.runtime_program, "cargo");
    assert!(
        artifact
            .test_command
            .argv
            .contains(&"--offline".to_string())
    );

    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    let inputs = super::store::read_inputs(persisted.history()).unwrap();
    let mut tampered = (*artifact).clone();
    tampered.test_command.argv.push("--ignored".to_string());
    tampered = super::commitment::seal_recipe(tampered).unwrap();
    assert!(
        validate_historical_v3_test_recipe(
            &protocol,
            &collection,
            &inputs.materialization,
            &inputs.source_census,
            &inputs.semantic_census,
            &inputs.qualification,
            &tampered,
        )
        .unwrap_err()
        .contains("changed")
    );
    drop(persisted);

    let destination = rank_workspace(workspace.path(), &identity).unwrap();
    fs::rename(
        destination.join("repository/.git"),
        destination.join("repository/.git-disabled"),
    )
    .unwrap();
    let resumed =
        run_historical_v3_test_recipe_stage(&protocol, &collection, 1, journal.path()).unwrap();
    assert!(matches!(
        resumed,
        HistoricalV3TestRecipeStageRun::Selected { resumed: true, .. }
    ));
}

#[tokio::test]
async fn commits_changed_recipe_input_as_a_typed_terminal_exclusion() {
    let fixture = semantic_fixture::fixture_with_changed_recipe(
        "src/lib.rs",
        "pub fn total() -> i32 {\n    let value = 1;\n    value\n}\n",
        "pub fn total() -> i32 { 2 }\n",
    );
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    prepare_qualified_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    )
    .await;

    let outcome =
        run_historical_v3_test_recipe_stage(&protocol, &collection, 1, journal.path()).unwrap();
    let HistoricalV3TestRecipeStageRun::Excluded { artifact, .. } = outcome else {
        panic!("changed Cargo inputs must be excluded");
    };
    assert_eq!(
        artifact.reason,
        HistoricalV3TestRecipeExclusionReason::ChangedRecipeInputs
    );
}

#[tokio::test]
async fn commits_missing_language_recipe_as_a_typed_terminal_exclusion() {
    let fixture = semantic_fixture::fixture_without_recipe(
        "src/lib.rs",
        "pub fn total() -> i32 {\n    let value = 1;\n    value\n}\n",
        "pub fn total() -> i32 { 2 }\n",
    );
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    prepare_qualified_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    )
    .await;

    let outcome =
        run_historical_v3_test_recipe_stage(&protocol, &collection, 1, journal.path()).unwrap();
    let HistoricalV3TestRecipeStageRun::Excluded { artifact, .. } = outcome else {
        panic!("missing Cargo inputs must be excluded");
    };
    assert_eq!(
        artifact.reason,
        HistoricalV3TestRecipeExclusionReason::MissingRecipeInputs
    );
}

#[tokio::test]
async fn operational_failure_leaves_test_recipe_rank_open_for_retry() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    prepare_qualified_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    )
    .await;

    let error =
        run_historical_v3_test_recipe_stage_with(&protocol, &collection, 1, journal.path(), |_| {
            Err(HistoricalV3RankJournalError {
                stage: HistoricalV3RankStage::TestRecipe,
                kind: HistoricalV3RankJournalErrorKind::InfrastructureUnavailable,
                detail: "synthetic test-recipe infrastructure outage".to_string(),
            })
        })
        .unwrap_err();
    assert_eq!(
        error.kind,
        HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
    );
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    assert_eq!(persisted.history().len(), 4);
    assert_eq!(
        persisted.next_stage(),
        Some(HistoricalV3RankStage::TestRecipe)
    );
    drop(persisted);

    let retried =
        run_historical_v3_test_recipe_stage(&protocol, &collection, 1, journal.path()).unwrap();
    assert!(matches!(
        retried,
        HistoricalV3TestRecipeStageRun::Selected { resumed: false, .. }
    ));
}

async fn prepare_qualified_rank(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    fixture: &semantic_fixture::GitFixture,
    journal: &Path,
    workspace: &Path,
) {
    semantic_fixture::prepare_rank(protocol, collection, fixture, journal, workspace);
    semantic_fixture::prepare_semantic_rank(protocol, collection, journal, workspace).await;
    let qualification =
        run_historical_v3_mechanical_qualification_stage(protocol, collection, 1, journal).unwrap();
    assert!(matches!(
        qualification,
        super::super::HistoricalV3MechanicalQualificationStageRun::Qualified { resumed: false, .. }
    ));
}
