use super::super::history_v3_rank_journal::rank_workspace;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::history_v3_test_recipe::tests::prepare_qualified_rank;
use super::super::{
    HistoricalV3ExecutionCommandEvidence, HistoricalV3ExecutionPhase, HistoricalV3ExecutionSide,
    HistoricalV3IdenticalTestExclusionReason, HistoricalV3IdenticalTestExecutionError,
    HistoricalV3IdenticalTestExecutionRequest, HistoricalV3IdenticalTestExecutor,
    HistoricalV3IdenticalTestOutcome, HistoricalV3IdenticalTestsStageRun, HistoricalV3RankJournal,
    HistoricalV3RankJournalErrorKind, HistoricalV3RankStage, HistoricalV3RawIdenticalTestExecution,
    HistoricalV3TestRecipe, HistoricalV3TestRecipeStageRun, historical_v3_rank_identity,
    run_historical_v3_test_recipe_stage,
};
use super::{run_historical_v3_identical_tests_stage, validate_historical_v3_identical_tests};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::fs;

#[derive(Clone, Copy)]
enum FakeOutcome {
    Pass,
    Exclude,
    InfrastructureFailure,
}

struct FakeExecutor {
    outcome: FakeOutcome,
    recoveries: Cell<usize>,
    executions: Cell<usize>,
}

impl FakeExecutor {
    fn new(outcome: FakeOutcome) -> Self {
        Self {
            outcome,
            recoveries: Cell::new(0),
            executions: Cell::new(0),
        }
    }
}

impl HistoricalV3IdenticalTestExecutor for FakeExecutor {
    fn recover(
        &self,
        _execution_identity_sha256: &str,
    ) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        self.recoveries.set(self.recoveries.get() + 1);
        Ok(())
    }

    fn execute(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        self.executions.set(self.executions.get() + 1);
        if matches!(self.outcome, FakeOutcome::InfrastructureFailure) {
            return Err(HistoricalV3IdenticalTestExecutionError::unavailable(
                "synthetic container outage",
            ));
        }
        let (events, outcome) = match self.outcome {
            FakeOutcome::Pass => (
                passing_events(request.recipe),
                HistoricalV3IdenticalTestOutcome::Passed,
            ),
            FakeOutcome::Exclude => {
                let event = event(
                    request.recipe,
                    HistoricalV3ExecutionSide::Base,
                    HistoricalV3ExecutionPhase::Preparation,
                    0,
                    Some(1),
                );
                (
                    vec![event],
                    HistoricalV3IdenticalTestOutcome::Excluded {
                        reason: HistoricalV3IdenticalTestExclusionReason::PreparationFailed {
                            side: HistoricalV3ExecutionSide::Base,
                            command_index: 0,
                        },
                    },
                )
            }
            FakeOutcome::InfrastructureFailure => unreachable!(),
        };
        Ok(HistoricalV3RawIdenticalTestExecution {
            image_digest: request.recipe.image_digest.clone(),
            toolchain_manifest_sha256: request.recipe.toolchain_manifest_sha256.clone(),
            dependency_store_sha256: request.recipe.dependency_store_sha256.clone(),
            events,
            outcome,
        })
    }
}

#[tokio::test]
async fn commits_exact_execution_rejects_rehashed_tamper_and_resumes_without_git_or_executor() {
    let (fixture, protocol, collection, journal, workspace, recipe) = prepared_rank().await;
    let executor = FakeExecutor::new(FakeOutcome::Pass);
    let first = run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &executor,
    )
    .unwrap();
    let HistoricalV3IdenticalTestsStageRun::Passed {
        artifact,
        resumed: false,
    } = first
    else {
        panic!("both exact executions must pass");
    };
    assert_eq!(artifact.events.len(), 4);
    assert_eq!(executor.recoveries.get(), 1);
    assert_eq!(executor.executions.get(), 1);

    let mut tampered = (*artifact).clone();
    tampered.events[0].command_sha256 = "d".repeat(64);
    tampered.execution_sha256 = super::commitment::execution_sha256(&tampered).unwrap();
    assert!(
        validate_historical_v3_identical_tests(&protocol, &recipe, &tampered)
            .unwrap_err()
            .contains("command evidence")
    );

    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let destination = rank_workspace(workspace.path(), &identity).unwrap();
    fs::rename(
        destination.join("repository/.git"),
        destination.join("repository/.git-disabled"),
    )
    .unwrap();
    let resumed = run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &executor,
    )
    .unwrap();
    assert!(matches!(
        resumed,
        HistoricalV3IdenticalTestsStageRun::Passed { resumed: true, .. }
    ));
    assert_eq!(executor.recoveries.get(), 1);
    assert_eq!(executor.executions.get(), 1);
    drop(fixture);
}

#[tokio::test]
async fn commits_candidate_command_failure_as_a_typed_terminal_exclusion() {
    let (_fixture, protocol, collection, journal, workspace, _) = prepared_rank().await;
    let executor = FakeExecutor::new(FakeOutcome::Exclude);
    let outcome = run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &executor,
    )
    .unwrap();
    assert!(matches!(
        outcome,
        HistoricalV3IdenticalTestsStageRun::Excluded { resumed: false, .. }
    ));
}

#[tokio::test]
async fn infrastructure_failure_leaves_the_exact_rank_open_for_retry() {
    let (_fixture, protocol, collection, journal, workspace, _) = prepared_rank().await;
    let failing = FakeExecutor::new(FakeOutcome::InfrastructureFailure);
    let error = run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &failing,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
    );
    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    assert_eq!(persisted.history().len(), 5);
    assert_eq!(
        persisted.next_stage(),
        Some(HistoricalV3RankStage::IdenticalTests)
    );
    drop(persisted);

    let retry = FakeExecutor::new(FakeOutcome::Pass);
    assert!(matches!(
        run_historical_v3_identical_tests_stage(
            &protocol,
            &collection,
            1,
            journal.path(),
            workspace.path(),
            &retry,
        )
        .unwrap(),
        HistoricalV3IdenticalTestsStageRun::Passed { resumed: false, .. }
    ));
}

pub(crate) async fn prepared_rank() -> (
    semantic_fixture::GitFixture,
    super::super::HistoricalV3Protocol,
    super::super::HistoricalV3CandidateCollection,
    tempfile::TempDir,
    tempfile::TempDir,
    HistoricalV3TestRecipe,
) {
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
    let outcome =
        run_historical_v3_test_recipe_stage(&protocol, &collection, 1, journal.path()).unwrap();
    let HistoricalV3TestRecipeStageRun::Selected { artifact, .. } = outcome else {
        panic!("the Cargo fixture must select a recipe");
    };
    (fixture, protocol, collection, journal, workspace, *artifact)
}

pub(crate) fn passing_events(
    recipe: &HistoricalV3TestRecipe,
) -> Vec<HistoricalV3ExecutionCommandEvidence> {
    let mut events = Vec::new();
    for side in [
        HistoricalV3ExecutionSide::Base,
        HistoricalV3ExecutionSide::Merge,
    ] {
        for index in 0..recipe.preparation_commands.len() {
            events.push(event(
                recipe,
                side,
                HistoricalV3ExecutionPhase::Preparation,
                index,
                Some(0),
            ));
        }
        events.push(event(
            recipe,
            side,
            HistoricalV3ExecutionPhase::Test,
            0,
            Some(0),
        ));
    }
    events
}

fn event(
    recipe: &HistoricalV3TestRecipe,
    side: HistoricalV3ExecutionSide,
    phase: HistoricalV3ExecutionPhase,
    command_index: usize,
    exit_code: Option<i32>,
) -> HistoricalV3ExecutionCommandEvidence {
    let command = match phase {
        HistoricalV3ExecutionPhase::Preparation => &recipe.preparation_commands[command_index],
        HistoricalV3ExecutionPhase::Test => &recipe.test_command,
    };
    let empty = Vec::<u8>::new();
    HistoricalV3ExecutionCommandEvidence {
        side,
        phase,
        command_index,
        command_sha256: super::commitment::command_sha256(command).unwrap(),
        exit_code,
        timed_out: false,
        duration_millis: 1,
        stdout_sha256: format!("{:x}", Sha256::digest(&empty)),
        stderr_sha256: format!("{:x}", Sha256::digest(&empty)),
        stdout_byte_count: 0,
        stderr_byte_count: 0,
        retained_stdout_base64: base64::engine::general_purpose::STANDARD.encode(&empty),
        retained_stderr_base64: base64::engine::general_purpose::STANDARD.encode(&empty),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}
