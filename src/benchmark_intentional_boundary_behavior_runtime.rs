use super::super::intentional_boundary_runtime_snapshot::IntentionalBoundaryRuntimeSnapshot;
use super::super::{
    HistoricalTestExecution, HistoricalTestExecutionOutcome, HistoricalTestRecipeDiscovery,
    HistoricalTestRecipeStatus, discover_historical_test_recipe, run_intentional_boundary_test,
};
use super::{
    BehaviorExecutionAttempt, IntentionalBoundaryBehaviorExecution,
    IntentionalBoundaryBehaviorSelector, IntentionalBoundaryBehaviorTestProofKind,
    IntentionalBoundaryBehaviorUnresolvedReason, IntentionalBoundaryBehaviorWitnessOutcome,
    hash_json, is_sha256,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) fn execute_behavior_selector(
    source_root: &Path,
    revision: &str,
    selector: &IntentionalBoundaryBehaviorSelector,
) -> Result<BehaviorExecutionAttempt, String> {
    if matches!(
        selector,
        IntentionalBoundaryBehaviorSelector::JavaScriptTest { .. }
            | IntentionalBoundaryBehaviorSelector::GradleTest { .. }
    ) {
        return Ok(unresolved_without_execution(
            IntentionalBoundaryBehaviorUnresolvedReason::UnsupportedTargetSelector,
            format!(
                "{} has no frozen exact-test adapter",
                provider_name(selector)
            ),
        ));
    }

    let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
        source_root,
        revision,
        "sniff-boundary-behavior",
    )?;
    let recipe = discover_historical_test_recipe(snapshot.path(), snapshot.path())?;
    if recipe.status != HistoricalTestRecipeStatus::Selected {
        return Ok(unresolved_without_execution(
            IntentionalBoundaryBehaviorUnresolvedReason::RecipeUnavailable,
            recipe.reason,
        ));
    }
    let recipe_sha256 = hash_json(&recipe)?;
    let recipe_json = serde_json::to_string(&recipe)
        .map_err(|error| format!("failed to retain targeted test recipe: {error}"))?;
    let (preparation, command) = match targeted_command(selector, &recipe) {
        Ok(value) => value,
        Err(detail) => {
            return Ok(unresolved_without_execution(
                IntentionalBoundaryBehaviorUnresolvedReason::RecipeMismatch,
                detail,
            ));
        }
    };
    let outcome = run_intentional_boundary_test(snapshot.path(), revision, &preparation, &command)?;
    match outcome {
        HistoricalTestExecutionOutcome::RuntimeUnavailable(detail) => {
            Ok(unresolved_without_execution(
                IntentionalBoundaryBehaviorUnresolvedReason::RuntimeUnavailable,
                detail,
            ))
        }
        HistoricalTestExecutionOutcome::SandboxUnavailable(detail) => {
            Ok(unresolved_without_execution(
                IntentionalBoundaryBehaviorUnresolvedReason::SandboxUnavailable,
                detail,
            ))
        }
        HistoricalTestExecutionOutcome::Completed(completed) => {
            completed_attempt(selector, recipe_sha256, recipe_json, command, *completed)
        }
    }
}

pub(super) fn targeted_command(
    selector: &IntentionalBoundaryBehaviorSelector,
    recipe: &HistoricalTestRecipeDiscovery,
) -> Result<(Vec<Vec<String>>, Vec<String>), String> {
    let base = recipe
        .command
        .as_ref()
        .ok_or_else(|| "selected test recipe has no command".to_string())?;
    match selector {
        IntentionalBoundaryBehaviorSelector::CargoTest { test_name } => {
            let valid_base = matches!(
                base.as_slice(),
                [cargo, test, workspace, targets]
                    if cargo == "cargo"
                        && test == "test"
                        && workspace == "--workspace"
                        && targets == "--all-targets"
            ) || matches!(
                base.as_slice(),
                [cargo, test, workspace, targets, locked]
                    if cargo == "cargo"
                        && test == "test"
                        && workspace == "--workspace"
                        && targets == "--all-targets"
                        && locked == "--locked"
            );
            if !valid_base || !recipe.preparation_commands.is_empty() {
                return Err("Cargo selector requires the frozen root Cargo recipe".to_string());
            }
            let mut command = base.clone();
            command.extend([
                test_name.clone(),
                "--".to_string(),
                "--exact".to_string(),
                "--nocapture".to_string(),
                "--test-threads=1".to_string(),
            ]);
            Ok((Vec::new(), command))
        }
        IntentionalBoundaryBehaviorSelector::Pytest {
            repository_path,
            test_name,
        } => {
            if base
                != &[
                    "{sniff_private_python}".to_string(),
                    "-m".to_string(),
                    "pytest".to_string(),
                ]
            {
                return Err("pytest selector requires the frozen root pytest recipe".to_string());
            }
            let node_id = format!("{repository_path}::{test_name}");
            Ok((
                recipe.preparation_commands.clone(),
                vec![
                    "{sniff_private_python}".to_string(),
                    "-m".to_string(),
                    "pytest".to_string(),
                    node_id,
                    "--maxfail=1".to_string(),
                    "--tb=no".to_string(),
                    "-q".to_string(),
                ],
            ))
        }
        IntentionalBoundaryBehaviorSelector::GoTest {
            package_repository_path,
            test_name,
        } => {
            if base != &["go".to_string(), "test".to_string(), "./...".to_string()]
                || !recipe.preparation_commands.is_empty()
            {
                return Err("Go selector requires the frozen root Go recipe".to_string());
            }
            let package = if package_repository_path == "." {
                ".".to_string()
            } else {
                format!("./{package_repository_path}")
            };
            Ok((
                Vec::new(),
                vec![
                    "go".to_string(),
                    "test".to_string(),
                    package,
                    "-run".to_string(),
                    format!("^{test_name}$"),
                    "-count=1".to_string(),
                    "-json".to_string(),
                ],
            ))
        }
        IntentionalBoundaryBehaviorSelector::JavaScriptTest { .. }
        | IntentionalBoundaryBehaviorSelector::GradleTest { .. } => {
            Err("provider has no frozen exact-test adapter".to_string())
        }
    }
}

fn completed_attempt(
    selector: &IntentionalBoundaryBehaviorSelector,
    recipe_sha256: String,
    recipe_json: String,
    command: Vec<String>,
    completed: HistoricalTestExecution,
) -> Result<BehaviorExecutionAttempt, String> {
    let result = &completed.result;
    if result.network_enabled
        || result.command != command
        || result.revision.len() != 40
        || !is_sha256(&result.stdout_sha256)
        || !is_sha256(&result.stderr_sha256)
        || !is_sha256(&result.raw_result_sha256)
    {
        return Err("targeted behavior execution violated its sealed runtime contract".to_string());
    }
    let count = if result.test_executed && !result.timed_out && result.status_code == Some(0) {
        count_tests(
            selector,
            &completed.bounded_sanitized_stdout,
            &completed.bounded_sanitized_stderr,
        )
    } else {
        Ok(TestCount::default())
    };
    let (count, count_error) = match count {
        Ok(count) => (count, None),
        Err(error) => (TestCount::default(), Some(error)),
    };
    let raw_result_json = String::from_utf8(completed.raw_result.clone())
        .map_err(|_| "targeted behavior execution receipt is not UTF-8 JSON".to_string())?;
    let mut execution = IntentionalBoundaryBehaviorExecution {
        execution_id: String::new(),
        revision: result.revision.clone(),
        provider: selector.provider(),
        selector: selector.clone(),
        recipe_sha256,
        recipe_json,
        command,
        runtime_identity_sha256: sha256(result.runtime_identity.as_bytes()),
        status_code: result.status_code,
        timed_out: result.timed_out,
        network_enabled: result.network_enabled,
        test_executed: result.test_executed,
        executed_test_count: count.executed,
        matched_test_count: count.matched,
        stdout_sha256: result.stdout_sha256.clone(),
        stderr_sha256: result.stderr_sha256.clone(),
        raw_result_sha256: result.raw_result_sha256.clone(),
        raw_result_json,
    };
    execution.execution_id = compute_execution_id(&execution)?;
    let execution_id = execution.execution_id.clone();
    let outcome = if !result.test_executed {
        unresolved_with_execution(
            IntentionalBoundaryBehaviorUnresolvedReason::PreparationFailed,
            "targeted test preparation did not complete".to_string(),
            execution_id,
        )
    } else if result.timed_out || result.status_code != Some(0) {
        unresolved_with_execution(
            IntentionalBoundaryBehaviorUnresolvedReason::TargetedTestFailed,
            format!(
                "targeted test failed: status={:?}, timed_out={}",
                result.status_code, result.timed_out
            ),
            execution_id,
        )
    } else if let Some(detail) = count_error {
        unresolved_with_execution(
            IntentionalBoundaryBehaviorUnresolvedReason::TargetCountMismatch,
            detail,
            execution_id,
        )
    } else if count.executed != 1 || count.matched != 1 {
        unresolved_with_execution(
            IntentionalBoundaryBehaviorUnresolvedReason::TargetCountMismatch,
            format!(
                "targeted command executed {} tests and matched {} exact tests",
                count.executed, count.matched
            ),
            execution_id,
        )
    } else {
        IntentionalBoundaryBehaviorWitnessOutcome::Passed {
            proof: IntentionalBoundaryBehaviorTestProofKind::TargetedBehaviorPass,
            execution_id,
        }
    };
    Ok(BehaviorExecutionAttempt {
        execution: Some(execution),
        outcome,
    })
}

#[derive(Default, PartialEq, Eq)]
pub(super) struct TestCount {
    pub(super) executed: usize,
    pub(super) matched: usize,
}

pub(super) fn count_tests(
    selector: &IntentionalBoundaryBehaviorSelector,
    stdout: &str,
    stderr: &str,
) -> Result<TestCount, String> {
    match selector {
        IntentionalBoundaryBehaviorSelector::CargoTest { test_name } => {
            let mut count = TestCount::default();
            for line in stdout.lines().chain(stderr.lines()) {
                let Some(result) = line.trim().strip_prefix("test ") else {
                    continue;
                };
                let Some((name, status)) = result.rsplit_once(" ... ") else {
                    continue;
                };
                if !matches!(status, "ok" | "FAILED" | "ignored") {
                    continue;
                }
                count.executed += 1;
                if name == test_name && status == "ok" {
                    count.matched += 1;
                }
            }
            Ok(count)
        }
        IntentionalBoundaryBehaviorSelector::Pytest { .. } => {
            let summary = stdout.lines().chain(stderr.lines()).find(|line| {
                let line = line.trim();
                line.starts_with("1 passed") || line.contains(" 1 passed")
            });
            let Some(summary) = summary else {
                return Err("pytest emitted no exact one-pass summary".to_string());
            };
            if [
                "failed",
                "error",
                "skipped",
                "xfailed",
                "xpassed",
                "deselected",
            ]
            .iter()
            .any(|status| summary.contains(status))
            {
                return Err("pytest summary contains non-target outcomes".to_string());
            }
            Ok(TestCount {
                executed: 1,
                matched: 1,
            })
        }
        IntentionalBoundaryBehaviorSelector::GoTest { test_name, .. } => {
            let mut count = TestCount::default();
            for line in stdout
                .lines()
                .chain(stderr.lines())
                .filter(|line| !line.trim().is_empty())
            {
                let value: Value = serde_json::from_str(line)
                    .map_err(|_| "go test -json emitted a non-JSON record".to_string())?;
                let Some(name) = value.get("Test").and_then(Value::as_str) else {
                    continue;
                };
                let Some(action) = value.get("Action").and_then(Value::as_str) else {
                    return Err("go test -json emitted a test record without an action".to_string());
                };
                if matches!(action, "pass" | "fail" | "skip") {
                    count.executed += 1;
                    if name == test_name && action == "pass" {
                        count.matched += 1;
                    }
                }
            }
            Ok(count)
        }
        IntentionalBoundaryBehaviorSelector::JavaScriptTest { .. }
        | IntentionalBoundaryBehaviorSelector::GradleTest { .. } => {
            Err("provider has no frozen output parser".to_string())
        }
    }
}

pub(super) fn compute_execution_id(
    execution: &IntentionalBoundaryBehaviorExecution,
) -> Result<String, String> {
    Ok(format!(
        "ibbe-v1:{}",
        hash_json(&(
            &execution.revision,
            execution.provider,
            &execution.selector,
            &execution.recipe_sha256,
            &execution.command,
            &execution.runtime_identity_sha256,
            execution.status_code,
            execution.timed_out,
            execution.network_enabled,
            execution.test_executed,
            execution.executed_test_count,
            execution.matched_test_count,
            &execution.stdout_sha256,
            &execution.stderr_sha256,
            &execution.raw_result_sha256,
        ))?
    ))
}

fn unresolved_without_execution(
    reason: IntentionalBoundaryBehaviorUnresolvedReason,
    detail: String,
) -> BehaviorExecutionAttempt {
    BehaviorExecutionAttempt {
        execution: None,
        outcome: IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
            reason,
            detail,
            execution_id: None,
        },
    }
}

fn unresolved_with_execution(
    reason: IntentionalBoundaryBehaviorUnresolvedReason,
    detail: String,
    execution_id: String,
) -> IntentionalBoundaryBehaviorWitnessOutcome {
    IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
        reason,
        detail,
        execution_id: Some(execution_id),
    }
}

fn provider_name(selector: &IntentionalBoundaryBehaviorSelector) -> &'static str {
    match selector {
        IntentionalBoundaryBehaviorSelector::CargoTest { .. } => "Cargo",
        IntentionalBoundaryBehaviorSelector::Pytest { .. } => "pytest",
        IntentionalBoundaryBehaviorSelector::GoTest { .. } => "Go",
        IntentionalBoundaryBehaviorSelector::JavaScriptTest { .. } => "JavaScript",
        IntentionalBoundaryBehaviorSelector::GradleTest { .. } => "Gradle",
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe(command: Vec<&str>) -> HistoricalTestRecipeDiscovery {
        HistoricalTestRecipeDiscovery {
            status: HistoricalTestRecipeStatus::Selected,
            preparation_commands: Vec::new(),
            command: Some(command.into_iter().map(str::to_string).collect()),
            runtime_program: None,
            inputs: Vec::new(),
            reason: "fixture".to_string(),
        }
    }

    #[test]
    fn cargo_command_uses_the_exact_harness_selector() {
        let selector = IntentionalBoundaryBehaviorSelector::CargoTest {
            test_name: "tests::adapter_works".to_string(),
        };
        let (_, command) = targeted_command(
            &selector,
            &recipe(vec!["cargo", "test", "--workspace", "--all-targets"]),
        )
        .unwrap();

        assert_eq!(
            command,
            [
                "cargo",
                "test",
                "--workspace",
                "--all-targets",
                "tests::adapter_works",
                "--",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ]
        );
    }

    #[test]
    fn cargo_output_must_contain_only_the_exact_test() {
        let selector = IntentionalBoundaryBehaviorSelector::CargoTest {
            test_name: "tests::adapter_works".to_string(),
        };
        let exact = count_tests(
            &selector,
            "running 1 test\ntest tests::adapter_works ... ok\n",
            "",
        )
        .unwrap();
        let ambiguous = count_tests(
            &selector,
            "test tests::adapter_works ... ok\ntest other::adapter_works ... ok\n",
            "",
        )
        .unwrap();

        assert_eq!((exact.executed, exact.matched), (1, 1));
        assert_eq!((ambiguous.executed, ambiguous.matched), (2, 1));
    }

    #[test]
    fn go_output_counts_terminal_test_events_only() {
        let selector = IntentionalBoundaryBehaviorSelector::GoTest {
            package_repository_path: "internal/retry".to_string(),
            test_name: "TestRetryBoundary".to_string(),
        };
        let output = concat!(
            "{\"Action\":\"run\",\"Test\":\"TestRetryBoundary\"}\n",
            "{\"Action\":\"output\",\"Test\":\"TestRetryBoundary\",\"Output\":\"ok\"}\n",
            "{\"Action\":\"pass\",\"Test\":\"TestRetryBoundary\"}\n",
            "{\"Action\":\"pass\",\"Package\":\"example/internal/retry\"}\n",
        );

        let count = count_tests(&selector, output, "").unwrap();
        assert_eq!((count.executed, count.matched), (1, 1));
    }

    #[test]
    fn arbitrary_explicit_recipe_cannot_masquerade_as_cargo() {
        let selector = IntentionalBoundaryBehaviorSelector::CargoTest {
            test_name: "tests::adapter_works".to_string(),
        };

        assert!(
            targeted_command(&selector, &recipe(vec!["cargo", "test", "--release"]))
                .unwrap_err()
                .contains("frozen root Cargo recipe")
        );
    }
}
