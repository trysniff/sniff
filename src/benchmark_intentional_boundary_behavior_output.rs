use super::IntentionalBoundaryBehaviorSelector;
use serde_json::Value;

#[derive(Default, PartialEq, Eq)]
pub(super) struct TestCount {
    pub executed: usize,
    pub matched: usize,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
