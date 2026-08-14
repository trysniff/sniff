use sniff::benchmark::{HistoricalTestRecipeStatus, discover_historical_test_recipe};
use std::fs;
use std::path::Path;

#[test]
fn explicit_sniff_argv_has_first_priority() {
    let (parent, commit) = roots();
    write_both(
        parent.path(),
        commit.path(),
        "sniff.config.toml",
        "[proof]\ntest_command = [\"custom\", \"verify\"]\n",
    );
    write_both(
        parent.path(),
        commit.path(),
        "Cargo.toml",
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    );

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Selected);
    assert_eq!(recipe.command.unwrap(), ["custom", "verify"]);
    assert_eq!(recipe.inputs.len(), 1);
}

#[test]
fn changed_explicit_recipe_fails_without_falling_through() {
    let (parent, commit) = roots();
    fs::write(
        parent.path().join("sniff.config.toml"),
        "[proof]\ntest_command = [\"custom\", \"old\"]\n",
    )
    .unwrap();
    fs::write(
        commit.path().join("sniff.config.toml"),
        "[proof]\ntest_command = [\"custom\", \"new\"]\n",
    )
    .unwrap();
    write_both(parent.path(), commit.path(), "go.mod", "module fixture\n");

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Changed);
    assert!(recipe.command.is_none());
}

#[test]
fn package_recipe_requires_one_unchanged_lockfile() {
    let (parent, commit) = roots();
    write_both(
        parent.path(),
        commit.path(),
        "package.json",
        r#"{"scripts":{"test":"vitest run"}}"#,
    );
    write_both(
        parent.path(),
        commit.path(),
        "pnpm-lock.yaml",
        "lockfileVersion: 9\n",
    );

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Selected);
    assert_eq!(
        recipe.preparation_commands,
        vec![vec![
            "pnpm".to_string(),
            "install".to_string(),
            "--frozen-lockfile".to_string(),
        ]]
    );
    assert_eq!(
        recipe.command,
        Some(vec!["pnpm".to_string(), "test".to_string()])
    );
}

#[test]
fn pytest_recipe_uses_a_fresh_private_environment() {
    let parent = tempfile::tempdir().unwrap();
    let commit = tempfile::tempdir().unwrap();
    for root in [parent.path(), commit.path()] {
        std::fs::write(root.join("pytest.ini"), "[pytest]\n").unwrap();
    }

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Selected);
    assert_eq!(recipe.preparation_commands.len(), 2);
    assert_eq!(
        recipe.preparation_commands[0],
        ["python", "-I", "-m", "venv", "{sniff_private_python_env}"]
    );
    assert_eq!(
        recipe.command,
        Some(vec![
            "{sniff_private_python}".to_string(),
            "-m".to_string(),
            "pytest".to_string(),
        ])
    );
}

#[test]
fn package_recipe_rejects_ambiguous_lockfiles() {
    let (parent, commit) = roots();
    write_both(
        parent.path(),
        commit.path(),
        "package.json",
        r#"{"scripts":{"test":"vitest run"}}"#,
    );
    write_both(parent.path(), commit.path(), "yarn.lock", "fixture\n");
    write_both(parent.path(), commit.path(), "package-lock.json", "{}\n");

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Ambiguous);
}

#[test]
fn cargo_lock_controls_locked_argv() {
    let (parent, commit) = roots();
    write_both(
        parent.path(),
        commit.path(),
        "Cargo.toml",
        "[workspace]\nmembers=[]\n",
    );
    write_both(parent.path(), commit.path(), "Cargo.lock", "version = 4\n");

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(
        recipe.command.unwrap(),
        ["cargo", "test", "--workspace", "--all-targets", "--locked"]
    );
}

#[test]
fn changed_cargo_inputs_keep_the_fixed_unlocked_recipe() {
    let (parent, commit) = roots();
    fs::write(
        parent.path().join("Cargo.toml"),
        "[workspace]\nmembers=[]\n",
    )
    .unwrap();
    fs::write(
        commit.path().join("Cargo.toml"),
        "[workspace]\nmembers=['crate']\n",
    )
    .unwrap();
    fs::write(parent.path().join("Cargo.lock"), "version = 3\n").unwrap();
    fs::write(commit.path().join("Cargo.lock"), "version = 4\n").unwrap();

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Selected);
    assert_eq!(
        recipe.command.unwrap(),
        ["cargo", "test", "--workspace", "--all-targets"]
    );
    assert_eq!(recipe.inputs.len(), 2);
    assert_ne!(
        recipe.inputs[0].parent_sha256,
        recipe.inputs[0].commit_sha256
    );
}

#[test]
fn malformed_explicit_recipe_is_typed_ambiguous() {
    let (parent, commit) = roots();
    write_both(
        parent.path(),
        commit.path(),
        "sniff.config.toml",
        "[proof]\ntest_command = 'cargo test'\n",
    );

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Ambiguous);
}

#[test]
fn changed_go_module_is_not_replaced_by_pytest() {
    let (parent, commit) = roots();
    fs::write(parent.path().join("go.mod"), "module old\n").unwrap();
    fs::write(commit.path().join("go.mod"), "module new\n").unwrap();
    write_both(parent.path(), commit.path(), "pytest.ini", "[pytest]\n");

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Changed);
}

#[test]
fn multiple_pytest_configs_are_ambiguous() {
    let (parent, commit) = roots();
    write_both(parent.path(), commit.path(), "pytest.ini", "[pytest]\n");
    write_both(
        parent.path(),
        commit.path(),
        "pyproject.toml",
        "[tool.pytest.ini_options]\naddopts='-q'\n",
    );

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Ambiguous);
}

#[test]
fn no_matching_recipe_is_typed_unavailable() {
    let (parent, commit) = roots();

    let recipe = discover_historical_test_recipe(parent.path(), commit.path()).unwrap();

    assert_eq!(recipe.status, HistoricalTestRecipeStatus::Unavailable);
    assert!(recipe.inputs.is_empty());
}

fn roots() -> (tempfile::TempDir, tempfile::TempDir) {
    (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
}

fn write_both(parent: &Path, commit: &Path, path: &str, contents: &str) {
    fs::write(parent.join(path), contents).unwrap();
    fs::write(commit.join(path), contents).unwrap();
}
