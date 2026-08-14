use super::{HistoricalTestRecipeDiscovery, HistoricalTestRecipeInput, HistoricalTestRecipeStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_RECIPE_INPUT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
enum PairState {
    Absent,
    Same(Vec<u8>),
    Changed {
        parent: Option<Vec<u8>>,
        commit: Option<Vec<u8>>,
    },
}

#[derive(Debug)]
struct RecipeMatch {
    preparation_commands: Vec<Vec<String>>,
    command: Vec<String>,
    inputs: Vec<HistoricalTestRecipeInput>,
}

pub fn discover_historical_test_recipe(
    parent_root: &Path,
    commit_root: &Path,
) -> Result<HistoricalTestRecipeDiscovery, String> {
    for selector in [
        explicit_sniff_recipe,
        package_recipe,
        cargo_recipe,
        go_recipe,
        pytest_recipe,
        gradle_recipe,
    ] {
        match selector(parent_root, commit_root)? {
            Selection::NoMatch => {}
            Selection::Changed(reason) => {
                return Ok(rejected(HistoricalTestRecipeStatus::Changed, reason));
            }
            Selection::Ambiguous(reason) => {
                return Ok(rejected(HistoricalTestRecipeStatus::Ambiguous, reason));
            }
            Selection::Match(recipe) => {
                let runtime_program = recipe.command.first().cloned();
                return Ok(HistoricalTestRecipeDiscovery {
                    status: HistoricalTestRecipeStatus::Selected,
                    preparation_commands: recipe.preparation_commands,
                    command: Some(recipe.command),
                    runtime_program,
                    inputs: recipe.inputs,
                    reason: "selected the first exact recipe in frozen protocol order".to_string(),
                });
            }
        }
    }
    Ok(rejected(
        HistoricalTestRecipeStatus::Unavailable,
        "no frozen root test recipe matched both revisions",
    ))
}

enum Selection {
    NoMatch,
    Match(RecipeMatch),
    Changed(String),
    Ambiguous(String),
}

fn explicit_sniff_recipe(parent: &Path, commit: &Path) -> Result<Selection, String> {
    match paired_file(parent, commit, "sniff.config.toml")? {
        PairState::Absent => Ok(Selection::NoMatch),
        PairState::Changed {
            parent: parent_bytes,
            commit: commit_bytes,
        } => {
            let parent_command = match proof_command_bytes(parent_bytes.as_deref()) {
                Ok(command) => command,
                Err(reason) => return Ok(Selection::Ambiguous(reason)),
            };
            let commit_command = match proof_command_bytes(commit_bytes.as_deref()) {
                Ok(command) => command,
                Err(reason) => return Ok(Selection::Ambiguous(reason)),
            };
            if parent_command.is_some() || commit_command.is_some() {
                Ok(Selection::Changed(
                    "root sniff.config.toml proof.test_command changed between revisions"
                        .to_string(),
                ))
            } else {
                Ok(Selection::NoMatch)
            }
        }
        PairState::Same(bytes) => {
            let Some(command) = (match proof_command_bytes(Some(&bytes)) {
                Ok(command) => command,
                Err(reason) => return Ok(Selection::Ambiguous(reason)),
            }) else {
                return Ok(Selection::NoMatch);
            };
            Ok(Selection::Match(RecipeMatch {
                preparation_commands: Vec::new(),
                command,
                inputs: vec![recipe_input("sniff.config.toml", &bytes)],
            }))
        }
    }
}

fn package_recipe(parent: &Path, commit: &Path) -> Result<Selection, String> {
    let package = paired_file(parent, commit, "package.json")?;
    let (parent_package, commit_package) = pair_bytes(&package);
    let parent_has_test = match package_test_bytes(parent_package) {
        Ok(test) => test.is_some(),
        Err(reason) => return Ok(Selection::Ambiguous(reason)),
    };
    let commit_has_test = match package_test_bytes(commit_package) {
        Ok(test) => test.is_some(),
        Err(reason) => return Ok(Selection::Ambiguous(reason)),
    };
    if !parent_has_test && !commit_has_test {
        return Ok(Selection::NoMatch);
    }
    let PairState::Same(package_bytes) = package else {
        return Ok(Selection::Changed(
            "root package.json test recipe changed between revisions".to_string(),
        ));
    };
    let lockfiles = [
        ("package-lock.json", "npm"),
        ("npm-shrinkwrap.json", "npm"),
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("bun.lock", "bun"),
        ("bun.lockb", "bun"),
    ];
    let mut matches = Vec::new();
    let mut changed = false;
    for (path, manager) in lockfiles {
        match paired_file(parent, commit, path)? {
            PairState::Absent => {}
            PairState::Changed { .. } => changed = true,
            PairState::Same(bytes) => matches.push((path, manager, bytes)),
        }
    }
    if changed {
        return Ok(Selection::Changed(
            "root package-manager lockfile changed between revisions".to_string(),
        ));
    }
    if matches.len() != 1 {
        return Ok(Selection::Ambiguous(
            "package.json test recipe requires exactly one unchanged root lockfile".to_string(),
        ));
    }
    let (lock_path, manager, lock_bytes) = matches.remove(0);
    let (preparation, command) = match manager {
        "npm" => (
            vec![vec!["npm".to_string(), "ci".to_string()]],
            vec!["npm".to_string(), "test".to_string()],
        ),
        "pnpm" => (
            vec![vec![
                "pnpm".to_string(),
                "install".to_string(),
                "--frozen-lockfile".to_string(),
            ]],
            vec!["pnpm".to_string(), "test".to_string()],
        ),
        "yarn" => {
            let lock = utf8(&lock_bytes, "yarn.lock")?;
            let frozen_flag = if lock.lines().any(|line| line.trim() == "# yarn lockfile v1") {
                "--frozen-lockfile"
            } else if lock.lines().any(|line| line.trim() == "__metadata:") {
                "--immutable"
            } else {
                return Ok(Selection::Ambiguous(
                    "root yarn.lock does not identify a supported immutable install contract"
                        .to_string(),
                ));
            };
            (
                vec![vec![
                    "yarn".to_string(),
                    "install".to_string(),
                    frozen_flag.to_string(),
                ]],
                vec!["yarn".to_string(), "test".to_string()],
            )
        }
        "bun" => (
            vec![vec![
                "bun".to_string(),
                "install".to_string(),
                "--frozen-lockfile".to_string(),
            ]],
            vec!["bun".to_string(), "run".to_string(), "test".to_string()],
        ),
        _ => unreachable!("package manager comes from the frozen lockfile table"),
    };
    Ok(Selection::Match(RecipeMatch {
        preparation_commands: preparation,
        command,
        inputs: vec![
            recipe_input("package.json", &package_bytes),
            recipe_input(lock_path, &lock_bytes),
        ],
    }))
}

fn cargo_recipe(parent: &Path, commit: &Path) -> Result<Selection, String> {
    let manifest = paired_file(parent, commit, "Cargo.toml")?;
    let (parent_manifest, commit_manifest) = pair_bytes(&manifest);
    if parent_manifest.is_none() && commit_manifest.is_none() {
        return Ok(Selection::NoMatch);
    }
    let (Some(parent_manifest), Some(commit_manifest)) = (parent_manifest, commit_manifest) else {
        return Ok(Selection::Changed(
            "root Cargo.toml is missing from one revision".to_string(),
        ));
    };
    let mut command = vec![
        "cargo".to_string(),
        "test".to_string(),
        "--workspace".to_string(),
        "--all-targets".to_string(),
    ];
    let mut inputs = vec![paired_recipe_input(
        "Cargo.toml",
        Some(parent_manifest),
        Some(commit_manifest),
    )];
    match paired_file(parent, commit, "Cargo.lock")? {
        PairState::Absent => {}
        PairState::Changed { parent, commit } => {
            inputs.push(paired_recipe_input(
                "Cargo.lock",
                parent.as_deref(),
                commit.as_deref(),
            ));
        }
        PairState::Same(bytes) => {
            command.push("--locked".to_string());
            inputs.push(recipe_input("Cargo.lock", &bytes));
        }
    }
    Ok(Selection::Match(RecipeMatch {
        preparation_commands: Vec::new(),
        command,
        inputs,
    }))
}

fn go_recipe(parent: &Path, commit: &Path) -> Result<Selection, String> {
    match paired_file(parent, commit, "go.mod")? {
        PairState::Absent => Ok(Selection::NoMatch),
        PairState::Changed { .. } => Ok(Selection::Changed(
            "root go.mod changed between revisions".to_string(),
        )),
        PairState::Same(bytes) => Ok(Selection::Match(RecipeMatch {
            preparation_commands: Vec::new(),
            command: vec!["go".to_string(), "test".to_string(), "./...".to_string()],
            inputs: vec![recipe_input("go.mod", &bytes)],
        })),
    }
}

fn pytest_recipe(parent: &Path, commit: &Path) -> Result<Selection, String> {
    let candidates = ["pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg"];
    let mut matches = Vec::new();
    let mut changed = false;
    for path in candidates {
        let state = paired_file(parent, commit, path)?;
        let (parent_bytes, commit_bytes) = pair_bytes(&state);
        let parent_matches = match is_pytest_config_bytes(path, parent_bytes) {
            Ok(value) => value,
            Err(reason) => return Ok(Selection::Ambiguous(reason)),
        };
        let commit_matches = match is_pytest_config_bytes(path, commit_bytes) {
            Ok(value) => value,
            Err(reason) => return Ok(Selection::Ambiguous(reason)),
        };
        if !parent_matches && !commit_matches {
            continue;
        }
        match state {
            PairState::Same(bytes) if parent_matches && commit_matches => {
                matches.push((path, bytes));
            }
            _ => changed = true,
        }
    }
    if changed {
        return Ok(Selection::Changed(
            "root pytest recipe configuration changed between revisions".to_string(),
        ));
    }
    if matches.len() > 1 {
        return Ok(Selection::Ambiguous(
            "more than one unchanged root pytest recipe matched".to_string(),
        ));
    }
    let Some((path, bytes)) = matches.pop() else {
        return Ok(Selection::NoMatch);
    };
    Ok(Selection::Match(RecipeMatch {
        preparation_commands: vec![
            vec![
                "python".to_string(),
                "-I".to_string(),
                "-m".to_string(),
                "venv".to_string(),
                "{sniff_private_python_env}".to_string(),
            ],
            vec![
                "{sniff_private_python}".to_string(),
                "-m".to_string(),
                "pip".to_string(),
                "install".to_string(),
                "--disable-pip-version-check".to_string(),
                ".".to_string(),
                "pytest".to_string(),
            ],
        ],
        command: vec![
            "{sniff_private_python}".to_string(),
            "-m".to_string(),
            "pytest".to_string(),
        ],
        inputs: vec![recipe_input(path, &bytes)],
    }))
}

fn gradle_recipe(parent: &Path, commit: &Path) -> Result<Selection, String> {
    let wrapper_path = if cfg!(windows) {
        "gradlew.bat"
    } else {
        "gradlew"
    };
    let wrapper = paired_file(parent, commit, wrapper_path)?;
    let indicators = [
        "settings.gradle.kts",
        "settings.gradle",
        "build.gradle.kts",
        "build.gradle",
    ];
    let mut project_inputs = Vec::new();
    let mut changed = false;
    for path in indicators {
        match paired_file(parent, commit, path)? {
            PairState::Absent => {}
            PairState::Changed { .. } => changed = true,
            PairState::Same(bytes) => project_inputs.push((path, bytes)),
        }
    }
    if matches!(wrapper, PairState::Absent) && project_inputs.is_empty() && !changed {
        return Ok(Selection::NoMatch);
    }
    let PairState::Same(wrapper_bytes) = wrapper else {
        return Ok(Selection::Changed(
            "platform Gradle wrapper changed or is missing from one revision".to_string(),
        ));
    };
    if changed {
        return Ok(Selection::Changed(
            "root Gradle project recipe changed between revisions".to_string(),
        ));
    }
    if project_inputs.is_empty() {
        return Ok(Selection::NoMatch);
    }
    let mut inputs = vec![recipe_input(wrapper_path, &wrapper_bytes)];
    inputs.extend(
        project_inputs
            .iter()
            .map(|(path, bytes)| recipe_input(path, bytes)),
    );
    let program = if cfg!(windows) {
        "gradlew.bat".to_string()
    } else {
        "./gradlew".to_string()
    };
    Ok(Selection::Match(RecipeMatch {
        preparation_commands: Vec::new(),
        command: vec![program, "test".to_string(), "--no-daemon".to_string()],
        inputs,
    }))
}

fn proof_command_bytes(bytes: Option<&[u8]>) -> Result<Option<Vec<String>>, String> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let value = toml::from_str::<toml::Value>(utf8(bytes, "sniff.config.toml")?)
        .map_err(|error| format!("invalid root sniff.config.toml: {error}"))?;
    proof_argv(&value)
}

fn proof_argv(value: &toml::Value) -> Result<Option<Vec<String>>, String> {
    let Some(command) = value
        .get("proof")
        .and_then(|proof| proof.get("test_command"))
    else {
        return Ok(None);
    };
    let values = command.as_array().ok_or_else(|| {
        "root sniff.config.toml proof.test_command must be an argv array".to_string()
    })?;
    if values.is_empty() {
        return Err("root sniff.config.toml proof.test_command cannot be empty".to_string());
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .filter(|argument| !argument.is_empty() && !argument.contains('\0'))
                .map(str::to_string)
                .ok_or_else(|| {
                    format!("root proof.test_command argument {index} is not safe argv text")
                })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn package_test_bytes(bytes: Option<&[u8]>) -> Result<Option<String>, String> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid root package.json: {error}"))?;
    Ok(value
        .get("scripts")
        .and_then(|scripts| scripts.get("test"))
        .and_then(serde_json::Value::as_str)
        .filter(|script| !script.trim().is_empty())
        .map(str::to_string))
}

fn is_pytest_config_bytes(path: &str, bytes: Option<&[u8]>) -> Result<bool, String> {
    let Some(bytes) = bytes else {
        return Ok(false);
    };
    let text = utf8(bytes, path)?;
    match path {
        "pytest.ini" => Ok(true),
        "pyproject.toml" => {
            let value = toml::from_str::<toml::Value>(text)
                .map_err(|error| format!("invalid root pyproject.toml: {error}"))?;
            Ok(value
                .get("tool")
                .and_then(|tool| tool.get("pytest"))
                .and_then(|pytest| pytest.get("ini_options"))
                .is_some())
        }
        "tox.ini" => Ok(ini_section(text, "testenv")
            .is_some_and(|section| section.lines().any(|line| line.contains("pytest")))),
        "setup.cfg" => Ok(ini_section(text, "tool:pytest").is_some()),
        _ => Ok(false),
    }
}

fn ini_section<'a>(text: &'a str, section: &str) -> Option<&'a str> {
    let marker = format!("[{section}]");
    let start = text.find(&marker)? + marker.len();
    let tail = &text[start..];
    let end = tail
        .lines()
        .scan(0_usize, |offset, line| {
            let current = *offset;
            *offset += line.len() + 1;
            Some((current, line))
        })
        .find_map(|(offset, line)| line.trim_start().starts_with('[').then_some(offset))
        .unwrap_or(tail.len());
    Some(&tail[..end])
}

fn paired_file(parent: &Path, commit: &Path, path: &str) -> Result<PairState, String> {
    let parent = regular_file(parent.join(path), path)?;
    let commit = regular_file(commit.join(path), path)?;
    Ok(match (parent, commit) {
        (None, None) => PairState::Absent,
        (Some(parent), Some(commit)) if parent == commit => PairState::Same(parent),
        (parent, commit) => PairState::Changed { parent, commit },
    })
}

fn regular_file(path: PathBuf, label: &str) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => read_regular(&path, label).map(Some),
        Ok(_) => Err(format!("root recipe input {label} is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "failed to inspect root recipe input {label}: {error}"
        )),
    }
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let length = fs::metadata(path)
        .map_err(|error| format!("failed to inspect root recipe input {label}: {error}"))?
        .len();
    if length > MAX_RECIPE_INPUT_BYTES {
        return Err(format!(
            "root recipe input {label} exceeds the {MAX_RECIPE_INPUT_BYTES}-byte limit"
        ));
    }
    fs::read(path).map_err(|error| format!("failed to read root recipe input {label}: {error}"))
}

fn recipe_input(path: &str, bytes: &[u8]) -> HistoricalTestRecipeInput {
    paired_recipe_input(path, Some(bytes), Some(bytes))
}

fn paired_recipe_input(
    path: &str,
    parent: Option<&[u8]>,
    commit: Option<&[u8]>,
) -> HistoricalTestRecipeInput {
    HistoricalTestRecipeInput {
        path: path.to_string(),
        parent_sha256: parent.map(sha256),
        commit_sha256: commit.map(sha256),
    }
}

fn pair_bytes(state: &PairState) -> (Option<&[u8]>, Option<&[u8]>) {
    match state {
        PairState::Absent => (None, None),
        PairState::Same(bytes) => (Some(bytes), Some(bytes)),
        PairState::Changed { parent, commit } => (parent.as_deref(), commit.as_deref()),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn rejected(
    status: HistoricalTestRecipeStatus,
    reason: impl Into<String>,
) -> HistoricalTestRecipeDiscovery {
    HistoricalTestRecipeDiscovery {
        status,
        preparation_commands: Vec::new(),
        command: None,
        runtime_program: None,
        inputs: Vec::new(),
        reason: reason.into(),
    }
}

fn utf8<'a>(bytes: &'a [u8], path: &str) -> Result<&'a str, String> {
    std::str::from_utf8(bytes).map_err(|_| format!("root recipe input {path} is not UTF-8"))
}
