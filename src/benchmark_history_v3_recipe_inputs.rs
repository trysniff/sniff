use super::{
    BoundaryGitEntryKind, HistoricalV3Language, HistoricalV3Protocol, HistoricalV3RecipeInputFact,
    HistoricalV3RecipeInputInterpretation, HistoricalV3RecipeInputStatus,
    HistoricalV3TestRecipePolicy, HistoricalV3YarnLockGeneration,
    IntentionalBoundaryInventoryError, IntentionalBoundaryInventoryErrorKind,
    IntentionalBoundaryRepositoryInventory,
};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) fn collect_recipe_input_facts(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    language: HistoricalV3Language,
    protocol: &HistoricalV3Protocol,
) -> Result<Vec<HistoricalV3RecipeInputFact>, IntentionalBoundaryInventoryError> {
    let policy = &protocol.test_recipe_policy;
    let entries = inventory
        .tracked_entries
        .iter()
        .filter(|entry| language_recipe_input_path(language, &entry.repository_path))
        .collect::<Vec<_>>();
    let readable_total = entries
        .iter()
        .filter(|entry| {
            entry.kind.is_file_blob()
                && entry
                    .byte_length
                    .is_some_and(|length| length <= policy.maximum_input_file_bytes)
        })
        .try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.byte_length.unwrap_or(0))
                .ok_or_else(|| invalid("historical-v3 recipe input byte count overflowed"))
        })?;
    let total_exceeded = readable_total > policy.maximum_total_input_bytes;
    let requests = entries
        .iter()
        .filter(|entry| {
            entry.kind.is_file_blob()
                && entry
                    .byte_length
                    .is_some_and(|length| length <= policy.maximum_input_file_bytes)
                && !total_exceeded
        })
        .map(|entry| (entry.object_id.as_str(), entry.byte_length.unwrap_or(0)))
        .collect::<Vec<_>>();
    let mut blobs =
        super::intentional_boundary_inventory::read_intentional_boundary_git_blobs_typed(
            root, &requests,
        )?
        .into_iter();
    let mut facts = Vec::with_capacity(entries.len());
    for entry in entries {
        let input_status = if !entry.kind.is_file_blob() || entry.byte_length.is_none() {
            HistoricalV3RecipeInputStatus::UnsupportedEntryKind
        } else if entry.byte_length.unwrap_or(0) > policy.maximum_input_file_bytes {
            HistoricalV3RecipeInputStatus::FileTooLarge
        } else if total_exceeded {
            HistoricalV3RecipeInputStatus::TotalLimitExceeded
        } else {
            let bytes = blobs
                .next()
                .ok_or_else(|| invalid("historical-v3 recipe input blob is missing"))?;
            classify_content(&entry.repository_path, &bytes)
        };
        facts.push(HistoricalV3RecipeInputFact {
            repository_path: entry.repository_path.clone(),
            mode: entry.mode.clone(),
            entry_kind: entry.kind,
            object_id: entry.object_id.clone(),
            byte_length: entry.byte_length,
            input_status,
        });
    }
    if blobs.next().is_some() {
        return Err(invalid("historical-v3 recipe input blob count changed"));
    }
    Ok(facts)
}

pub(super) fn language_recipe_input_path(language: HistoricalV3Language, path: &str) -> bool {
    match language {
        HistoricalV3Language::JavaScript | HistoricalV3Language::TypeScript => matches!(
            path,
            "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "bun.lock"
                | "bun.lockb"
        ),
        HistoricalV3Language::Rust => matches!(path, "Cargo.toml" | "Cargo.lock"),
        HistoricalV3Language::Go => matches!(path, "go.mod" | "go.sum"),
        HistoricalV3Language::Python => matches!(
            path,
            "pyproject.toml"
                | "pytest.ini"
                | "tox.ini"
                | "setup.cfg"
                | "uv.lock"
                | "poetry.lock"
                | "pdm.lock"
                | "requirements.txt"
                | "requirements-dev.txt"
                | "requirements.lock"
                | "requirements-dev.lock"
        ),
        HistoricalV3Language::Kotlin => gradle_input_path(path),
    }
}

pub(super) fn validate_recipe_input_fact_shape(
    fact: &HistoricalV3RecipeInputFact,
    policy: &HistoricalV3TestRecipePolicy,
) -> Result<(), String> {
    let expected_limit_status = match (fact.entry_kind, fact.byte_length) {
        (
            BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob,
            Some(length),
        ) if length > policy.maximum_input_file_bytes => {
            Some(HistoricalV3RecipeInputStatus::FileTooLarge)
        }
        (BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob, Some(_)) => None,
        _ => Some(HistoricalV3RecipeInputStatus::UnsupportedEntryKind),
    };
    if expected_limit_status
        .as_ref()
        .is_some_and(|expected| expected != &fact.input_status)
    {
        return Err(
            "historical-v3 recipe input status contradicts its inventory entry".to_string(),
        );
    }
    match &fact.input_status {
        HistoricalV3RecipeInputStatus::Committed {
            content_sha256,
            interpretation,
        } => {
            require_sha256(content_sha256)?;
            validate_interpretation(&fact.repository_path, interpretation)?;
        }
        HistoricalV3RecipeInputStatus::InvalidContent { content_sha256 } => {
            require_sha256(content_sha256)?;
        }
        HistoricalV3RecipeInputStatus::FileTooLarge
        | HistoricalV3RecipeInputStatus::TotalLimitExceeded
        | HistoricalV3RecipeInputStatus::UnsupportedEntryKind => {}
    }
    Ok(())
}

fn classify_content(path: &str, bytes: &[u8]) -> HistoricalV3RecipeInputStatus {
    let content_sha256 = format!("{:x}", Sha256::digest(bytes));
    match interpret_content(path, bytes) {
        Some(interpretation) => HistoricalV3RecipeInputStatus::Committed {
            content_sha256,
            interpretation,
        },
        None => HistoricalV3RecipeInputStatus::InvalidContent { content_sha256 },
    }
}

fn interpret_content(path: &str, bytes: &[u8]) -> Option<HistoricalV3RecipeInputInterpretation> {
    match path {
        "package.json" => {
            let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
            Some(HistoricalV3RecipeInputInterpretation::NodePackage {
                has_test_script: value
                    .get("scripts")
                    .and_then(|scripts| scripts.get("test"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|script| !script.trim().is_empty()),
            })
        }
        "yarn.lock" => {
            let text = std::str::from_utf8(bytes).ok()?;
            let generation = if text.lines().any(|line| line.trim() == "# yarn lockfile v1") {
                HistoricalV3YarnLockGeneration::Classic
            } else if text.lines().any(|line| line.trim() == "__metadata:") {
                HistoricalV3YarnLockGeneration::Berry
            } else {
                return None;
            };
            Some(HistoricalV3RecipeInputInterpretation::YarnLock { generation })
        }
        "pyproject.toml" => {
            let text = std::str::from_utf8(bytes).ok()?;
            let value = toml::from_str::<toml::Value>(text).ok()?;
            Some(HistoricalV3RecipeInputInterpretation::PythonProject {
                has_pytest_configuration: value
                    .get("tool")
                    .and_then(|tool| tool.get("pytest"))
                    .and_then(|pytest| pytest.get("ini_options"))
                    .is_some(),
            })
        }
        "requirements.txt"
        | "requirements-dev.txt"
        | "requirements.lock"
        | "requirements-dev.lock" => {
            let text = std::str::from_utf8(bytes).ok()?;
            let requirements = logical_requirements(text)?;
            Some(HistoricalV3RecipeInputInterpretation::PythonRequirements {
                hash_locked: !requirements.is_empty()
                    && requirements
                        .iter()
                        .all(|line| line.contains("--hash=sha256:")),
                contains_pytest: requirements.iter().any(|line| {
                    let normalized = line.trim_start().to_ascii_lowercase();
                    normalized.starts_with("pytest==") || normalized.starts_with("pytest[")
                }),
            })
        }
        "gradle/wrapper/gradle-wrapper.properties" => {
            let text = std::str::from_utf8(bytes).ok()?;
            let distribution_sha256 = text.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("distributionSha256Sum=")
                    .map(str::trim)
                    .filter(|value| {
                        value.len() == 64
                            && value
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                    .map(str::to_string)
            });
            Some(
                HistoricalV3RecipeInputInterpretation::GradleWrapperProperties {
                    distribution_sha256,
                },
            )
        }
        _ => Some(HistoricalV3RecipeInputInterpretation::Opaque),
    }
}

fn logical_requirements(text: &str) -> Option<Vec<String>> {
    let mut requirements = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line == "--require-hashes" {
            continue;
        }
        if line.starts_with('-') && !line.starts_with("--hash=") {
            return None;
        }
        let continued = line.ends_with('\\');
        let part = line.trim_end_matches('\\').trim();
        if !pending.is_empty() {
            pending.push(' ');
        }
        pending.push_str(part);
        if !continued {
            requirements.push(std::mem::take(&mut pending));
        }
    }
    pending.is_empty().then_some(requirements)
}

fn gradle_input_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        path,
        "gradlew"
            | "gradle/wrapper/gradle-wrapper.jar"
            | "gradle/wrapper/gradle-wrapper.properties"
            | "gradle/verification-metadata.xml"
    ) || matches!(
        name,
        "settings.gradle"
            | "settings.gradle.kts"
            | "build.gradle"
            | "build.gradle.kts"
            | "gradle.lockfile"
    ) || (path.contains("/gradle/dependency-locks/") && path.ends_with(".lockfile"))
}

fn validate_interpretation(
    path: &str,
    interpretation: &HistoricalV3RecipeInputInterpretation,
) -> Result<(), String> {
    let valid = match path {
        "package.json" => matches!(
            interpretation,
            HistoricalV3RecipeInputInterpretation::NodePackage { .. }
        ),
        "yarn.lock" => matches!(
            interpretation,
            HistoricalV3RecipeInputInterpretation::YarnLock { .. }
        ),
        "pyproject.toml" => matches!(
            interpretation,
            HistoricalV3RecipeInputInterpretation::PythonProject { .. }
        ),
        "requirements.txt"
        | "requirements-dev.txt"
        | "requirements.lock"
        | "requirements-dev.lock" => matches!(
            interpretation,
            HistoricalV3RecipeInputInterpretation::PythonRequirements { .. }
        ),
        "gradle/wrapper/gradle-wrapper.properties" => matches!(
            interpretation,
            HistoricalV3RecipeInputInterpretation::GradleWrapperProperties { .. }
        ),
        _ => matches!(
            interpretation,
            HistoricalV3RecipeInputInterpretation::Opaque
        ),
    };
    if !valid {
        return Err("historical-v3 recipe input interpretation changed its path kind".to_string());
    }
    Ok(())
}

fn require_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("historical-v3 recipe input hash is invalid".to_string());
    }
    Ok(())
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryInventoryError {
    IntentionalBoundaryInventoryError {
        kind: IntentionalBoundaryInventoryErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
