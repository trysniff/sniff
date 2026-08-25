use super::fs_safety::reject_link_or_reparse;
use super::settings::discover_build_roots;
use ignore::WalkBuilder;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_CONTROL_FILES: usize = 5_000;
const MAX_CONTROL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONTROL_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::semantic_indexer_runner) enum KotlinDependencyPreparationError {
    RepositoryRejected(String),
    InfrastructureFailed(String),
}

impl From<String> for KotlinDependencyPreparationError {
    fn from(detail: String) -> Self {
        Self::InfrastructureFailed(detail)
    }
}

#[derive(Default)]
struct CopyBudget {
    files: usize,
    bytes: u64,
}

pub(super) fn stage_control_plane(
    repository: &Path,
    target: &Path,
) -> Result<(), KotlinDependencyPreparationError> {
    let repository = fs::canonicalize(repository).map_err(|error| {
        format!(
            "failed to resolve Kotlin dependency-preparation source {}: {error}",
            repository.display()
        )
    })?;
    if target.exists() {
        return Err(format!(
            "refusing to reuse Kotlin dependency-preparation root {}",
            target.display()
        )
        .into());
    }
    fs::create_dir_all(target).map_err(|error| {
        format!(
            "failed to create Kotlin dependency-preparation root {}: {error}",
            target.display()
        )
    })?;

    let build_roots = discover_build_roots(&repository)?;
    let mut builder = WalkBuilder::new(&repository);
    builder.standard_filters(true).follow_links(false);
    let filter_root = repository.clone();
    builder.filter_entry(move |entry| {
        entry.path() == filter_root
            || entry
                .path()
                .strip_prefix(&filter_root)
                .is_ok_and(|relative| !contains_excluded_directory(relative))
    });

    let mut budget = CopyBudget::default();
    let mut root_script_found = false;
    let mut project_roots = BTreeSet::new();
    for result in builder.build() {
        let entry = result
            .map_err(|error| format!("failed to inventory the Gradle control plane: {error}"))?;
        let path = entry.path();
        let relative = path.strip_prefix(&repository).map_err(|_| {
            format!(
                "Gradle control-plane path escaped the repository: {}",
                path.display()
            )
        })?;
        if relative.as_os_str().is_empty() || !should_copy(relative, &build_roots) {
            continue;
        }
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!(
                "failed to inspect Gradle control-plane file {}: {error}",
                path.display()
            )
        })?;
        reject_link_or_reparse(path, &metadata)?;
        if !metadata.is_file() {
            return Err(format!(
                "Gradle control-plane entry is not a regular file: {}",
                path.display()
            )
            .into());
        }
        budget.files = budget.files.saturating_add(1);
        budget.bytes = budget.bytes.saturating_add(metadata.len());
        if metadata.len() > MAX_CONTROL_FILE_BYTES
            || budget.files > MAX_CONTROL_FILES
            || budget.bytes > MAX_CONTROL_BYTES
        {
            return Err(format!(
                "Gradle control plane exceeds the strict preparation limit of {MAX_CONTROL_FILES} files, {MAX_CONTROL_BYTES} total bytes, or {MAX_CONTROL_FILE_BYTES} bytes per file"
            )
            .into());
        }

        let bytes = fs::read(path).map_err(|error| {
            format!(
                "failed to read Gradle control-plane file {}: {error}",
                path.display()
            )
        })?;
        let source = std::str::from_utf8(&bytes).map_err(|_| {
            format!(
                "Gradle control-plane file is not UTF-8 and cannot enter the network-enabled preparation sandbox: {}",
                path.display()
            )
        })?;
        if let Some((line, kind)) = crate::source_privacy::first_likely_secret(source) {
            return Err(format!(
                "likely {kind} found in Gradle control-plane file {}:{line}; refusing network-enabled dependency preparation",
                path.display()
            )
            .into());
        }
        let output = target.join(relative);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create staged Gradle directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        if file_name(relative) == Some("gradle.properties") {
            fs::write(&output, sanitize_gradle_properties(source, path)?).map_err(|error| {
                format!(
                    "failed to write sanitized Gradle properties {}: {error}",
                    output.display()
                )
            })?;
        } else {
            fs::write(&output, bytes).map_err(|error| {
                format!(
                    "failed to stage Gradle control-plane file {}: {error}",
                    output.display()
                )
            })?;
        }
        if relative
            .parent()
            .is_none_or(|parent| parent.as_os_str().is_empty())
            && is_primary_gradle_script(relative)
        {
            root_script_found = true;
        }
        if is_project_build_script(relative) {
            project_roots.insert(
                relative
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .map_or_else(PathBuf::new, Path::to_path_buf),
            );
        }
    }

    if !root_script_found {
        return Err(KotlinDependencyPreparationError::RepositoryRejected(
            "Kotlin dependency preparation requires a repository-root settings.gradle(.kts) or build.gradle(.kts) file"
                .to_string(),
        ));
    }
    if project_roots.is_empty() {
        return Err(KotlinDependencyPreparationError::RepositoryRejected(
            "Kotlin dependency preparation found no build.gradle(.kts) project to compile"
                .to_string(),
        ));
    }
    write_compiler_probes(target, &project_roots)?;
    Ok(())
}

fn write_compiler_probes(target: &Path, project_roots: &BTreeSet<PathBuf>) -> Result<(), String> {
    for (ordinal, project_root) in project_roots.iter().enumerate() {
        let java_directory = target.join(project_root).join("src/main/java");
        let kotlin_directory = target.join(project_root).join("src/main/kotlin");
        for directory in [&java_directory, &kotlin_directory] {
            fs::create_dir_all(directory).map_err(|error| {
                format!(
                    "failed to create synthetic compiler-probe directory {}: {error}",
                    directory.display()
                )
            })?;
        }
        let java_name = format!("SniffDependencyJavaProbe{ordinal}");
        let kotlin_name = format!("SniffDependencyKotlinProbe{ordinal}");
        fs::write(
            java_directory.join(format!("{java_name}.java")),
            format!("final class {java_name} {{}}\n"),
        )
        .map_err(|error| {
            format!(
                "failed to write synthetic Java compiler probe for {}: {error}",
                target.join(project_root).display()
            )
        })?;
        fs::write(
            kotlin_directory.join(format!("{kotlin_name}.kt")),
            format!("internal class {kotlin_name}\n"),
        )
        .map_err(|error| {
            format!(
                "failed to write synthetic Kotlin compiler probe for {}: {error}",
                target.join(project_root).display()
            )
        })?;
    }
    Ok(())
}

fn should_copy(relative: &Path, build_roots: &BTreeSet<PathBuf>) -> bool {
    if is_primary_gradle_script(relative) || file_name(relative) == Some("gradle.properties") {
        return true;
    }
    if relative
        .components()
        .any(|component| component.as_os_str() == "gradle")
        && has_control_extension(relative)
    {
        return true;
    }
    build_roots.iter().any(|build_root| {
        let build_src = build_root.join("buildSrc");
        (!build_src.as_os_str().is_empty() && relative.starts_with(&build_src))
            || (!build_root.as_os_str().is_empty() && relative.starts_with(build_root))
    }) && has_build_logic_extension(relative)
}

fn is_primary_gradle_script(path: &Path) -> bool {
    matches!(
        file_name(path),
        Some("settings.gradle" | "settings.gradle.kts" | "build.gradle" | "build.gradle.kts")
    )
}

fn is_project_build_script(path: &Path) -> bool {
    matches!(file_name(path), Some("build.gradle" | "build.gradle.kts"))
}

fn has_control_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("gradle" | "kts" | "toml" | "properties")
    )
}

fn has_build_logic_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some(
            "gradle"
                | "kts"
                | "kt"
                | "java"
                | "groovy"
                | "toml"
                | "properties"
                | "xml"
                | "json"
                | "yml"
                | "yaml"
        )
    )
}

fn contains_excluded_directory(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(
                ".git"
                    | ".gradle"
                    | ".idea"
                    | ".kotlin"
                    | ".sniff-indexer-cache"
                    | ".sniff-indexer-tmp"
                    | "build"
                    | "node_modules"
                    | "out"
                    | "target"
            )
        )
    })
}

fn sanitize_gradle_properties(source: &str, path: &Path) -> Result<String, String> {
    let mut sanitized = String::new();
    for (line_index, line) in source.lines().enumerate() {
        if line.trim_end().ends_with('\\') {
            return Err(format!(
                "multiline Gradle property in {}:{} cannot be sanitized safely",
                path.display(),
                line_index + 1
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            sanitized.push_str(line);
            sanitized.push('\n');
            continue;
        }
        let separator = trimmed
            .find(|character: char| {
                character == '=' || character == ':' || character.is_whitespace()
            })
            .unwrap_or(trimmed.len());
        let key = trimmed[..separator].to_ascii_lowercase();
        if [
            "password",
            "secret",
            "token",
            "credential",
            "apikey",
            "api_key",
            "privatekey",
            "private_key",
            "accesskey",
            "access_key",
        ]
        .iter()
        .any(|marker| key.contains(marker))
        {
            continue;
        }
        sanitized.push_str(line);
        sanitized.push('\n');
    }
    Ok(sanitized)
}

fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|value| value.to_str())
}
