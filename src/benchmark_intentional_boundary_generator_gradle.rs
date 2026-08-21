use super::{GeneratorCommand, hash_json};
use crate::benchmark::release::{
    BoundaryGitEntryKind, IntentionalBoundaryGeneratorUnresolvedReason,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelProducerTask,
    IntentionalBoundaryProjectModelProvider, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryRepositoryInventory,
};
use std::collections::BTreeMap;

const GRADLE_JAVA_TOOL_OPTIONS: &str = "-Djava.net.preferIPv4Stack=true";

pub(super) enum GradleGeneratorCommandPlan {
    Planned(GeneratorCommand),
    Unresolved {
        reason: IntentionalBoundaryGeneratorUnresolvedReason,
        detail: String,
    },
}

pub(super) fn configuration_id(
    target: &IntentionalBoundaryProjectModelTarget,
    task: &IntentionalBoundaryProjectModelProducerTask,
) -> Result<String, String> {
    Ok(format!(
        "ibgc-gradle-v1:{}",
        hash_json(&("gradle-project-model-generator-v1", &target.target_id, task))?
    ))
}

pub(super) fn gradle_generator_command_plan(
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &IntentionalBoundaryProjectModelCensus,
    target: &IntentionalBoundaryProjectModelTarget,
    task: &IntentionalBoundaryProjectModelProducerTask,
) -> GradleGeneratorCommandPlan {
    if target.provider != IntentionalBoundaryProjectModelProvider::GradleToolingApi
        || target.producer_tasks.binary_search(task).is_err()
    {
        return unsupported("Gradle producer is not committed by its compiler target");
    }
    let executions = census
        .executions
        .iter()
        .filter(|execution| execution.execution_id == target.execution_id)
        .collect::<Vec<_>>();
    let [execution] = executions.as_slice() else {
        return unresolved(
            IntentionalBoundaryGeneratorUnresolvedReason::AmbiguousConfiguration,
            "Gradle producer has no unique Tooling API execution",
        );
    };
    if execution.provider != IntentionalBoundaryProjectModelProvider::GradleToolingApi {
        return unsupported("Gradle producer execution changed provider");
    }
    let build_directory = manifest_directory(&execution.invocation_anchor_repository_path);
    if !has_regular(
        inventory,
        &scoped(build_directory, "gradle/verification-metadata.xml"),
    ) {
        return unresolved(
            IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration,
            "Gradle generator requires committed dependency verification metadata",
        );
    }
    let project_directory = manifest_directory(&target.manifest_repository_path);
    if !has_gradle_lock_state(inventory, project_directory) {
        return unresolved(
            IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration,
            "Gradle generator requires committed dependency lock state",
        );
    }
    let project = if build_directory.is_empty() {
        "."
    } else {
        build_directory
    };
    let mut common = vec![
        "{sniff_gradle}".to_string(),
        "--project-dir".to_string(),
        project.to_string(),
        "--project-cache-dir".to_string(),
        "{sniff_gradle_project_cache}".to_string(),
        "--no-daemon".to_string(),
        "--no-parallel".to_string(),
        "--max-workers=1".to_string(),
        "--no-build-cache".to_string(),
        "--no-configuration-cache".to_string(),
        "--no-watch-fs".to_string(),
        "--console=plain".to_string(),
        "--rerun-tasks".to_string(),
    ];
    let mut preparation = common.clone();
    preparation.push(task.task_path.clone());
    common.push("--offline".to_string());
    common.push(task.task_path.clone());
    let cleanup_paths = task
        .output_repository_paths
        .iter()
        .filter(|output| {
            !task
                .source_repository_paths
                .iter()
                .any(|source| path_contains(output, source))
        })
        .cloned()
        .collect();
    let environment = BTreeMap::from([(
        "JAVA_TOOL_OPTIONS".to_string(),
        GRADLE_JAVA_TOOL_OPTIONS.to_string(),
    )]);
    GradleGeneratorCommandPlan::Planned(GeneratorCommand {
        preparation: Some(preparation),
        preparation_environment: environment.clone(),
        execution: common,
        execution_environment: environment,
        cleanup_paths,
    })
}

fn has_gradle_lock_state(inventory: &IntentionalBoundaryRepositoryInventory, build: &str) -> bool {
    let root_lock = scoped(build, "gradle.lockfile");
    let legacy_prefix = scoped(build, "gradle/dependency-locks/");
    inventory.tracked_entries.iter().any(|entry| {
        entry.kind == BoundaryGitEntryKind::RegularBlob
            && (entry.repository_path == root_lock
                || (entry.repository_path.starts_with(&legacy_prefix)
                    && entry.repository_path.ends_with(".lockfile")))
    })
}

fn has_regular(inventory: &IntentionalBoundaryRepositoryInventory, path: &str) -> bool {
    inventory.tracked_entries.iter().any(|entry| {
        entry.repository_path == path && entry.kind == BoundaryGitEntryKind::RegularBlob
    })
}

fn manifest_directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

fn scoped(directory: &str, path: &str) -> String {
    if directory.is_empty() {
        path.to_string()
    } else {
        format!("{directory}/{path}")
    }
}

fn path_contains(directory_or_file: &str, source: &str) -> bool {
    source == directory_or_file
        || source
            .strip_prefix(directory_or_file)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn unsupported(detail: impl Into<String>) -> GradleGeneratorCommandPlan {
    unresolved(
        IntentionalBoundaryGeneratorUnresolvedReason::UnsupportedConfiguration,
        detail,
    )
}

fn unresolved(
    reason: IntentionalBoundaryGeneratorUnresolvedReason,
    detail: impl Into<String>,
) -> GradleGeneratorCommandPlan {
    GradleGeneratorCommandPlan::Unresolved {
        reason,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_generator_gradle_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "benchmark_intentional_boundary_generator_gradle_evidence_tests.rs"]
mod evidence_tests;
