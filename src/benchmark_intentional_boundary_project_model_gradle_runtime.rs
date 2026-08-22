use super::super::IntentionalBoundaryProjectModelFailurePhase;
use super::super::intentional_boundary_project_model::hash_json;
use super::super::intentional_boundary_project_model_outcome::{
    ProjectModelDerivationError, ProjectModelDerivationErrorKind, legacy_project_model_error,
    project_model_error, project_model_process_error, project_model_runtime_plan_error,
    project_model_sandbox_error,
};
use super::super::intentional_boundary_runtime_snapshot::{
    IntentionalBoundaryRuntimeSnapshot, allocate_runtime_directory,
};
use super::super::non_blind_history_runtime::prepare_historical_runtime;
use super::*;
use crate::benchmark::release::BoundaryGitEntryKind;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const GRADLE_TOOLING_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const GRADLE_TOOLING_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
const GRADLE_MACOS_JAVA_TOOL_OPTIONS: &str = "-Djava.net.preferIPv4Stack=true";
const GRADLE_CLIENT_SOURCE: &str =
    include_str!("../assets/gradle-tooling/sniff-project-model-client.groovy");
const GRADLE_INIT_SOURCE: &str =
    include_str!("../assets/gradle-tooling/sniff-project-model.init.gradle");

struct GradleToolingCallRuntime(PathBuf);

impl GradleToolingCallRuntime {
    fn create(root: &Path) -> Result<Self, String> {
        allocate_runtime_directory(root, ".sniff-gradle-tooling-call").map(Self)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for GradleToolingCallRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) struct GradleToolingExecutionOutput {
    pub(super) toolchain_identity_sha256: String,
    pub(super) stdout: String,
}

pub fn census_intentional_boundary_gradle_project_models(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    census_intentional_boundary_gradle_project_models_typed(repository, revision, root, inventory)
        .map_err(legacy_project_model_error)
}

pub(in crate::benchmark::release) fn census_intentional_boundary_gradle_project_models_typed(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError> {
    super::super::validate_intentional_boundary_repository_inventory(
        repository, revision, root, inventory,
    )
    .map_err(|detail| {
        gradle_error(
            ProjectModelDerivationErrorKind::InvalidInput,
            IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
            None,
            detail,
        )
    })?;
    let snapshot =
        IntentionalBoundaryRuntimeSnapshot::create(root, revision, "sniff-gradle-tooling-snapshot")
            .map_err(|detail| {
                gradle_error(
                    ProjectModelDerivationErrorKind::InfrastructureFailed,
                    IntentionalBoundaryProjectModelFailurePhase::SnapshotPreparation,
                    None,
                    detail,
                )
            })?;
    census_gradle_project_models_at_execution_root(
        repository,
        revision,
        root,
        snapshot.path(),
        inventory,
        run_gradle_tooling_model,
    )
}

#[cfg(test)]
pub(super) fn census_gradle_project_models_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, String>
where
    F: FnMut(&Path, &str) -> Result<GradleToolingExecutionOutput, String>,
{
    let mut executor = executor;
    census_gradle_project_models_at_execution_root(
        repository,
        revision,
        root,
        root,
        inventory,
        |execution_root, settings_path| {
            executor(execution_root, settings_path).map_err(|detail| {
                gradle_error(
                    ProjectModelDerivationErrorKind::InfrastructureFailed,
                    IntentionalBoundaryProjectModelFailurePhase::Execution,
                    Some(settings_path),
                    detail,
                )
            })
        },
    )
    .map_err(legacy_project_model_error)
}

fn census_gradle_project_models_at_execution_root<F>(
    repository: &str,
    revision: &str,
    immutable_root: &Path,
    execution_root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    mut executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError>
where
    F: FnMut(&Path, &str) -> Result<GradleToolingExecutionOutput, ProjectModelDerivationError>,
{
    super::super::validate_intentional_boundary_repository_inventory(
        repository,
        revision,
        immutable_root,
        inventory,
    )
    .map_err(|detail| {
        gradle_error(
            ProjectModelDerivationErrorKind::InvalidInput,
            IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
            None,
            detail,
        )
    })?;
    let settings_files = inventory
        .tracked_entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.repository_path.rsplit('/').next(),
                Some("settings.gradle" | "settings.gradle.kts")
            )
        })
        .map(|entry| {
            if entry.kind != BoundaryGitEntryKind::RegularBlob {
                return Err(gradle_error(
                    ProjectModelDerivationErrorKind::UnsupportedProjectShape,
                    IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                    Some(&entry.repository_path),
                    format!(
                        "Gradle settings file is not a regular Git blob: {}",
                        entry.repository_path
                    ),
                ));
            }
            Ok(entry.repository_path.clone())
        })
        .collect::<Result<Vec<_>, ProjectModelDerivationError>>()?;
    let mut executions = Vec::with_capacity(settings_files.len());
    let mut targets = Vec::new();
    let mut source_owners = std::collections::BTreeMap::<String, String>::new();
    for settings_path in &settings_files {
        let output = executor(execution_root, settings_path);
        if let Err(error) = super::super::validate_intentional_boundary_repository_inventory(
            repository,
            revision,
            immutable_root,
            inventory,
        ) {
            return Err(gradle_error(
                ProjectModelDerivationErrorKind::InfrastructureFailed,
                IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
                Some(settings_path),
                format!("Gradle Tooling API changed the immutable repository: {error}"),
            ));
        }
        let output = output?;
        let contribution = parse_intentional_boundary_gradle_tooling_model(
            execution_root,
            inventory,
            settings_path,
            &output.toolchain_identity_sha256,
            output.stdout.as_bytes(),
        )
        .map_err(|detail| {
            gradle_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(settings_path),
                detail,
            )
        })?;
        let [execution] = contribution.executions.as_slice() else {
            return Err(gradle_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
                Some(settings_path),
                "Gradle project-model contribution changed cardinality",
            ));
        };
        if !execution
            .covered_manifest_repository_paths
            .contains(settings_path)
        {
            return Err(gradle_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(settings_path),
                "Gradle Tooling API omitted its invocation settings file",
            ));
        }
        for target in &contribution.targets {
            for source in &target.source_repository_paths {
                if let Some(owner) = source_owners.insert(source.clone(), settings_path.clone())
                    && owner != *settings_path
                {
                    return Err(gradle_error(
                        ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                        IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                        Some(settings_path),
                        format!("Gradle Tooling API assigned source {source} to multiple builds"),
                    ));
                }
            }
        }
        executions.extend(contribution.executions);
        targets.extend(contribution.targets);
    }
    super::super::validate_intentional_boundary_repository_inventory(
        repository,
        revision,
        immutable_root,
        inventory,
    )
    .map_err(|detail| {
        gradle_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
            None,
            detail,
        )
    })?;
    finish_project_model_census(inventory, executions, targets).map_err(|detail| {
        gradle_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
            None,
            detail,
        )
    })
}

fn run_gradle_tooling_model(
    root: &Path,
    settings_repository_path: &str,
) -> Result<GradleToolingExecutionOutput, ProjectModelDerivationError> {
    let runtime = GradleToolingCallRuntime::create(root).map_err(|detail| {
        gradle_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(settings_repository_path),
            detail,
        )
    })?;
    let cache = runtime.path().join("cache");
    let gradle_home = cache.join("gradle-user-home");
    fs::create_dir_all(&gradle_home).map_err(|error| {
        gradle_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(settings_repository_path),
            format!("failed to create private Gradle Tooling API cache: {error}"),
        )
    })?;
    let client = cache.join("sniff-project-model-client.groovy");
    let init = cache.join("sniff-project-model.init.gradle");
    fs::write(&client, GRADLE_CLIENT_SOURCE).map_err(|error| {
        gradle_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(settings_repository_path),
            format!("failed to write trusted Gradle Tooling API client: {error}"),
        )
    })?;
    fs::write(&init, GRADLE_INIT_SOURCE).map_err(|error| {
        gradle_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(settings_repository_path),
            format!("failed to write trusted Gradle model builder: {error}"),
        )
    })?;
    let project_directory = settings_repository_path
        .rsplit_once('/')
        .map_or(".", |(directory, _)| directory);
    let relative = |path: &Path| -> Result<String, ProjectModelDerivationError> {
        path.strip_prefix(root)
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|_| {
                gradle_error(
                    ProjectModelDerivationErrorKind::InfrastructureFailed,
                    IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
                    Some(settings_repository_path),
                    "Gradle Tooling API runtime path escaped its snapshot",
                )
            })
    };
    let logical_command = vec![
        "{sniff_gradle_tooling}".to_string(),
        relative(&client)?,
        project_directory.to_string(),
        relative(&gradle_home)?,
        relative(&init)?,
    ];
    let mut plan = prepare_historical_runtime(root, &cache, &logical_command).map_err(|error| {
        project_model_runtime_plan_error(
            Provider::GradleToolingApi,
            settings_repository_path,
            "Gradle Tooling API runtime",
            error,
        )
    })?;
    plan.command.allow_network = false;
    #[cfg(target_os = "macos")]
    {
        // Gradle's daemon and cache lock coordinator require loopback IPC.
        plan.command.allow_local_network = true;
        // Java's dual-stack socket path is denied by Seatbelt even when the
        // equivalent IPv4 child-process connection is admitted.
        plan.command.env.push((
            "JAVA_TOOL_OPTIONS".to_string(),
            GRADLE_MACOS_JAVA_TOOL_OPTIONS.to_string(),
        ));
    }
    plan.command.timeout = GRADLE_TOOLING_TIMEOUT;
    plan.command.output_limit = GRADLE_TOOLING_OUTPUT_LIMIT;
    let toolchain_identity_sha256 = hash_json(&(
        "sniffbench-gradle-tooling-runtime-v4",
        &plan.runtime_identity,
        GRADLE_MACOS_JAVA_TOOL_OPTIONS,
        GRADLE_CLIENT_SOURCE,
        GRADLE_INIT_SOURCE,
    ))
    .map_err(|detail| {
        gradle_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(settings_repository_path),
            detail,
        )
    })?;
    let output = crate::sandbox::run(&plan.command).map_err(|error| {
        project_model_sandbox_error(
            Provider::GradleToolingApi,
            settings_repository_path,
            "sandboxed Gradle Tooling API failed",
            error,
        )
    })?;
    if output.timed_out {
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            Provider::GradleToolingApi,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            settings_repository_path,
            "sandboxed Gradle Tooling API timed out",
            output,
        ));
    }
    if output.status_code != Some(0) {
        let stderr = output.stderr.trim();
        let stdout = output.stdout.trim();
        let diagnostics = if !stderr.is_empty() {
            diagnostic_tail(stderr)
        } else if !stdout.is_empty() {
            diagnostic_tail(stdout)
        } else {
            String::new()
        };
        let detail = format!(
            "sandboxed Gradle Tooling API exited with status {}{}",
            output
                .status_code
                .map_or_else(|| "unknown".to_string(), |status| status.to_string()),
            if diagnostics.is_empty() {
                String::new()
            } else {
                format!(": {diagnostics}")
            }
        );
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::ProviderRejectedRepository,
            Provider::GradleToolingApi,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            settings_repository_path,
            detail,
            output,
        ));
    }
    Ok(GradleToolingExecutionOutput {
        toolchain_identity_sha256,
        stdout: output.stdout,
    })
}

fn diagnostic_tail(value: &str) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
    if value.len() <= MAX_DIAGNOSTIC_BYTES {
        return value.to_string();
    }
    let start = value
        .char_indices()
        .find_map(|(index, _)| (value.len() - index <= MAX_DIAGNOSTIC_BYTES).then_some(index))
        .unwrap_or(0);
    format!("[truncated] {}", &value[start..])
}

fn gradle_error(
    kind: ProjectModelDerivationErrorKind,
    phase: IntentionalBoundaryProjectModelFailurePhase,
    invocation_anchor_repository_path: Option<&str>,
    detail: impl Into<String>,
) -> ProjectModelDerivationError {
    project_model_error(
        kind,
        Provider::GradleToolingApi,
        phase,
        invocation_anchor_repository_path,
        detail,
    )
}
