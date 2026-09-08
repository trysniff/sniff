use super::super::IntentionalBoundaryProjectModelFailurePhase;
use super::super::intentional_boundary_project_model_outcome::{
    ProjectModelDerivationError, ProjectModelDerivationErrorKind, project_model_error,
    project_model_process_error, project_model_runtime_plan_error, project_model_sandbox_error,
};
use super::super::intentional_boundary_runtime_snapshot::{
    IntentionalBoundaryRuntimeSnapshot, allocate_runtime_directory,
};
use super::super::non_blind_history_runtime::prepare_historical_runtime;
use super::super::non_blind_history_runtime_support::{resolve_on_path, sandbox_repository_path};
use super::{Provider, TypeScriptCompilerExecutionOutput};
use crate::semantic_indexer_installation::SemanticIndexerStore;
use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROJECT_MODEL_SIDECAR: &[u8] = include_bytes!("../assets/typescript-project-model.js");
const PROJECT_MODEL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PROJECT_MODEL_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SidecarInput<'a> {
    schema_version: u32,
    configs: &'a [String],
    source_files: &'a [String],
}

struct TypeScriptProjectModelRuntime(PathBuf);

impl TypeScriptProjectModelRuntime {
    fn create(root: &Path) -> Result<Self, String> {
        allocate_runtime_directory(root, ".sniff-typescript-project-model-call").map(Self)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TypeScriptProjectModelRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn run_typescript_project_model(
    root: &Path,
    revision: &str,
    configs: &[String],
    required_sources: &[String],
) -> Result<TypeScriptCompilerExecutionOutput, ProjectModelDerivationError> {
    let anchor = configs
        .first()
        .or_else(|| required_sources.first())
        .map(String::as_str)
        .unwrap_or("<typescript-project>");
    let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
        root,
        revision,
        "sniff-typescript-project-model-snapshot",
    )
    .map_err(|detail| {
        project_model_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            Provider::TypeScriptCompilerApi,
            IntentionalBoundaryProjectModelFailurePhase::SnapshotPreparation,
            Some(anchor),
            detail,
        )
    })?;
    let runtime = TypeScriptProjectModelRuntime::create(snapshot.path())
        .map_err(|detail| runtime_error(anchor, detail))?;
    let cache = runtime.path().join("cache");
    fs::create_dir(&cache).map_err(|error| {
        runtime_error(
            anchor,
            format!("failed to create TypeScript project-model cache: {error}"),
        )
    })?;
    let sidecar = runtime.path().join("typescript-project-model.js");
    fs::write(&sidecar, PROJECT_MODEL_SIDECAR).map_err(|error| {
        runtime_error(
            anchor,
            format!("failed to stage TypeScript project-model sidecar: {error}"),
        )
    })?;
    let input_path = runtime.path().join("input.json");
    let input = serde_json::to_vec(&SidecarInput {
        schema_version: 1,
        configs,
        source_files: required_sources,
    })
    .map_err(|error| runtime_error(anchor, format!("failed to encode sidecar input: {error}")))?;
    fs::write(&input_path, input).map_err(|error| {
        runtime_error(
            anchor,
            format!("failed to stage TypeScript project-model input: {error}"),
        )
    })?;

    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript)
        .map_err(|detail| runtime_error(anchor, detail))?;
    let store = SemanticIndexerStore::for_user().map_err(|detail| {
        project_model_error(
            ProjectModelDerivationErrorKind::InfrastructureUnavailable,
            Provider::TypeScriptCompilerApi,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(anchor),
            detail,
        )
    })?;
    let installed = store.verify(spec).map_err(|detail| {
        project_model_error(
            ProjectModelDerivationErrorKind::InfrastructureUnavailable,
            Provider::TypeScriptCompilerApi,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(anchor),
            detail,
        )
    })?;
    let typescript = installed
        .root
        .join("node_modules")
        .join("typescript")
        .join("lib")
        .join("typescript.js");
    if !typescript.is_file() {
        return Err(runtime_error(
            anchor,
            "pinned TypeScript compiler API entrypoint is missing",
        ));
    }
    let host_node = resolve_on_path("node").map_err(|error| {
        project_model_runtime_plan_error(
            Provider::TypeScriptCompilerApi,
            anchor,
            "TypeScript compiler project-model Node runtime",
            error,
        )
    })?;
    #[cfg(windows)]
    let node = stage_windows_node(runtime.path(), &host_node)
        .map_err(|detail| runtime_error(anchor, detail))?;
    #[cfg(not(windows))]
    let node = host_node;
    #[cfg(windows)]
    let logical_program = node.to_string_lossy().into_owned();
    #[cfg(not(windows))]
    let logical_program = "node".to_string();
    let mut logical_command = vec![logical_program];
    if cfg!(windows) {
        logical_command.extend([
            "--preserve-symlinks".to_string(),
            "--preserve-symlinks-main".to_string(),
        ]);
    }
    logical_command.extend([
        sandbox_repository_path(snapshot.path(), &sidecar),
        typescript.to_string_lossy().into_owned(),
        sandbox_repository_path(snapshot.path(), &input_path),
    ]);
    let mut plan =
        prepare_historical_runtime(snapshot.path(), &cache, &logical_command).map_err(|error| {
            project_model_runtime_plan_error(
                Provider::TypeScriptCompilerApi,
                anchor,
                "TypeScript compiler project-model runtime",
                error,
            )
        })?;
    plan.command.allow_network = false;
    #[cfg(target_os = "macos")]
    {
        plan.command.allow_local_network = false;
    }
    plan.command.timeout = PROJECT_MODEL_TIMEOUT;
    plan.command.output_limit = PROJECT_MODEL_OUTPUT_LIMIT;
    plan.command.read_only_paths.push(installed.root.clone());
    plan.command.read_only_paths.sort();
    plan.command.read_only_paths.dedup();
    let node_sha256 = file_sha256(&node, "TypeScript project-model Node runtime")
        .map_err(|detail| runtime_error(anchor, detail))?;
    let sidecar_sha256 = file_sha256(&sidecar, "TypeScript project-model sidecar")
        .map_err(|detail| runtime_error(anchor, detail))?;
    let input_sha256 = file_sha256(&input_path, "TypeScript project-model input")
        .map_err(|detail| runtime_error(anchor, detail))?;
    let toolchain_identity_sha256 = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                "sniff-typescript-project-model-toolchain-v2",
                &plan.runtime_identity,
                &installed.tree_sha256,
                &node_sha256,
                &sidecar_sha256,
                &input_sha256,
            ))
            .map_err(|error| runtime_error(
                anchor,
                format!("failed to commit toolchain: {error}")
            ))?
        )
    );
    let run_result = crate::sandbox::run(&plan.command);
    verify_file_unchanged(&node, "TypeScript project-model Node runtime", &node_sha256)
        .and_then(|()| {
            verify_file_unchanged(
                &sidecar,
                "TypeScript project-model sidecar",
                &sidecar_sha256,
            )
        })
        .and_then(|()| {
            verify_file_unchanged(&input_path, "TypeScript project-model input", &input_sha256)
        })
        .map_err(|detail| integrity_error(anchor, detail))?;
    store.verify(spec).map_err(|error| {
        project_model_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            Provider::TypeScriptCompilerApi,
            IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
            Some(anchor),
            format!("TypeScript compiler installation changed during project modeling: {error}"),
        )
    })?;
    let output = run_result.map_err(|error| {
        project_model_sandbox_error(
            Provider::TypeScriptCompilerApi,
            anchor,
            "sandboxed TypeScript compiler project-model execution failed",
            error,
        )
    })?;
    if output.timed_out {
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            Provider::TypeScriptCompilerApi,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            anchor,
            "sandboxed TypeScript compiler project-model execution timed out",
            output,
        ));
    }
    if output.status_code != Some(0) {
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::ProviderRejectedRepository,
            Provider::TypeScriptCompilerApi,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            anchor,
            "sandboxed TypeScript compiler project-model execution failed",
            output,
        ));
    }
    Ok(TypeScriptCompilerExecutionOutput {
        toolchain_identity_sha256,
        stdout: output.stdout,
    })
}

#[cfg(windows)]
fn stage_windows_node(directory: &Path, source: &Path) -> Result<PathBuf, String> {
    let staged = directory.join("node.exe");
    fs::copy(source, &staged).map_err(|error| {
        format!(
            "failed to stage Node runtime {} into {}: {error}",
            source.display(),
            staged.display()
        )
    })?;
    fs::canonicalize(&staged).map_err(|error| {
        format!(
            "failed to resolve staged Node runtime {}: {error}",
            staged.display()
        )
    })
}

fn file_sha256(path: &Path, label: &str) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|error| format!("failed to open {label} {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash {label} {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_file_unchanged(path: &Path, label: &str, expected: &str) -> Result<(), String> {
    let actual = file_sha256(path, label)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} changed during project modeling"))
    }
}

fn integrity_error(anchor: &str, detail: impl Into<String>) -> ProjectModelDerivationError {
    project_model_error(
        ProjectModelDerivationErrorKind::InfrastructureFailed,
        Provider::TypeScriptCompilerApi,
        IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
        Some(anchor),
        detail,
    )
}

fn runtime_error(anchor: &str, detail: impl Into<String>) -> ProjectModelDerivationError {
    project_model_error(
        ProjectModelDerivationErrorKind::InfrastructureFailed,
        Provider::TypeScriptCompilerApi,
        IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
        Some(anchor),
        detail,
    )
}
