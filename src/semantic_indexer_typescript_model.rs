use super::census::{Inputs, Journal, ModelPart, Request, Role};
use super::typescript_inputs::{CompilerInputBindings, command_runtime_sha256};
use super::typescript_model_output::{OUTPUT_SCHEMA_VERSION, is_config_candidate, parse_output};
use super::typescript_model_plans::plans_from_output;
use super::*;
use serde::Serialize;

const SIDECAR: &[u8] = include_bytes!("../assets/typescript-project-model.js");

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SidecarInput<'a> {
    schema_version: u32,
    configs: &'a [String],
    source_files: &'a [String],
}

pub(super) async fn discover(
    context: &RequiredIndexerRunContext<'_>,
) -> Result<Vec<SemanticIndexerVariantPlan>, SemanticIndexerRunFailure> {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::InstallationVerification,
            Some(SemanticIndexerKind::TypeScriptJavaScript),
            detail,
        )
    })?;
    let installed = context.store.verify(spec).map_err(|detail| {
        model_failure(
            spec,
            SemanticIndexerRunPhase::InstallationVerification,
            detail,
        )
    })?;
    let journal = Journal::open(context, spec, &installed)?;
    let execution_root = match context
        .recovery
        .prepare_indexer_run()
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))
    {
        Ok(root) => root,
        Err(failure) => return journal.finish(Err(failure)),
    };
    let result = discover_at(context, spec, &installed, &execution_root, &journal).await;
    let cleanup = context
        .recovery
        .finish_indexer_run()
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Cleanup, detail));
    journal.finish(finish_discovery(result, cleanup))
}

async fn discover_at(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    root: &Path,
    journal: &Journal,
) -> Result<
    (
        Vec<SemanticIndexerVariantPlan>,
        SemanticIndexerProcessEvidence,
    ),
    SemanticIndexerRunFailure,
> {
    repository_snapshot::stage_repository_snapshot(context.root, root)
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))?;
    require_snapshot(context, root).map_err(|detail| {
        model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
    })?;
    let sources = files_for_indexer(context.files, spec.kind)
        .iter()
        .map(|file| {
            repository_relative_path(context.root, Path::new(&file.file_path)).map(|path| path.0)
        })
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|detail| {
            model_failure(spec, SemanticIndexerRunPhase::RepositoryValidation, detail)
        })?
        .into_iter()
        .collect::<Vec<_>>();
    let configs = discover_configs(root).map_err(|detail| {
        model_failure(spec, SemanticIndexerRunPhase::RepositoryValidation, detail)
    })?;
    fs::create_dir(root.join(INDEXER_TEMP_DIR)).map_err(|error| {
        model_failure(
            spec,
            SemanticIndexerRunPhase::Preparation,
            format!("failed to create TypeScript project-model runtime: {error}"),
        )
    })?;
    let sidecar = root
        .join(INDEXER_TEMP_DIR)
        .join("typescript-project-model.js");
    let input_path = root
        .join(INDEXER_TEMP_DIR)
        .join("typescript-project-model-input.json");
    fs::write(&sidecar, SIDECAR).map_err(|error| {
        model_failure(
            spec,
            SemanticIndexerRunPhase::Preparation,
            format!("failed to stage TypeScript project-model sidecar: {error}"),
        )
    })?;
    let input = serde_json::to_vec(&SidecarInput {
        schema_version: OUTPUT_SCHEMA_VERSION,
        configs: &configs,
        source_files: &sources,
    })
    .map_err(|error| {
        model_failure(
            spec,
            SemanticIndexerRunPhase::Preparation,
            format!("failed to encode TypeScript project-model input: {error}"),
        )
    })?;
    fs::write(&input_path, input).map_err(|error| {
        model_failure(
            spec,
            SemanticIndexerRunPhase::Preparation,
            format!("failed to stage TypeScript project-model input: {error}"),
        )
    })?;
    let compiler = fs::canonicalize(
        installed
            .root
            .join("node_modules/typescript/lib/typescript.js"),
    )
    .map_err(|error| {
        model_failure(
            spec,
            SemanticIndexerRunPhase::InstallationVerification,
            format!("failed to resolve the pinned TypeScript compiler: {error}"),
        )
    })?;
    let mut prepared = build_indexer_sandbox_command(spec, root, installed, Vec::new(), None)
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))?;
    prepared.command.args = model_arguments(root, &sidecar, &compiler, &input_path);
    #[cfg(windows)]
    prepared
        .command
        .windows_virtualized_paths
        .push(root.to_path_buf());
    prepared.command.timeout = Duration::from_secs(5 * 60);
    prepared.command.output_limit = 32 * 1024 * 1024;
    prepared
        .runtime_files
        .extend([sidecar, input_path, compiler]);
    let identities = runtime_file_identities(&prepared.runtime_files).map_err(|detail| {
        model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
    })?;
    let execution_runtime_sha256 = command_runtime_sha256(
        spec,
        installed,
        Path::new(&prepared.command.program),
        &identities,
    )
    .map_err(|detail| {
        model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
    })?;
    let runtime_sha256 = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                "sniff-normal-typescript-project-model-runtime-v1",
                &installed.tree_sha256,
                identities
                    .iter()
                    .map(|identity| (identity.length, &identity.sha256))
                    .collect::<Vec<_>>(),
            ))
            .map_err(|error| model_failure(
                spec,
                SemanticIndexerRunPhase::Preparation,
                error.to_string()
            ))?
        )
    );
    journal.bind_inputs(Inputs::TypeScript {
        runtime_sha256: runtime_sha256.clone(),
    })?;
    let request = Request {
        role: Role::TypeScriptProject,
        arguments: prepared.command.args.clone(),
        environment: prepared.command.env.iter().cloned().collect(),
    };
    let result = run_sandbox_command(prepared.command, Role::TypeScriptProject.operation()).await;
    let integrity = runtime_file_identities(&prepared.runtime_files).and_then(|after| {
        verify_runtime_identities_unchanged(
            "TypeScript compiler project model",
            &identities,
            &after,
        )
    });
    let snapshot_integrity = require_snapshot(context, root);
    let installation_integrity = context.store.verify(spec).map(|_| ());
    let output = journal.record_command(
        request,
        validate_execution(
            spec,
            result,
            [integrity, snapshot_integrity, installation_integrity],
        ),
    )?;
    let ((plans, model), process) = validate_output(spec, output, |stdout| {
        let plans = plans_from_output(
            stdout,
            &configs,
            &sources,
            context.repository_content_sha256,
            &CompilerInputBindings {
                project_model: &runtime_sha256,
                runtime: &execution_runtime_sha256,
                installation: &installed.tree_sha256,
            },
            |path| require_plain_file(root, path),
        )?;
        Ok((plans, parse_output(stdout)?))
    })?;
    journal.record_model(ModelPart::TypeScript(model))?;
    Ok((plans, process))
}

fn validate_output<T>(
    spec: PinnedIndexer,
    output: crate::sandbox::SandboxOutput,
    validate: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<(T, SemanticIndexerProcessEvidence), SemanticIndexerRunFailure> {
    match validate(output.stdout.as_bytes()) {
        Ok(value) => Ok((value, process_evidence(output))),
        Err(detail) => Err(indexer_process_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::OutputValidation,
            detail,
            output,
        )),
    }
}

fn finish_discovery<T>(
    result: Result<(T, SemanticIndexerProcessEvidence), SemanticIndexerRunFailure>,
    cleanup: Result<(), SemanticIndexerRunFailure>,
) -> Result<T, SemanticIndexerRunFailure> {
    match (result, cleanup) {
        (Ok((_, process)), Err(mut failure)) => {
            if failure.process.is_none() {
                failure.process = Some(Box::new(process));
            }
            Err(failure)
        }
        (result, cleanup) => {
            combine_typed_run_and_integrity(result, cleanup).map(|(value, _)| value)
        }
    }
}

fn validate_execution(
    spec: PinnedIndexer,
    result: Result<crate::sandbox::SandboxOutput, String>,
    integrity_checks: [Result<(), String>; 3],
) -> Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure> {
    let mut result = match result {
        Err(detail) => Err(model_failure(
            spec,
            SemanticIndexerRunPhase::Execution,
            detail,
        )),
        Ok(output)
            if output.timed_out
                || output.memory_limit_exceeded
                || output.process_limit_exceeded
                || output.status_code != Some(0) =>
        {
            Err(indexer_process_failure(
                spec,
                SemanticIndexerRunFailureKind::RepositoryRejected,
                SemanticIndexerRunPhase::Execution,
                "TypeScript compiler project census failed; no unqualified indexing fallback was used",
                output,
            ))
        }
        Ok(output) => Ok(output),
    };
    for integrity in integrity_checks {
        let integrity = integrity.map_err(|detail| {
            model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
        });
        result = match (result, integrity) {
            (Ok(output), Err(mut failure)) => {
                failure.process = Some(Box::new(process_evidence(output)));
                Err(failure)
            }
            (result, integrity) => combine_typed_run_and_integrity(result, integrity),
        };
    }
    result
}

fn require_snapshot(context: &RequiredIndexerRunContext<'_>, staged: &Path) -> Result<(), String> {
    source_integrity_digest_at(context.root, staged, context.files)?;
    for root in [staged, context.root] {
        if repository_snapshot::repository_content_digest(root)?
            != context.repository_content_sha256
        {
            return Err(
                "TypeScript project-model repository differs from the parsed scan snapshot"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn model_arguments(root: &Path, sidecar: &Path, compiler: &Path, input: &Path) -> Vec<String> {
    let mut args = Vec::new();
    if cfg!(windows) {
        args.extend([
            "--preserve-symlinks".to_string(),
            "--preserve-symlinks-main".to_string(),
        ]);
    }
    args.extend(
        [sidecar, compiler, input]
            .map(|path| sandbox_repository_argument(root, &path.to_string_lossy())),
    );
    args
}

fn require_plain_file(root: &Path, path: &str) -> Result<(), String> {
    let target = root.join(path);
    let metadata = fs::symlink_metadata(&target).map_err(|error| {
        format!("TypeScript project-model input {path} is unavailable: {error}")
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || !fs::canonicalize(&target)
            .map_err(|error| error.to_string())?
            .starts_with(fs::canonicalize(root).map_err(|error| error.to_string())?)
    {
        return Err(format!(
            "TypeScript project-model input is not a plain repository file: {path}"
        ));
    }
    Ok(())
}

fn discover_configs(root: &Path) -> Result<Vec<String>, String> {
    let mut configs = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            format!("failed to enumerate TypeScript project configurations: {error}")
        })? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or_else(|| "TypeScript project configuration has a non-UTF-8 path".to_string())?
                .replace('\\', "/");
            if relative.split('/').any(|part| {
                matches!(
                    part,
                    "node_modules"
                        | ".git"
                        | ".hg"
                        | ".svn"
                        | ".sniff"
                        | INDEXER_TEMP_DIR
                        | INDEXER_CACHE_DIR
                )
            }) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if is_config_candidate(&relative) {
                require_plain_file(root, &relative)?;
                configs.insert(relative);
            } else if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push(path);
            } else if metadata.file_type().is_symlink()
                && fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir())
            {
                return Err(format!(
                    "TypeScript configuration census cannot enumerate a symlink directory: {relative}"
                ));
            }
        }
    }
    Ok(configs.into_iter().collect())
}

fn model_failure(
    spec: PinnedIndexer,
    phase: SemanticIndexerRunPhase,
    detail: impl Into<String>,
) -> SemanticIndexerRunFailure {
    indexer_failure(
        spec,
        SemanticIndexerRunFailureKind::InfrastructureFailed,
        phase,
        detail,
    )
}

#[cfg(test)]
#[path = "tests/semantic_indexer_typescript_model.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/semantic_indexer_typescript_model_execution.rs"]
mod execution_tests;
