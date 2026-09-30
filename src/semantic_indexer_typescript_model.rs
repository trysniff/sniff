use super::typescript_model_output::{OUTPUT_SCHEMA_VERSION, is_config_candidate};
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
    let execution_root = context
        .recovery
        .prepare_indexer_run()
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))?;
    let result = discover_at(context, spec, &installed, &execution_root).await;
    let cleanup = context
        .recovery
        .finish_indexer_run()
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Cleanup, detail));
    combine_typed_run_and_integrity(result, cleanup)
}

async fn discover_at(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    root: &Path,
) -> Result<Vec<SemanticIndexerVariantPlan>, SemanticIndexerRunFailure> {
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
    let compiler = installed
        .root
        .join("node_modules/typescript/lib/typescript.js");
    let mut prepared = build_indexer_sandbox_command(spec, root, installed, Vec::new(), None)
        .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Preparation, detail))?;
    prepared.command.args = model_arguments(root, &sidecar, &compiler, &input_path);
    prepared.command.timeout = Duration::from_secs(5 * 60);
    prepared.command.output_limit = 32 * 1024 * 1024;
    prepared
        .runtime_files
        .extend([sidecar, input_path, compiler]);
    let identities = runtime_file_identities(&prepared.runtime_files).map_err(|detail| {
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
    let result = run_with_runtime_identity(prepared, "TypeScript compiler project model").await;
    require_snapshot(context, root).map_err(|detail| {
        model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
    })?;
    context.store.verify(spec).map_err(|detail| {
        model_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
    })?;
    let output =
        result.map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::Execution, detail))?;
    if output.timed_out
        || output.memory_limit_exceeded
        || output.process_limit_exceeded
        || output.status_code != Some(0)
    {
        return Err(indexer_process_failure(
            spec,
            SemanticIndexerRunFailureKind::RepositoryRejected,
            SemanticIndexerRunPhase::Execution,
            "TypeScript compiler project census failed; no unqualified indexing fallback was used",
            output,
        ));
    }
    plans_from_output(
        output.stdout.as_bytes(),
        &configs,
        &sources,
        context.repository_content_sha256,
        &runtime_sha256,
        |path| require_plain_file(root, path),
    )
    .map_err(|detail| model_failure(spec, SemanticIndexerRunPhase::OutputValidation, detail))
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
