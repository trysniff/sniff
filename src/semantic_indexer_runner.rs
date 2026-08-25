use crate::sandbox::{SandboxCommand, sandbox_path};
use crate::semantic_index::{RepositoryPath, SemanticIndex, SemanticPositionEncoding};
use crate::semantic_indexer_installation::{InstalledIndexer, SemanticIndexerStore};
use crate::semantic_indexer_manifest::{
    IndexerRuntime, PinnedIndexer, SemanticIndexerKind, pinned_indexer, required_indexers,
};
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::Duration;
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "semantic_indexer_runner_outcome.rs"]
mod outcome;

pub(crate) use outcome::*;

#[path = "semantic_indexer_recovery.rs"]
mod recovery;

pub(crate) use recovery::recover_interrupted_semantic_indexing;
use recovery::{INDEXER_CACHE_DIR, INDEXER_TEMP_DIR, SemanticIndexerRecoveryGuard};

#[cfg(test)]
pub(crate) fn install_test_semantic_recovery_marker(root: &Path) -> Result<(), String> {
    let guard = recovery::SemanticIndexerRecoveryGuard::begin(root)?;
    std::mem::forget(guard);
    Ok(())
}

#[path = "semantic_indexer_gradle_preparation.rs"]
mod gradle_preparation;
#[cfg(windows)]
#[path = "semantic_indexer_gradle_windows.rs"]
mod gradle_windows;
#[path = "semantic_indexer_java_runtime.rs"]
mod java_runtime;
#[cfg(test)]
use java_runtime::resolve_java_home_runtime;
use java_runtime::resolve_java_runtime;
#[cfg(windows)]
use java_runtime::system_gradle_launcher_jar;

const INDEX_TIMEOUT: Duration = Duration::from_secs(60 * 60);
#[cfg(debug_assertions)]
const INDEXER_TIMEOUT_ENV: &str = "SNIFF_INTERNAL_INDEXER_TIMEOUT_SECS";
const MAX_PROCESS_OUTPUT: usize = 2 * 1024 * 1024;
const INDEXER_MEMORY_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const INDEXER_PROCESS_LIMIT: u32 = 512;
const MAX_COMPACT_ERROR_OUTPUT: usize = 8 * 1024;
const MAX_RUNTIME_IDENTITY_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RUNTIME_IDENTITY_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const GRADLE_INDEXER_BASE_JVM_ARGS: &str = concat!(
    "--add-opens=java.base/java.util=ALL-UNNAMED ",
    "--add-opens=java.base/java.lang=ALL-UNNAMED ",
    "--add-opens=java.base/java.lang.invoke=ALL-UNNAMED ",
    "--add-opens=java.prefs/java.util.prefs=ALL-UNNAMED ",
    "--add-opens=java.base/java.nio.charset=ALL-UNNAMED ",
    "--add-opens=java.base/java.net=ALL-UNNAMED ",
    "--add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED ",
    "-Xmx512m -XX:MaxMetaspaceSize=384m -Dfile.encoding=US-ASCII ",
    "-Duser.country=US -Duser.language=en -Duser.variant=",
);
pub(crate) const WINDOWS_SCIP_PYTHON_BOOTSTRAP: &str = "const child_process=require('child_process'); const denyProcess=(...args)=>{ throw new Error('Sniff denied scip-python subprocess: '+String(args[0])); }; child_process.execFileSync=denyProcess; child_process.spawnSync=denyProcess; child_process.spawn=denyProcess; const path=require('path'); const NativeRegExp=RegExp; function PatchedRegExp(pattern, flags) { if (pattern === path.sep) pattern = path.sep + path.sep; return new NativeRegExp(pattern, flags); } PatchedRegExp.prototype=NativeRegExp.prototype; Object.setPrototypeOf(PatchedRegExp, NativeRegExp); global.RegExp=PatchedRegExp; require(process.argv[1]);";
const WINDOWS_SCIP_NODE_BOOTSTRAP: &str = "const indexer=require(process.argv[1]); if (typeof indexer.main !== 'function') throw new Error('SCIP Node indexer does not export main()'); indexer.main();";

struct TemporaryIndexerWorkspace {
    directory: PathBuf,
    #[cfg(windows)]
    gradle_launcher_jar: PathBuf,
    #[cfg(windows)]
    gradle_overlay_directory: Option<PathBuf>,
    gradle_main_class: &'static str,
    project_root: PathBuf,
}

struct PreparedIndexerCommand {
    command: SandboxCommand,
    runtime_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeFileIdentity {
    path: PathBuf,
    length: u64,
    sha256: String,
}

impl TemporaryIndexerWorkspace {
    fn cleanup(self, indexer_name: &str) -> Result<(), String> {
        let workspace_cleanup = fs::remove_dir_all(&self.directory).map_err(|error| {
            format!(
                "{} indexing completed but temporary workspace cleanup failed for {}: {error}",
                indexer_name,
                self.directory.display()
            )
        });
        #[cfg(windows)]
        let overlay_cleanup = match &self.gradle_overlay_directory {
            Some(overlay) if overlay.exists() => {
                fs::remove_dir_all(overlay).map_err(|error| {
                    format!(
                        "{} indexing completed but Gradle runtime overlay cleanup failed for {}: {error}",
                        indexer_name,
                        overlay.display()
                    )
                })
            }
            _ => Ok(()),
        };
        #[cfg(not(windows))]
        let overlay_cleanup = Ok(());
        match (workspace_cleanup, overlay_cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(workspace_error), Err(overlay_error)) => {
                Err(format!("{workspace_error}; additionally, {overlay_error}"))
            }
        }
    }
}

pub(crate) async fn run_required_indexers(
    repository_root: &Path,
    files: &[FileRecord],
) -> Result<BTreeMap<SemanticIndexerKind, SemanticIndex>, String> {
    run_required_indexers_typed(repository_root, files)
        .await
        .map_err(|failure| failure.detail)
}

pub(crate) async fn run_required_indexers_typed(
    repository_root: &Path,
    files: &[FileRecord],
) -> Result<BTreeMap<SemanticIndexerKind, SemanticIndex>, SemanticIndexerRunFailure> {
    let outcome = run_required_indexers_exhaustive_typed(repository_root, files).await?;
    if let Some(failure) = outcome.failures.into_iter().next() {
        Err(failure)
    } else {
        Ok(outcome.indexes)
    }
}

pub(crate) async fn run_required_indexers_exhaustive_typed(
    repository_root: &Path,
    files: &[FileRecord],
) -> Result<SemanticIndexerBatchOutcome, SemanticIndexerRunFailure> {
    let root =
        strip_windows_verbatim_prefix(fs::canonicalize(repository_root).map_err(|error| {
            failure(
                SemanticIndexerRunFailureKind::InvalidInput,
                SemanticIndexerRunPhase::RepositoryValidation,
                None,
                format!(
                    "failed to resolve semantic index repository root {}: {error}",
                    repository_root.display()
                ),
            )
        })?);
    let store = SemanticIndexerStore::for_user().map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::InstallationVerification,
            None,
            detail,
        )
    })?;
    let recovery = recovery::SemanticIndexerRecoveryGuard::begin(&root).map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            None,
            detail,
        )
    })?;
    let mut indexes = BTreeMap::new();
    let mut failures = Vec::new();
    for kind in required_indexers(files) {
        match run_required_indexer_typed(&root, files, &store, kind, &recovery).await {
            Ok(index) => {
                indexes.insert(kind, index);
            }
            Err(failure) => failures.push(failure),
        }
    }
    recovery.finish().map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Cleanup,
            None,
            detail,
        )
    })?;
    Ok(SemanticIndexerBatchOutcome { indexes, failures })
}

#[cfg(test)]
pub(crate) async fn run_required_indexer_with_store_for_test(
    repository_root: &Path,
    files: &[FileRecord],
    store: &SemanticIndexerStore,
    kind: SemanticIndexerKind,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    let root =
        strip_windows_verbatim_prefix(fs::canonicalize(repository_root).map_err(|error| {
            failure(
                SemanticIndexerRunFailureKind::InvalidInput,
                SemanticIndexerRunPhase::RepositoryValidation,
                Some(kind),
                format!(
                    "failed to resolve semantic index repository root {}: {error}",
                    repository_root.display()
                ),
            )
        })?);
    let recovery = SemanticIndexerRecoveryGuard::begin(&root).map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            Some(kind),
            detail,
        )
    })?;
    let run_result = run_required_indexer_typed(&root, files, store, kind, &recovery).await;
    let cleanup_result = recovery.finish().map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Cleanup,
            Some(kind),
            detail,
        )
    });
    combine_typed_run_and_integrity(run_result, cleanup_result)
}

async fn run_required_indexer_typed(
    root: &Path,
    files: &[FileRecord],
    store: &SemanticIndexerStore,
    kind: SemanticIndexerKind,
    recovery: &SemanticIndexerRecoveryGuard,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    let spec = pinned_indexer(kind).map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::InstallationVerification,
            Some(kind),
            detail,
        )
    })?;
    if kind == SemanticIndexerKind::Kotlin {
        reject_unsupported_android_gradle_typed(root, files)?;
    }
    let installed = store.verify(spec).map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::InstallationVerification,
            Some(kind),
            detail,
        )
    })?;
    let index_path = root.join("index.scip");
    if index_path.exists() {
        return Err(failure(
            SemanticIndexerRunFailureKind::UnsupportedProjectShape,
            SemanticIndexerRunPhase::RepositoryValidation,
            Some(kind),
            "refusing to overwrite repository file index.scip; remove or relocate it before indexing",
        ));
    }
    if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
        eprintln!("[sniff] semantic indexer start: {}", spec.display_name);
    }
    let run_result = run_one(spec, root, &installed, files, recovery).await;
    let installation_result = store.verify(spec).map(|_| ()).map_err(|error| {
        failure(
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::IntegrityVerification,
            Some(kind),
            format!(
                "{} installation changed while it was running: {error}",
                spec.display_name
            ),
        )
    });
    let process = match combine_typed_run_and_integrity(run_result, installation_result) {
        Ok(process) => process,
        Err(run_failure) => {
            if index_path.exists()
                && let Err(error) = fs::remove_file(&index_path)
            {
                return Err(failure(
                    SemanticIndexerRunFailureKind::InfrastructureFailed,
                    SemanticIndexerRunPhase::Cleanup,
                    Some(kind),
                    format!(
                        "{}; additionally failed to remove generated SCIP output {}: {error}",
                        run_failure.detail,
                        index_path.display()
                    ),
                ));
            }
            return Err(run_failure);
        }
    };
    if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
        eprintln!("[sniff] semantic indexer complete: {}", spec.display_name);
    }
    let index_files = files_for_indexer(files, kind);
    let expected_languages = expected_document_languages(root, &index_files).map_err(|detail| {
        failure(
            SemanticIndexerRunFailureKind::InvalidInput,
            SemanticIndexerRunPhase::OutputValidation,
            Some(kind),
            detail,
        )
    })?;
    let result = crate::semantic_index_scip::ingest_scip_file_with_expected_languages(
        root,
        &index_path,
        Some(&expected_languages),
        missing_position_encoding(kind),
    )
    .and_then(|index| validate_expected_documents(root, files, kind, index))
    .map_err(|detail| SemanticIndexerRunFailure {
        kind: SemanticIndexerRunFailureKind::IncompleteOutput,
        phase: SemanticIndexerRunPhase::OutputValidation,
        indexer: Some(kind),
        detail,
        process: Some(Box::new(process)),
    });
    let cleanup = fs::remove_file(&index_path);
    if let Err(error) = cleanup {
        let prior = result
            .as_ref()
            .err()
            .map(|failure| format!("{}; additionally, ", failure.detail))
            .unwrap_or_default();
        return Err(failure(
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Cleanup,
            Some(kind),
            format!(
                "{prior}failed to remove generated SCIP output {}: {error}",
                index_path.display()
            ),
        ));
    }
    result
}

pub(crate) fn files_for_indexer(
    files: &[FileRecord],
    kind: SemanticIndexerKind,
) -> Vec<FileRecord> {
    files
        .iter()
        .filter(|file| language_kind(file) == Some(kind))
        .cloned()
        .collect()
}

fn expected_document_languages(
    root: &Path,
    files: &[FileRecord],
) -> Result<BTreeMap<RepositoryPath, String>, String> {
    files
        .iter()
        .map(|file| {
            Ok((
                repository_relative_path(root, Path::new(&file.file_path))?,
                file.language.clone(),
            ))
        })
        .collect()
}

fn missing_position_encoding(kind: SemanticIndexerKind) -> Option<SemanticPositionEncoding> {
    match kind {
        SemanticIndexerKind::TypeScriptJavaScript => Some(SemanticPositionEncoding::Utf16),
        SemanticIndexerKind::Go => Some(SemanticPositionEncoding::Utf8),
        SemanticIndexerKind::Python => Some(SemanticPositionEncoding::Utf32),
        SemanticIndexerKind::Kotlin => Some(SemanticPositionEncoding::Utf16),
        SemanticIndexerKind::Rust => None,
    }
}

async fn run_one(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
    files: &[FileRecord],
    recovery: &SemanticIndexerRecoveryGuard,
) -> Result<SemanticIndexerProcessEvidence, SemanticIndexerRunFailure> {
    recovery.prepare_indexer_run().map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            detail,
        )
    })?;
    let run_result = run_one_in_recovery_scope(spec, root, installed, files).await;
    let cleanup_result = recovery.finish_indexer_run().map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Cleanup,
            detail,
        )
    });
    combine_typed_run_and_integrity(run_result, cleanup_result)
}

async fn run_one_in_recovery_scope(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
    files: &[FileRecord],
) -> Result<SemanticIndexerProcessEvidence, SemanticIndexerRunFailure> {
    let source_digest_before = source_integrity_digest(files).map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InvalidInput,
            SemanticIndexerRunPhase::IntegrityVerification,
            detail,
        )
    })?;
    let temporary_dir = root.join(INDEXER_TEMP_DIR);
    let temporary_metadata = fs::symlink_metadata(&temporary_dir).map_err(|error| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            format!(
                "failed to inspect private semantic indexer temp directory {}: {error}",
                temporary_dir.display()
            ),
        )
    })?;
    if !temporary_metadata.file_type().is_dir() {
        return Err(indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            format!(
                "semantic recovery lifecycle did not prepare private runtime directory {}",
                temporary_dir.display()
            ),
        ));
    }
    let cache_root =
        (spec.kind == SemanticIndexerKind::Kotlin).then(|| root.join(INDEXER_CACHE_DIR));
    if let Some(cache_root) = &cache_root {
        match fs::symlink_metadata(cache_root) {
            Ok(_) => {
                return Err(indexer_failure(
                    spec,
                    SemanticIndexerRunFailureKind::InfrastructureFailed,
                    SemanticIndexerRunPhase::Preparation,
                    format!(
                        "semantic recovery lifecycle did not provide a clean private cache path {}",
                        cache_root.display()
                    ),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(indexer_failure(
                    spec,
                    SemanticIndexerRunFailureKind::InfrastructureFailed,
                    SemanticIndexerRunPhase::Preparation,
                    format!(
                        "failed to inspect private semantic indexer cache path {}: {error}",
                        cache_root.display()
                    ),
                ));
            }
        }
    }
    if spec.kind == SemanticIndexerKind::Go {
        prepare_go_dependency_cache(spec, root, installed).await?;
    }
    if spec.kind == SemanticIndexerKind::Kotlin {
        prepare_kotlin_dependency_cache(spec, root, installed)
            .await
            .map_err(|error| kotlin_dependency_preparation_failure(spec, error))?;
    }
    let workspace = prepare_indexer_workspace(spec, root).map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            detail,
        )
    })?;
    let temporary_project = if spec.kind == SemanticIndexerKind::TypeScriptJavaScript {
        prepare_mixed_typescript_javascript_project(spec, root, files).map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Preparation,
                detail,
            )
        })?
    } else {
        #[cfg(windows)]
        if spec.kind == SemanticIndexerKind::Python {
            prepare_windows_python_project(root, files).map_err(|detail| {
                indexer_failure(
                    spec,
                    SemanticIndexerRunFailureKind::InfrastructureFailed,
                    SemanticIndexerRunPhase::Preparation,
                    detail,
                )
            })?
        } else {
            None
        }
        #[cfg(not(windows))]
        {
            None
        }
    };
    #[cfg(windows)]
    let python_environment = if spec.kind == SemanticIndexerKind::Python {
        Some(
            prepare_windows_python_environment(&temporary_dir).map_err(|detail| {
                indexer_failure(
                    spec,
                    SemanticIndexerRunFailureKind::InfrastructureFailed,
                    SemanticIndexerRunPhase::Preparation,
                    detail,
                )
            })?,
        )
    } else {
        None
    };
    #[cfg(not(windows))]
    let python_environment: Option<PathBuf> = None;
    let mut arguments = indexer_arguments_with_workspace(
        spec,
        root,
        temporary_project.as_deref(),
        workspace.as_ref(),
    );
    if let Some(environment) = python_environment {
        arguments.extend([
            "--environment".to_string(),
            environment.to_string_lossy().to_string(),
        ]);
    }
    let prepared_command =
        build_indexer_sandbox_command(spec, root, installed, arguments, workspace.as_ref())
            .map_err(|detail| {
                indexer_failure(
                    spec,
                    SemanticIndexerRunFailureKind::InfrastructureFailed,
                    SemanticIndexerRunPhase::Preparation,
                    detail,
                )
            })?;
    if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
        eprintln!(
            "[sniff] semantic indexer sandbox ready: {}",
            spec.display_name
        );
    }
    if let Some(cache_root) = &cache_root {
        if !cache_root.is_dir() {
            return Err(indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Preparation,
                format!(
                    "Kotlin dependency preparation did not produce the required offline cache {}",
                    cache_root.display()
                ),
            ));
        }
        write_private_gradle_properties(root, cache_root).map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Preparation,
                detail,
            )
        })?;
    }
    if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
        eprintln!(
            "[sniff] semantic indexer process start: {}",
            spec.display_name
        );
    }
    let output = run_with_runtime_identity(prepared_command, spec.display_name).await;
    if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
        eprintln!(
            "[sniff] semantic indexer process returned: {}",
            spec.display_name
        );
    }
    let temporary_project_cleanup = cleanup_temporary_project(temporary_project, spec.display_name);
    let workspace_cleanup = workspace
        .map(|workspace| workspace.cleanup(spec.display_name))
        .transpose();
    match (temporary_project_cleanup, workspace_cleanup) {
        (Ok(()), Ok(_)) => {}
        (Err(error), Ok(_)) | (Ok(()), Err(error)) => {
            return Err(indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Cleanup,
                error,
            ));
        }
        (Err(project_error), Err(workspace_error)) => {
            return Err(indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Cleanup,
                format!("{project_error}; additionally, {workspace_error}"),
            ));
        }
    }
    if let Some(cache_root) = cache_root
        && cache_root.exists()
    {
        fs::remove_dir_all(&cache_root).map_err(|error| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Cleanup,
                format!(
                    "{} indexing completed but private cache cleanup failed for {}: {error}",
                    spec.display_name,
                    cache_root.display()
                ),
            )
        })?;
    }
    let source_digest_after = source_integrity_digest(files).map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::IntegrityVerification,
            detail,
        )
    })?;
    if source_digest_before != source_digest_after {
        return Err(indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::IntegrityVerification,
            format!(
                "{} indexing changed an eligible source file; refusing to trust its SCIP output",
                spec.display_name
            ),
        ));
    }
    let output = output.map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Execution,
            detail,
        )
    })?;
    if output.timed_out {
        return Err(indexer_process_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::Execution,
            format!(
                "{} indexing timed out after {}",
                spec.display_name,
                format_timeout(index_timeout())
            ),
            output,
        ));
    }
    if output.status_code == Some(0) {
        let index_path = root.join("index.scip");
        if !index_path.is_file() {
            return Err(indexer_process_failure(
                spec,
                SemanticIndexerRunFailureKind::IncompleteOutput,
                SemanticIndexerRunPhase::OutputValidation,
                format!(
                    "{} exited successfully but did not emit SCIP index {}; output: {}",
                    spec.display_name,
                    index_path.display(),
                    compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
                ),
                output,
            ));
        }
        return Ok(process_evidence(output));
    }
    if output.status_code.is_none() {
        return Err(indexer_process_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Execution,
            format!(
                "{} indexing terminated without an exit status; output: {}",
                spec.display_name,
                compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
            ),
            output,
        ));
    }
    Err(indexer_process_failure(
        spec,
        SemanticIndexerRunFailureKind::RepositoryRejected,
        SemanticIndexerRunPhase::Execution,
        format!(
            "{} indexing failed with {}; output: {}",
            spec.display_name,
            output
                .status_code
                .map_or_else(|| "signal".to_string(), |status| status.to_string()),
            compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
        ),
        output,
    ))
}

async fn prepare_go_dependency_cache(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
) -> Result<(), SemanticIndexerRunFailure> {
    let mut prepared = build_indexer_sandbox_command(spec, root, installed, Vec::new(), None)
        .map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Preparation,
                detail,
            )
        })?;
    prepared.command.program = go_dependency_program(installed)
        .map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureUnavailable,
                SemanticIndexerRunPhase::Preparation,
                detail,
            )
        })?
        .to_string_lossy()
        .into_owned();
    prepared.command.args = go_dependency_arguments();
    prepared.command.allow_network = true;
    let output = run_with_runtime_identity(prepared, "Go dependency preparation")
        .await
        .map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Preparation,
                detail,
            )
        })?;
    require_dependency_preparation_success(spec, output)
}

fn go_dependency_arguments() -> Vec<String> {
    vec!["mod".to_string(), "download".to_string(), "all".to_string()]
}

fn go_dependency_program(installed: &InstalledIndexer) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        fs::canonicalize(installed.root.join("bin").join("go.exe")).map_err(|error| {
            format!(
                "sandbox-compatible Go command is missing from the sealed scip-go installation: {error}"
            )
        })
    }
    #[cfg(not(windows))]
    {
        let _ = installed;
        resolve_runtime("go")
    }
}

fn require_dependency_preparation_success(
    spec: PinnedIndexer,
    output: crate::sandbox::SandboxOutput,
) -> Result<(), SemanticIndexerRunFailure> {
    if output.timed_out {
        return Err(indexer_process_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::Preparation,
            format!(
                "{} dependency preparation timed out after {}",
                spec.display_name,
                format_timeout(index_timeout())
            ),
            output,
        ));
    }
    if output.status_code == Some(0) {
        return Ok(());
    }
    let kind = if output.status_code.is_some() {
        // Preparation depends on external registries. A nonzero result cannot
        // safely become a repository label without typed registry evidence.
        SemanticIndexerRunFailureKind::InfrastructureUnavailable
    } else {
        SemanticIndexerRunFailureKind::InfrastructureFailed
    };
    Err(indexer_process_failure(
        spec,
        kind,
        SemanticIndexerRunPhase::Preparation,
        format!(
            "{} dependency preparation failed with {}; output: {}",
            spec.display_name,
            output
                .status_code
                .map_or_else(|| "signal".to_string(), |status| status.to_string()),
            compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
        ),
        output,
    ))
}

#[cfg(windows)]
fn prepare_windows_python_environment(directory: &Path) -> Result<PathBuf, String> {
    // scip-python accepts an explicit environment manifest. Keeping this
    // empty on Windows avoids unbounded host `pip` discovery inside the
    // AppContainer; external package facts remain unresolved, never guessed.
    let path = directory.join("python-environment.json");
    fs::write(&path, b"[]").map_err(|error| {
        format!(
            "failed to write explicit Python environment manifest {}: {error}",
            path.display()
        )
    })?;
    Ok(path)
}

fn stage_node_runtime(root: &Path, runtime: &Path) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let staged = root.join(INDEXER_TEMP_DIR).join("node.exe");
        fs::copy(runtime, &staged).map_err(|error| {
            format!(
                "failed to stage Node runtime {} into {}: {error}",
                runtime.display(),
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
    #[cfg(not(windows))]
    {
        let _ = root;
        Ok(runtime.to_path_buf())
    }
}

async fn run_sandbox_command(
    sandbox_command: SandboxCommand,
    indexer_name: &str,
) -> Result<crate::sandbox::SandboxOutput, String> {
    match tokio::task::spawn_blocking(move || crate::sandbox::run(&sandbox_command)).await {
        Err(error) => Err(format!("{} indexing worker failed: {error}", indexer_name)),
        Ok(Err(error)) => Err(format!(
            "{} indexing could not start in the sandbox: {error}",
            indexer_name
        )),
        Ok(Ok(output)) => Ok(output),
    }
}

async fn run_with_runtime_identity(
    prepared: PreparedIndexerCommand,
    indexer_name: &str,
) -> Result<crate::sandbox::SandboxOutput, String> {
    let PreparedIndexerCommand {
        command,
        runtime_files,
    } = prepared;
    let before = runtime_file_identities(&runtime_files)?;
    let run_result = run_sandbox_command(command, indexer_name).await;
    let integrity_result = runtime_file_identities(&runtime_files)
        .and_then(|after| verify_runtime_identities_unchanged(indexer_name, &before, &after));
    combine_run_and_integrity(run_result, integrity_result)
}

fn combine_run_and_integrity<T>(
    run_result: Result<T, String>,
    integrity_result: Result<(), String>,
) -> Result<T, String> {
    match (run_result, integrity_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(run_error), Err(integrity_error)) => {
            Err(format!("{run_error}; additionally, {integrity_error}"))
        }
    }
}

fn runtime_file_identities(paths: &[PathBuf]) -> Result<Vec<RuntimeFileIdentity>, String> {
    let mut canonical_paths = paths
        .iter()
        .map(|path| {
            fs::canonicalize(path).map_err(|error| {
                format!(
                    "failed to resolve executable runtime {} for identity verification: {error}",
                    path.display()
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    canonical_paths.sort();
    canonical_paths.dedup();

    let mut total_bytes = 0u64;
    let mut identities = Vec::with_capacity(canonical_paths.len());
    for path in canonical_paths {
        let mut file = fs::File::open(&path).map_err(|error| {
            format!(
                "failed to open executable runtime {} for identity verification: {error}",
                path.display()
            )
        })?;
        let metadata = file.metadata().map_err(|error| {
            format!(
                "failed to inspect executable runtime {} for identity verification: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file() {
            return Err(format!(
                "executable runtime is not a regular file: {}",
                path.display()
            ));
        }
        let length = metadata.len();
        if length > MAX_RUNTIME_IDENTITY_FILE_BYTES {
            return Err(format!(
                "executable runtime exceeds the {} byte identity limit: {}",
                MAX_RUNTIME_IDENTITY_FILE_BYTES,
                path.display()
            ));
        }
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or_else(|| "executable runtime identity byte count overflowed".to_string())?;
        if total_bytes > MAX_RUNTIME_IDENTITY_TOTAL_BYTES {
            return Err(format!(
                "executable runtimes exceed the {} byte aggregate identity limit",
                MAX_RUNTIME_IDENTITY_TOTAL_BYTES
            ));
        }

        let mut digest = Sha256::new();
        let mut bytes_read = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|error| {
                format!(
                    "failed to hash executable runtime {}: {error}",
                    path.display()
                )
            })?;
            if count == 0 {
                break;
            }
            bytes_read = bytes_read
                .checked_add(count as u64)
                .ok_or_else(|| "executable runtime hash byte count overflowed".to_string())?;
            digest.update(&buffer[..count]);
        }
        let length_after = file
            .metadata()
            .map_err(|error| {
                format!(
                    "failed to re-inspect executable runtime {} after hashing: {error}",
                    path.display()
                )
            })?
            .len();
        if bytes_read != length || length_after != length {
            return Err(format!(
                "executable runtime changed while its identity was being verified: {}",
                path.display()
            ));
        }
        identities.push(RuntimeFileIdentity {
            path,
            length,
            sha256: format!("{:x}", digest.finalize()),
        });
    }
    Ok(identities)
}

fn verify_runtime_identities_unchanged(
    indexer_name: &str,
    before: &[RuntimeFileIdentity],
    after: &[RuntimeFileIdentity],
) -> Result<(), String> {
    let before_by_path = before
        .iter()
        .map(|identity| (&identity.path, identity))
        .collect::<BTreeMap<_, _>>();
    let after_by_path = after
        .iter()
        .map(|identity| (&identity.path, identity))
        .collect::<BTreeMap<_, _>>();

    for (path, expected) in &before_by_path {
        let Some(actual) = after_by_path.get(path) else {
            return Err(format!(
                "{indexer_name} executable runtime disappeared or resolved elsewhere while indexing: {}",
                path.display()
            ));
        };
        if expected.length != actual.length || expected.sha256 != actual.sha256 {
            return Err(format!(
                "{indexer_name} executable runtime changed while indexing: {}",
                path.display()
            ));
        }
    }
    if let Some(path) = after_by_path
        .keys()
        .find(|path| !before_by_path.contains_key(*path))
    {
        return Err(format!(
            "{indexer_name} executable runtime resolved to an unexpected file after indexing: {}",
            path.display()
        ));
    }
    Ok(())
}

fn build_indexer_sandbox_command(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
    arguments: Vec<String>,
    workspace: Option<&TemporaryIndexerWorkspace>,
) -> Result<PreparedIndexerCommand, String> {
    let installed_root = fs::canonicalize(&installed.root).map_err(|error| {
        format!(
            "failed to resolve {} installation root {}: {error}",
            spec.display_name,
            installed.root.display()
        )
    })?;
    let entrypoint = fs::canonicalize(&installed.entrypoint).map_err(|error| {
        format!(
            "failed to resolve {} entrypoint {}: {error}",
            spec.display_name,
            installed.entrypoint.display()
        )
    })?;
    let mut env = private_indexer_environment(root)?;
    #[cfg(windows)]
    let gradle_child = if spec.kind == SemanticIndexerKind::Kotlin {
        let workspace = workspace.ok_or_else(|| {
            "Windows Kotlin indexing requires a prepared Gradle workspace".to_string()
        })?;
        Some(gradle_windows::prepare_child_classpath(
            workspace.gradle_overlay_directory.as_deref(),
            &workspace.gradle_launcher_jar,
            workspace.gradle_main_class,
            &entrypoint,
        )?)
    } else {
        None
    };
    let (program, mut args, runtime_path) = match spec.runtime {
        IndexerRuntime::NodeScript => {
            let node = stage_node_runtime(root, &resolve_runtime("node")?)?;
            let mut args = Vec::new();
            if cfg!(windows) {
                // AppContainers cannot inspect a volume root. These flags keep
                // CommonJS resolution on the explicitly granted paths instead
                // of canonicalizing every module through that root.
                args.push("--preserve-symlinks".to_string());
                args.push("--preserve-symlinks-main".to_string());
                args.push("-e".to_string());
                args.push(
                    if spec.kind == SemanticIndexerKind::Python {
                        WINDOWS_SCIP_PYTHON_BOOTSTRAP
                    } else {
                        WINDOWS_SCIP_NODE_BOOTSTRAP
                    }
                    .to_string(),
                );
                args.push(windows_node_entrypoint_argument(root, &entrypoint)?);
            } else {
                args.push(entrypoint.to_string_lossy().to_string());
            }
            (node.to_string_lossy().to_string(), args, node)
        }
        IndexerRuntime::Native => (
            entrypoint.to_string_lossy().to_string(),
            Vec::new(),
            entrypoint.clone(),
        ),
        IndexerRuntime::JavaJar => {
            let java = resolve_java_runtime()?;
            let mut args = private_indexer_jvm_arguments(root).to_vec();
            #[cfg(windows)]
            if spec.kind == SemanticIndexerKind::Kotlin {
                let patch_dir = entrypoint
                    .parent()
                    .ok_or_else(|| "scip-java entrypoint has no parent directory".to_string())?
                    .join("scip-java-v0.13.1-patch");
                args.extend([
                    "-cp".to_string(),
                    gradle_windows::java_classpath(&patch_dir, &entrypoint),
                    "coursier.bootstrap.launcher.ResourcesLauncher".to_string(),
                ]);
            } else {
                args.extend(["-jar".to_string(), entrypoint.to_string_lossy().to_string()]);
            }
            #[cfg(not(windows))]
            args.extend(["-jar".to_string(), entrypoint.to_string_lossy().to_string()]);
            (java.clone().to_string_lossy().to_string(), args, java)
        }
    };
    args.extend(
        arguments
            .into_iter()
            .map(|argument| sandbox_repository_argument(root, &argument)),
    );

    let runtime_root = if spec.runtime == IndexerRuntime::NodeScript {
        runtime_path.parent().unwrap_or(&runtime_path).to_path_buf()
    } else {
        runtime_mount_root(&runtime_path)
    };
    let mut read_only_paths = Vec::new();
    let mut persistent_read_only_paths = Vec::new();
    let mut executable_paths = Vec::new();
    #[cfg(windows)]
    let mut windows_virtualized_paths = Vec::new();
    push_external_read_only(
        root,
        &mut persistent_read_only_paths,
        installed_root.clone(),
    );
    #[cfg(windows)]
    if spec.runtime == IndexerRuntime::JavaJar {
        configure_windows_runtime_images(
            root,
            &mut executable_paths,
            &mut windows_virtualized_paths,
            &runtime_root,
        )?;
    }
    push_external_read_only(root, &mut persistent_read_only_paths, runtime_root);
    for dependency in runtime_dependency_paths(&runtime_path)? {
        push_external_read_only(root, &mut persistent_read_only_paths, dependency);
    }
    let mut path_prefixes = Vec::new();
    let mut runtime_files = vec![runtime_path.clone()];
    env.push(("SNIFF_INTERNAL_INDEXER".to_string(), "1".to_string()));
    if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
        env.push(("SNIFF_DEBUG_INDEXERS".to_string(), "1".to_string()));
    }
    if cfg!(windows) && spec.runtime == IndexerRuntime::NodeScript {
        env.push((
            "NODE_PATH".to_string(),
            installed_root
                .join("node_modules")
                .to_string_lossy()
                .into_owned(),
        ));
    }
    #[cfg(target_os = "macos")]
    if spec.kind == SemanticIndexerKind::Python
        && let Some(developer_dir) = macos_developer_directory()
    {
        push_external_read_only(root, &mut persistent_read_only_paths, developer_dir.clone());
        env.push((
            "DEVELOPER_DIR".to_string(),
            developer_dir.to_string_lossy().to_string(),
        ));
    }
    if spec.kind == SemanticIndexerKind::Go {
        let go = resolve_runtime("go")?;
        runtime_files.push(go.clone());
        let go_root = runtime_mount_root(&go);
        push_external_read_only(root, &mut persistent_read_only_paths, go_root.clone());
        #[cfg(windows)]
        {
            let sandbox_go = fs::canonicalize(installed_root.join("bin").join("go.exe"))
                .map_err(|error| {
                    format!(
                        "sandbox-compatible Go command is missing from the sealed scip-go installation: {error}"
                    )
                })?;
            push_external_read_only(root, &mut executable_paths, sandbox_go.clone());
            runtime_files.push(sandbox_go.clone());
            collect_windows_runtime_images(
                root,
                &mut executable_paths,
                &go_root.join("pkg").join("tool"),
            )?;
            path_prefixes.push(runtime_bin_directory(&sandbox_go, "sandbox Go")?);
        }
        path_prefixes.push(runtime_bin_directory(&go, "go")?);
        env.extend(go_sandbox_environment(root, &go_root));
    }
    if spec.kind == SemanticIndexerKind::Rust {
        #[cfg(windows)]
        let cargo = fs::canonicalize(installed_root.join("bin").join("cargo.exe"))
            .map(strip_windows_verbatim_prefix)
            .map_err(|error| {
                format!(
                    "Windows rust-analyzer bundle is missing its pinned Cargo companion: {error}"
                )
            })?;
        #[cfg(not(windows))]
        let cargo = resolve_rust_compiler_runtime("cargo")?;
        let rustc = resolve_rust_compiler_runtime("rustc")?;
        runtime_files.extend([cargo.clone(), rustc.clone()]);
        #[cfg(windows)]
        {
            let cargo_toolchain = runtime_mount_root(&cargo);
            let rustc_toolchain = runtime_mount_root(&rustc);
            for toolchain in [&cargo_toolchain, &rustc_toolchain] {
                collect_windows_runtime_images(root, &mut executable_paths, toolchain)?;
                windows_virtualized_paths.push(toolchain.clone());
            }
        }
        for (name, runtime) in [("cargo", &cargo), ("rustc", &rustc)] {
            let runtime_root = runtime_mount_root(runtime);
            push_external_read_only(root, &mut persistent_read_only_paths, runtime_root);
            #[cfg(windows)]
            {
                push_external_read_only(root, &mut executable_paths, runtime.clone());
                push_external_read_only(
                    root,
                    &mut executable_paths,
                    runtime
                        .parent()
                        .ok_or_else(|| format!("Rust {name} runtime has no parent directory"))?
                        .to_path_buf(),
                );
            }
            path_prefixes.push(runtime_bin_directory(runtime, name)?);
        }
        #[cfg(windows)]
        env.extend([
            ("CARGO".to_string(), external_runtime_path_value(&cargo)),
            ("RUSTC".to_string(), external_runtime_path_value(&rustc)),
        ]);
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_dir())
            .or_else(|| {
                cargo
                    .parent()
                    .and_then(Path::parent)
                    .map(Path::to_path_buf)
                    .filter(|path| path.is_dir())
            });
        if let Some(cargo_home) = cargo_home {
            push_external_read_only(root, &mut persistent_read_only_paths, cargo_home.clone());
            env.push((
                "CARGO_HOME".to_string(),
                cargo_home.to_string_lossy().to_string(),
            ));
            let rustup_home = std::env::var_os("RUSTUP_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_dir())
                .or_else(|| {
                    cargo_home
                        .parent()
                        .map(|path| path.join(".rustup"))
                        .filter(|path| path.is_dir())
                });
            if let Some(rustup_home) = rustup_home {
                push_external_read_only(root, &mut persistent_read_only_paths, rustup_home.clone());
                env.push((
                    "RUSTUP_HOME".to_string(),
                    rustup_home.to_string_lossy().to_string(),
                ));
            }
        }
    }
    let gradle_jvm_args = if spec.kind == SemanticIndexerKind::Kotlin {
        let gradle = resolve_runtime("gradle")?;
        runtime_files.push(gradle.clone());
        let gradle_jvm_args = gradle_indexer_jvm_args(&gradle)?;
        let gradle_root = runtime_mount_root(&gradle);
        push_external_read_only(root, &mut persistent_read_only_paths, gradle_root);
        #[cfg(windows)]
        push_external_read_only(root, &mut executable_paths, gradle.clone());
        path_prefixes.push(runtime_bin_directory(&gradle, "gradle")?);
        Some(gradle_jvm_args)
    } else {
        None
    };
    let temp_directory =
        sandbox_repository_argument(root, &root.join(INDEXER_TEMP_DIR).to_string_lossy());
    env.extend([
        ("TMPDIR".to_string(), temp_directory.clone()),
        ("TMP".to_string(), temp_directory.clone()),
        ("TEMP".to_string(), temp_directory),
    ]);
    if spec.runtime == IndexerRuntime::JavaJar {
        let java_home = runtime_path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "Java runtime has no JAVA_HOME parent".to_string())?;
        env.push((
            "JAVA_HOME".to_string(),
            external_runtime_path_value(java_home),
        ));
    }
    if let Some(workspace) = workspace {
        read_only_paths.push(fs::canonicalize(&workspace.directory).map_err(|error| {
            format!(
                "failed to resolve temporary indexer workspace {}: {error}",
                workspace.directory.display()
            )
        })?);
        #[cfg(windows)]
        if let Some(overlay) = gradle_child
            .as_ref()
            .and_then(|prepared| prepared.read_only_directory.as_ref())
        {
            read_only_paths.push(fs::canonicalize(overlay).map_err(|error| {
                format!(
                    "failed to resolve private Gradle runtime overlay {}: {error}",
                    overlay.display()
                )
            })?);
        }
        env.push((
            "SNIFF_INTERNAL_GRADLE_LAUNCHER".to_string(),
            "1".to_string(),
        ));
        #[cfg(windows)]
        env.push((
            "SNIFF_GRADLE_CLASSPATH".to_string(),
            gradle_child
                .as_ref()
                .ok_or_else(|| "Windows Gradle child classpath was not prepared".to_string())?
                .value
                .clone(),
        ));
        env.push((
            "SNIFF_GRADLE_MAIN_CLASS".to_string(),
            workspace.gradle_main_class.to_string(),
        ));
        env.push((
            "SNIFF_GRADLE_PROJECT".to_string(),
            sandbox_repository_argument(root, &workspace.project_root.to_string_lossy()),
        ));
        if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
            env.push((
                "SNIFF_GRADLE_TRACE".to_string(),
                sandbox_repository_argument(
                    root,
                    &root
                        .join(INDEXER_TEMP_DIR)
                        .join("gradle-launcher.log")
                        .to_string_lossy(),
                ),
            ));
        }
    }
    if spec.kind == SemanticIndexerKind::Kotlin {
        let cache_root = root.join(INDEXER_CACHE_DIR);
        let cache = sandbox_repository_argument(root, &cache_root.to_string_lossy());
        env.push(("COURSIER_CACHE".to_string(), cache.clone()));
        env.push(("COURSIER_CACHE_DIR".to_string(), cache.clone()));
        env.push(("GRADLE_USER_HOME".to_string(), cache.clone()));
        env.push(("SNIFF_GRADLE_USER_HOME".to_string(), cache.clone()));
        env.push((
            "SNIFF_GRADLE_TEMP".to_string(),
            sandbox_repository_argument(root, &root.join(INDEXER_TEMP_DIR).to_string_lossy()),
        ));
        env.push((
            "SNIFF_GRADLE_PROJECT_CACHE".to_string(),
            sandbox_repository_argument(root, &cache_root.join("project-cache").to_string_lossy()),
        ));
        env.push(("SNIFF_GRADLE_OFFLINE".to_string(), "1".to_string()));
        // Match Gradle's client JVM to org.gradle.jvmargs so --no-daemon does
        // not fork a single-use daemon that needs a network listener.
        let gradle_jvm_args = gradle_jvm_args
            .as_deref()
            .ok_or_else(|| "Kotlin indexer Gradle JVM arguments were not prepared".to_string())?;
        env.push(("JAVA_OPTS".to_string(), gradle_jvm_args.to_string()));
        env.push(("GRADLE_OPTS".to_string(), gradle_jvm_args.to_string()));
        env.push((
            "MAVEN_USER_HOME".to_string(),
            sandbox_repository_argument(root, &cache_root.to_string_lossy()),
        ));
    }
    if !path_prefixes.is_empty() {
        path_prefixes.extend(std::env::split_paths(std::ffi::OsStr::new(sandbox_path())));
        let path = std::env::join_paths(path_prefixes)
            .map_err(|error| format!("failed to build sandbox PATH: {error}"))?;
        env.push(("PATH".to_string(), path.to_string_lossy().to_string()));
    }
    read_only_paths.sort();
    read_only_paths.dedup();
    persistent_read_only_paths.sort();
    persistent_read_only_paths.dedup();
    executable_paths.sort();
    executable_paths.dedup();
    #[cfg(windows)]
    if matches!(
        spec.kind,
        SemanticIndexerKind::Kotlin | SemanticIndexerKind::Rust
    ) {
        windows_virtualized_paths.push(root.to_path_buf());
    }
    #[cfg(windows)]
    {
        windows_virtualized_paths.sort();
        windows_virtualized_paths.dedup();
    }
    let mut writable_paths = vec![root.join(INDEXER_TEMP_DIR)];
    if spec.kind == SemanticIndexerKind::Kotlin {
        let cache = root.join(INDEXER_CACHE_DIR);
        writable_paths.extend([
            cache.clone(),
            cache.join(".tmp"),
            cache.join("project-cache"),
        ]);
    }

    runtime_files.sort();
    runtime_files.dedup();
    Ok(PreparedIndexerCommand {
        command: SandboxCommand {
            root: root.to_path_buf(),
            workdir: PathBuf::from("."),
            program,
            args,
            read_only_paths,
            writable_paths,
            persistent_read_only_paths,
            executable_paths,
            #[cfg(windows)]
            windows_virtualized_paths,
            env,
            allow_network: false,
            #[cfg(target_os = "macos")]
            allow_local_network: spec.kind == SemanticIndexerKind::Kotlin,
            timeout: index_timeout(),
            output_limit: MAX_PROCESS_OUTPUT,
            memory_limit: INDEXER_MEMORY_LIMIT,
            process_limit: INDEXER_PROCESS_LIMIT,
        },
        runtime_files,
    })
}

fn gradle_launcher_trace(root: &Path) -> String {
    const LIMIT: u64 = 8 * 1024;
    let path = root.join(INDEXER_TEMP_DIR).join("gradle-launcher.log");
    let Ok(file) = fs::File::open(&path) else {
        return "not emitted (the Gradle launcher process did not enter Sniff)".to_string();
    };
    let mut bytes = Vec::new();
    if std::io::Read::take(file, LIMIT + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return format!("could not read {}", path.display());
    }
    if bytes.len() > LIMIT as usize {
        bytes.truncate(LIMIT as usize);
        bytes.extend_from_slice(b"\n[trace truncated]");
    }
    String::from_utf8_lossy(&bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn push_external_read_only(root: &Path, paths: &mut Vec<PathBuf>, path: PathBuf) {
    let path = strip_windows_verbatim_prefix(path);
    let root = strip_windows_verbatim_prefix(root.to_path_buf());
    if !path.starts_with(&root) {
        paths.push(path);
    }
}

#[cfg(windows)]
fn collect_windows_runtime_images(
    repository_root: &Path,
    executable_paths: &mut Vec<PathBuf>,
    runtime_root: &Path,
) -> Result<(), String> {
    const MAX_RUNTIME_ENTRIES: usize = 100_000;
    const MAX_RUNTIME_IMAGES: usize = 4_096;

    if !runtime_root.is_dir() {
        return Err(format!(
            "Windows compiler runtime directory is missing: {}",
            runtime_root.display()
        ));
    }
    let mut pending = vec![runtime_root.to_path_buf()];
    let mut entries_seen = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            format!(
                "failed to inspect Windows compiler runtime {}: {error}",
                directory.display()
            )
        })? {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to enumerate Windows compiler runtime {}: {error}",
                    directory.display()
                )
            })?;
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > MAX_RUNTIME_ENTRIES {
                return Err(format!(
                    "Windows compiler runtime exceeds {MAX_RUNTIME_ENTRIES} entries: {}",
                    runtime_root.display()
                ));
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "failed to inspect Windows compiler runtime entry {}: {error}",
                    path.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "Windows compiler runtime contains a symlink and cannot be trusted for execution: {}",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && path.extension().is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("exe") || extension.eq_ignore_ascii_case("dll")
                })
            {
                let mut header = [0u8; 2];
                fs::File::open(&path)
                    .and_then(|mut file| file.read_exact(&mut header))
                    .map_err(|error| {
                        format!(
                            "failed to verify Windows runtime image {}: {error}",
                            path.display()
                        )
                    })?;
                if header != *b"MZ" {
                    return Err(format!(
                        "Windows runtime executable or library is not a PE image: {}",
                        path.display()
                    ));
                }
                push_external_read_only(repository_root, executable_paths, path);
                if executable_paths.len() > MAX_RUNTIME_IMAGES {
                    return Err(format!(
                        "Windows compiler runtime exceeds {MAX_RUNTIME_IMAGES} executable images: {}",
                        runtime_root.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn configure_windows_runtime_images(
    repository_root: &Path,
    executable_paths: &mut Vec<PathBuf>,
    virtualized_paths: &mut Vec<PathBuf>,
    runtime_root: &Path,
) -> Result<(), String> {
    collect_windows_runtime_images(repository_root, executable_paths, runtime_root)?;
    let virtualization_root = runtime_root.parent().ok_or_else(|| {
        format!(
            "Windows Java runtime root has no parent directory: {}",
            runtime_root.display()
        )
    })?;
    if runtime_root.file_name().is_none() {
        return Err(format!(
            "Windows Java runtime cannot be mounted at a drive root: {}",
            runtime_root.display()
        ));
    }
    virtualized_paths.push(virtualization_root.to_path_buf());
    Ok(())
}

async fn prepare_kotlin_dependency_cache(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
) -> Result<(), gradle_preparation::KotlinDependencyPreparationError> {
    let preparation_root = root
        .join(INDEXER_TEMP_DIR)
        .join("kotlin-dependency-preparation");
    gradle_preparation::stage_control_plane(root, &preparation_root)?;
    let preparation_temp = preparation_root.join(INDEXER_TEMP_DIR);
    fs::create_dir(&preparation_temp).map_err(|error| {
        format!(
            "failed to create source-minimized Kotlin preparation temp directory {}: {error}",
            preparation_temp.display()
        )
    })?;
    let preparation_cache = preparation_root.join(INDEXER_CACHE_DIR);
    fs::create_dir(&preparation_cache).map_err(|error| {
        format!(
            "failed to create source-minimized Kotlin preparation cache {}: {error}",
            preparation_cache.display()
        )
    })?;
    write_private_gradle_properties(&preparation_root, &preparation_cache)?;

    let workspace = prepare_indexer_workspace(spec, &preparation_root)?;
    let arguments =
        indexer_arguments_with_workspace(spec, &preparation_root, None, workspace.as_ref());
    let command = build_indexer_sandbox_command(
        spec,
        &preparation_root,
        installed,
        arguments,
        workspace.as_ref(),
    );
    let output = match command {
        Ok(mut command) => {
            command.command.allow_network = true;
            command
                .command
                .env
                .retain(|(name, _)| name != "SNIFF_GRADLE_OFFLINE");
            if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
                eprintln!(
                    "[sniff] source-minimized dependency preparation start: {}",
                    spec.display_name
                );
            }
            run_with_runtime_identity(command, spec.display_name).await
        }
        Err(error) => Err(error),
    };
    let workspace_cleanup = workspace
        .map(|workspace| workspace.cleanup(spec.display_name))
        .transpose();
    let output = match (output, workspace_cleanup) {
        (Ok(output), Ok(_)) => output,
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => return Err(error.into()),
        (Err(error), Err(cleanup)) => {
            return Err(format!("{error}; additionally, {cleanup}").into());
        }
    };
    if output.timed_out || output.status_code != Some(0) {
        return Err(format!(
            "{} source-minimized dependency preparation failed with {}; output: {}; launcher trace: {}",
            spec.display_name,
            if output.timed_out {
                format!("a timeout after {}", format_timeout(index_timeout()))
            } else {
                output
                    .status_code
                    .map_or_else(|| "a signal".to_string(), |status| status.to_string())
            },
            compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes()),
            gradle_launcher_trace(&preparation_root)
        )
        .into());
    }

    let preparation_index = preparation_root.join("index.scip");
    if let Err(error) = fs::remove_file(&preparation_index)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!(
            "{} dependency preparation emitted an index that could not be cleared: {error}",
            spec.display_name
        )
        .into());
    }
    gradle_preparation::transfer_cache(&preparation_cache, &root.join(INDEXER_CACHE_DIR))
        .map_err(gradle_preparation::KotlinDependencyPreparationError::from)
}

fn kotlin_dependency_preparation_failure(
    spec: PinnedIndexer,
    error: gradle_preparation::KotlinDependencyPreparationError,
) -> SemanticIndexerRunFailure {
    let (kind, detail) = match error {
        gradle_preparation::KotlinDependencyPreparationError::RepositoryRejected(detail) => {
            (SemanticIndexerRunFailureKind::RepositoryRejected, detail)
        }
        gradle_preparation::KotlinDependencyPreparationError::InfrastructureFailed(detail) => {
            (SemanticIndexerRunFailureKind::InfrastructureFailed, detail)
        }
    };
    indexer_failure(spec, kind, SemanticIndexerRunPhase::Preparation, detail)
}

fn windows_node_entrypoint_argument(root: &Path, entrypoint: &Path) -> Result<String, String> {
    Ok(entrypoint.strip_prefix(root).map_or_else(
        |_| entrypoint.to_string_lossy().into_owned(),
        |relative| format!(r".\{}", relative.to_string_lossy()),
    ))
}

fn index_timeout() -> Duration {
    #[cfg(debug_assertions)]
    if let Ok(value) = std::env::var(INDEXER_TIMEOUT_ENV)
        && let Ok(seconds) = value.parse::<u64>()
        && seconds > 0
    {
        return Duration::from_secs(seconds);
    }
    INDEX_TIMEOUT
}

fn format_timeout(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 60 && seconds.is_multiple_of(60) {
        let minutes = seconds / 60;
        let unit = if minutes == 1 { "minute" } else { "minutes" };
        format!("{minutes} {unit}")
    } else {
        format!("{seconds} seconds")
    }
}

fn write_private_gradle_properties(root: &Path, cache_root: &Path) -> Result<(), String> {
    for directory in [cache_root.join(".tmp"), cache_root.join("project-cache")] {
        fs::create_dir(&directory).map_err(|error| {
            format!(
                "failed to create private Gradle directory {}: {error}",
                directory.display()
            )
        })?;
    }
    let home = sandbox_repository_argument(root, &root.to_string_lossy()).replace('\\', "\\\\");
    let project_cache =
        sandbox_repository_argument(root, &cache_root.join("project-cache").to_string_lossy())
            .replace('\\', "\\\\");
    fs::write(
        cache_root.join("gradle.properties"),
        format!(
            "systemProp.user.home={home}\norg.gradle.daemon=false\norg.gradle.parallel=false\norg.gradle.vfs.watch=false\norg.gradle.workers.max=32\norg.gradle.projectcachedir={project_cache}\n"
        ),
    )
    .map_err(|error| {
        format!(
            "failed to create private Gradle properties in {}: {error}",
            cache_root.display()
        )
    })
}

fn gradle_indexer_jvm_args(gradle: &Path) -> Result<String, String> {
    let installation = gradle.parent().and_then(Path::parent).ok_or_else(|| {
        format!(
            "Gradle runtime has no installation root: {}",
            gradle.display()
        )
    })?;
    let agents = installation.join("lib").join("agents");
    let mut matches = fs::read_dir(&agents)
        .map_err(|error| {
            format!(
                "failed to inspect Gradle instrumentation agents in {}: {error}",
                agents.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "failed to read Gradle instrumentation agents in {}: {error}",
                agents.display()
            )
        })?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("gradle-instrumentation-agent-") && name.ends_with(".jar")
                    })
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "expected exactly one Gradle instrumentation agent in {}, found {}",
            agents.display(),
            matches.len()
        ));
    }
    let agent = fs::canonicalize(matches.pop().expect("one agent was found")).map_err(|error| {
        format!(
            "failed to resolve Gradle instrumentation agent in {}: {error}",
            agents.display()
        )
    })?;
    Ok(format!(
        "{GRADLE_INDEXER_BASE_JVM_ARGS} -javaagent:{}",
        external_runtime_path_value(&agent)
    ))
}

fn runtime_bin_directory(runtime: &Path, name: &str) -> Result<PathBuf, String> {
    runtime
        .parent()
        .ok_or_else(|| format!("{name} runtime has no parent directory"))
        .map(Path::to_path_buf)
}

#[cfg(target_os = "macos")]
fn macos_developer_directory() -> Option<PathBuf> {
    let output = Command::new("xcode-select").arg("-p").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.is_dir().then_some(path)
}

#[cfg(target_os = "macos")]
fn runtime_dependency_paths(runtime: &Path) -> Result<Vec<PathBuf>, String> {
    let output = Command::new("otool")
        .arg("-L")
        .arg(runtime)
        .output()
        .map_err(|error| {
            format!(
                "failed to inspect runtime dependencies for {}: {error}",
                runtime.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "otool could not inspect runtime dependencies for {}",
            runtime.display()
        ));
    }
    let mut paths = Vec::new();
    for dependency in String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .filter(|path| path.starts_with('/'))
        .filter(|path| {
            !path.starts_with("/usr/")
                && !path.starts_with("/System/")
                && !path.starts_with("/Library/")
                && !path.starts_with("/private/")
        })
    {
        let dependency = PathBuf::from(dependency);
        if !dependency.is_file() {
            return Err(format!(
                "runtime dependency is unavailable: {}",
                dependency.display()
            ));
        }
        if let Some(parent) = dependency.parent() {
            paths.push(parent.to_path_buf());
            paths.push(macos_dependency_mount_root(parent));
        }
    }
    let homebrew_root = Path::new("/opt/homebrew");
    if runtime.starts_with(homebrew_root) && homebrew_root.is_dir() {
        paths.push(homebrew_root.to_path_buf());
    }
    Ok(paths)
}

#[cfg(target_os = "macos")]
fn macos_dependency_mount_root(path: &Path) -> PathBuf {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if std::fs::symlink_metadata(&current)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return current.parent().unwrap_or(path).to_path_buf();
        }
    }
    path.to_path_buf()
}

#[cfg(not(target_os = "macos"))]
fn runtime_dependency_paths(_runtime: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(Vec::new())
}

fn resolve_runtime(name: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| format!("{} runtime is unavailable because PATH is not set", name))?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return fs::canonicalize(&candidate).map_err(|error| {
                format!(
                    "failed to resolve {} runtime {}: {error}",
                    name,
                    candidate.display()
                )
            });
        }
        #[cfg(windows)]
        {
            let candidate = directory.join(format!("{name}.exe"));
            if candidate.is_file() {
                return fs::canonicalize(&candidate).map_err(|error| {
                    format!(
                        "failed to resolve {} runtime {}: {error}",
                        name,
                        candidate.display()
                    )
                });
            }
        }
    }
    Err(format!(
        "{} runtime is required for semantic indexing",
        name
    ))
}

#[cfg(not(windows))]
fn resolve_rust_compiler_runtime(name: &str) -> Result<PathBuf, String> {
    resolve_runtime(name)
}

#[cfg(windows)]
fn resolve_rust_compiler_runtime(name: &str) -> Result<PathBuf, String> {
    let rustup = resolve_runtime("rustup")?;
    let output = std::process::Command::new(&rustup)
        .args(["which", name])
        .output()
        .map_err(|error| format!("failed to resolve active Rust {name} through rustup: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustup could not resolve the active Rust {name}: {}",
            compact_process_output(&output.stdout, &output.stderr)
        ));
    }
    if !output.stderr.is_empty() {
        return Err(format!(
            "rustup emitted unexpected stderr while resolving Rust {name}: {}",
            compact_process_output(&[], &output.stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| format!("rustup returned a non-UTF-8 path for Rust {name}"))?;
    let mut lines = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let path = lines
        .next()
        .ok_or_else(|| format!("rustup returned no path for Rust {name}"))?;
    if lines.next().is_some() {
        return Err(format!(
            "rustup returned multiple paths for Rust {name}; refusing an ambiguous toolchain"
        ));
    }
    let path = fs::canonicalize(path)
        .map(strip_windows_verbatim_prefix)
        .map_err(|error| format!("failed to resolve active Rust {name} at {path}: {error}"))?;
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_none_or(|value| !value.eq_ignore_ascii_case(&format!("{name}.exe")))
    {
        return Err(format!(
            "rustup resolved Rust {name} to an unexpected executable: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn runtime_mount_root(runtime: &Path) -> PathBuf {
    runtime
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| runtime.parent().unwrap_or(runtime))
        .to_path_buf()
}

#[cfg(target_os = "linux")]
fn sandbox_repository_argument(root: &Path, argument: &str) -> String {
    let path = Path::new(argument);
    let Ok(relative) = path.strip_prefix(root) else {
        return argument.to_string();
    };
    Path::new("/workspace")
        .join(relative)
        .to_string_lossy()
        .to_string()
}

#[cfg(not(target_os = "linux"))]
fn sandbox_repository_argument(_root: &Path, argument: &str) -> String {
    argument.to_string()
}

fn source_integrity_digest(files: &[FileRecord]) -> Result<String, String> {
    let mut paths = files
        .iter()
        .map(|file| PathBuf::from(&file.file_path))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();

    let mut digest = Sha256::new();
    for path in paths {
        let bytes = fs::read(&path).map_err(|error| {
            format!(
                "failed to hash eligible source file {}: {error}",
                path.display()
            )
        })?;
        let path_text = path.to_string_lossy();
        digest.update(path_text.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
fn reject_unsupported_android_gradle(root: &Path, files: &[FileRecord]) -> Result<(), String> {
    reject_unsupported_android_gradle_typed(root, files).map_err(|failure| failure.detail)
}

fn reject_unsupported_android_gradle_typed(
    root: &Path,
    files: &[FileRecord],
) -> Result<(), SemanticIndexerRunFailure> {
    let kind = Some(SemanticIndexerKind::Kotlin);
    let root = fs::canonicalize(root).map_err(|error| {
        failure(
            SemanticIndexerRunFailureKind::InvalidInput,
            SemanticIndexerRunPhase::RepositoryValidation,
            kind,
            format!("failed to resolve repository root for Kotlin Gradle capability: {error}"),
        )
    })?;
    let mut directories = BTreeSet::new();
    for file in files {
        if language_kind(file) != Some(SemanticIndexerKind::Kotlin) {
            continue;
        }
        let path = fs::canonicalize(&file.file_path).map_err(|error| {
            failure(
                SemanticIndexerRunFailureKind::InvalidInput,
                SemanticIndexerRunPhase::RepositoryValidation,
                kind,
                format!(
                    "failed to inspect Kotlin source {} for Gradle capability: {error}",
                    file.file_path
                ),
            )
        })?;
        let mut directory = path.parent();
        while let Some(current) = directory {
            if !current.starts_with(&root) {
                return Err(failure(
                    SemanticIndexerRunFailureKind::InvalidInput,
                    SemanticIndexerRunPhase::RepositoryValidation,
                    kind,
                    format!(
                        "Kotlin source {} is outside the semantic repository root",
                        file.file_path
                    ),
                ));
            }
            directories.insert(current.to_path_buf());
            if current == root.as_path() {
                break;
            }
            directory = current.parent();
        }
    }

    for directory in directories {
        for name in ["build.gradle.kts", "build.gradle"] {
            let path = directory.join(name);
            if !path.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(&root)
                .map(|path| path.to_string_lossy().replace('\\', "/"))
                .map_err(|error| {
                    failure(
                        SemanticIndexerRunFailureKind::InvalidInput,
                        SemanticIndexerRunPhase::RepositoryValidation,
                        kind,
                        format!("Gradle build script escaped the repository root: {error}"),
                    )
                })?;
            let source = fs::read_to_string(&path).map_err(|error| {
                failure(
                    SemanticIndexerRunFailureKind::InfrastructureFailed,
                    SemanticIndexerRunPhase::RepositoryValidation,
                    kind,
                    format!(
                        "failed to inspect Gradle build script {relative} for Kotlin capability: {error}"
                    ),
                )
            })?;
            if gradle_script_uses_android(&source) {
                return Err(failure(
                    SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                    SemanticIndexerRunPhase::RepositoryValidation,
                    kind,
                    format!(
                        "scip-java does not support Android Gradle integration; detected Android module {relative}. Sniff refuses a weaker Kotlin graph provider"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn gradle_script_uses_android(source: &str) -> bool {
    source.lines().any(|line| {
        let line = line.trim();
        line.starts_with("android {")
            || line.starts_with("androidLibrary {")
            || line.starts_with("androidTarget(")
            || ((line.contains("com.android.application")
                || line.contains("com.android.library")
                || line.contains("com.android.kotlin.multiplatform.library"))
                && !line.contains("apply false"))
    })
}

fn indexer_arguments_with_project(
    spec: PinnedIndexer,
    root: &Path,
    extra_project: Option<&Path>,
) -> Vec<String> {
    match spec.kind {
        SemanticIndexerKind::TypeScriptJavaScript => {
            let mut arguments = vec!["index".to_string()];
            let has_typescript = root.join("tsconfig.json").is_file();
            if let Some(extra_project) = extra_project {
                arguments.push(".".to_string());
                arguments.push(extra_project.to_string_lossy().to_string());
            }
            // scip-typescript requires an explicit project when no root
            // tsconfig exists. Its inference mode is the strict compiler
            // project for standalone fixtures and mixed JS/TS repositories.
            if !has_typescript {
                arguments.push("--infer-tsconfig".to_string());
            }
            arguments
        }
        SemanticIndexerKind::Python => vec![
            "index".to_string(),
            ".".to_string(),
            "--project-name".to_string(),
            project_name(root),
            // scip-python 0.6.6 assumes a project version exists while
            // normalizing symbols. A stable synthetic version keeps
            // dependency-free repositories valid without touching them.
            "--project-version".to_string(),
            "_".to_string(),
        ],
        // Avoid scip-go's git-dependent module-root inference inside the
        // sandbox. The compiler still resolves the complete module graph.
        SemanticIndexerKind::Go => vec![
            "--module-root".to_string(),
            ".".to_string(),
            "./...".to_string(),
        ],
        SemanticIndexerKind::Kotlin => vec!["index".to_string()],
        SemanticIndexerKind::Rust => vec!["scip".to_string(), ".".to_string()],
    }
}

fn go_sandbox_environment(root: &Path, go_root: &Path) -> Vec<(String, String)> {
    let private_go_root = root.join(INDEXER_TEMP_DIR).join("go");
    let private_go_root = sandbox_repository_argument(root, &private_go_root.to_string_lossy());
    vec![
        // The Windows Go tool otherwise reads GOENV and GOPATH from the host
        // USERPROFILE, which is intentionally inaccessible to the AppContainer.
        ("GOENV".to_string(), "off".to_string()),
        ("GOTOOLCHAIN".to_string(), "local".to_string()),
        ("GOROOT".to_string(), go_root.to_string_lossy().into_owned()),
        ("GOPATH".to_string(), private_go_root.clone()),
        (
            "GOMODCACHE".to_string(),
            format!(
                "{private_go_root}{}pkg{}mod",
                std::path::MAIN_SEPARATOR,
                std::path::MAIN_SEPARATOR
            ),
        ),
        (
            "GOCACHE".to_string(),
            sandbox_repository_argument(
                root,
                &root
                    .join(INDEXER_TEMP_DIR)
                    .join("go-build")
                    .to_string_lossy(),
            ),
        ),
    ]
}

fn private_indexer_directory_argument(root: &Path, name: &str) -> String {
    sandbox_repository_argument(
        root,
        &root.join(INDEXER_TEMP_DIR).join(name).to_string_lossy(),
    )
}

fn private_indexer_jvm_arguments(root: &Path) -> [String; 2] {
    [
        format!(
            "-Duser.home={}",
            private_indexer_directory_argument(root, "home")
        ),
        format!(
            "-Djava.io.tmpdir={}",
            private_indexer_directory_argument(root, "temp")
        ),
    ]
}

fn private_indexer_environment(root: &Path) -> Result<Vec<(String, String)>, String> {
    let private_root = root.join(INDEXER_TEMP_DIR);
    let directories = [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("TEMP", "temp"),
        ("TMP", "temp"),
    ];
    let mut environment = Vec::with_capacity(directories.len());
    for (name, directory_name) in directories {
        let directory = private_root.join(directory_name);
        fs::create_dir_all(&directory).map_err(|error| {
            format!(
                "failed to create private semantic indexer {name} directory {}: {error}",
                directory.display()
            )
        })?;
        environment.push((
            name.to_string(),
            private_indexer_directory_argument(root, directory_name),
        ));
    }
    Ok(environment)
}

fn indexer_arguments_with_workspace(
    spec: PinnedIndexer,
    root: &Path,
    extra_project: Option<&Path>,
    workspace: Option<&TemporaryIndexerWorkspace>,
) -> Vec<String> {
    let arguments = indexer_arguments_with_project(spec, root, extra_project);
    let Some(workspace) = workspace else {
        return arguments;
    };

    let mut wrapped = vec![
        "--cwd".to_string(),
        workspace.directory.to_string_lossy().to_string(),
        "index".to_string(),
        "--build-tool".to_string(),
        "Gradle".to_string(),
        "--output".to_string(),
        root.join("index.scip").to_string_lossy().to_string(),
    ];
    wrapped.extend(arguments.into_iter().skip(1));
    wrapped
}

fn prepare_indexer_workspace(
    spec: PinnedIndexer,
    root: &Path,
) -> Result<Option<TemporaryIndexerWorkspace>, String> {
    if spec.kind != SemanticIndexerKind::Kotlin {
        return Ok(None);
    }

    #[cfg(windows)]
    {
        prepare_windows_kotlin_workspace(root)
    }

    #[cfg(not(windows))]
    {
        let _ = root;
        Ok(None)
    }
}

#[cfg(windows)]
fn prepare_windows_kotlin_workspace(
    root: &Path,
) -> Result<Option<TemporaryIndexerWorkspace>, String> {
    let unix_wrapper = root.join("gradlew");
    let project_gradle_wrapper = root.join("gradlew.bat");
    if unix_wrapper.is_file() && !project_gradle_wrapper.is_file() {
        return Err(format!(
            "scip-java cannot index this Windows Gradle project: {} exists but {} is missing; refusing to use a weaker system-Gradle fallback",
            unix_wrapper.display(),
            project_gradle_wrapper.display()
        ));
    }

    let directory =
        create_temporary_workspace_in(&root.join(INDEXER_TEMP_DIR), "sniff-kotlin-gradle")?;
    let result = (|| {
        fs::write(
            directory.join("build.gradle.kts"),
            "// Sniff marker: the launcher delegates the build to the target project.\r\n",
        )
        .map_err(|error| {
            format!(
                "failed to create temporary Kotlin Gradle project marker {}: {error}",
                directory.join("build.gradle.kts").display()
            )
        })?;
        fs::create_dir(directory.join("build")).map_err(|error| {
            format!(
                "failed to create temporary Kotlin Gradle output directory {}: {error}",
                directory.join("build").display()
            )
        })?;
        let (gradle_launcher_jar, gradle_main_class, gradle_overlay_directory) =
            if project_gradle_wrapper.is_file() {
                let wrapper_jar = root.join("gradle/wrapper/gradle-wrapper.jar");
                if !wrapper_jar.is_file() {
                    return Err(format!(
                        "Gradle wrapper launcher is missing at {}; refusing to execute the batch wrapper through a shell",
                        wrapper_jar.display()
                    ));
                }
                (wrapper_jar, "org.gradle.wrapper.GradleWrapperMain", None)
            } else {
                let system_gradle = find_system_gradle()?;
                (
                    system_gradle_launcher_jar(&system_gradle)?,
                    "org.gradle.launcher.GradleMain",
                    Some(create_temporary_workspace_in(
                        &root.join(INDEXER_TEMP_DIR),
                        gradle_windows::OVERLAY_DIR,
                    )?),
                )
            };
        Ok(TemporaryIndexerWorkspace {
            directory: directory.clone(),
            gradle_launcher_jar,
            gradle_overlay_directory,
            gradle_main_class,
            project_root: root.to_path_buf(),
        })
    })();

    match result {
        Ok(workspace) => Ok(Some(workspace)),
        Err(error) => {
            let _ = fs::remove_dir_all(&directory);
            Err(error)
        }
    }
}

#[cfg(windows)]
fn find_system_gradle() -> Result<PathBuf, String> {
    let output = std::process::Command::new("where.exe")
        .arg("gradle")
        .output()
        .map_err(|error| format!("could not locate system Gradle with where.exe: {error}"))?;
    if !output.status.success() {
        return Err(
            "Kotlin indexing requires gradlew.bat or a system Gradle executable; neither was found"
                .to_string(),
        );
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "where.exe reported no usable system Gradle executable".to_string())
}

#[cfg(windows)]
fn create_temporary_workspace_in(base: &Path, prefix: &str) -> Result<PathBuf, String> {
    static NEXT_WORKSPACE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let pid = std::process::id();
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
        .as_nanos();
    for attempt in 0..1000u32 {
        let sequence = NEXT_WORKSPACE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let directory = base.join(format!("{prefix}-{pid}-{started}-{sequence}-{attempt}"));
        match fs::create_dir(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "failed to create temporary semantic indexer workspace {}: {error}",
                    directory.display()
                ));
            }
        }
    }
    Err(format!(
        "failed to allocate a unique temporary semantic indexer workspace under {}",
        base.display()
    ))
}

fn prepare_mixed_typescript_javascript_project(
    spec: PinnedIndexer,
    root: &Path,
    files: &[FileRecord],
) -> Result<Option<PathBuf>, String> {
    if spec.kind != SemanticIndexerKind::TypeScriptJavaScript {
        return Ok(None);
    }
    let has_typescript = files
        .iter()
        .any(|file| file.language.eq_ignore_ascii_case("typescript"));
    let javascript_files = files
        .iter()
        .filter(|file| file.language.eq_ignore_ascii_case("javascript"))
        .map(|file| repository_relative_path(root, Path::new(&file.file_path)))
        .collect::<Result<Vec<_>, _>>()?;
    if !has_typescript || javascript_files.is_empty() {
        return Ok(None);
    }

    let path = root.join(".sniff-jsconfig.json");
    let file_list = javascript_files
        .into_iter()
        .map(|path| path.0)
        .collect::<Vec<_>>();
    let config = serde_json::json!({
        "compilerOptions": {
            "allowJs": true,
            "checkJs": false,
            "noEmit": true
        },
        "files": file_list
    });
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            format!(
                "failed to create temporary JavaScript semantic project {}: {error}",
                path.display()
            )
        })?;
    let bytes = serde_json::to_vec_pretty(&config).map_err(|error| {
        format!("failed to serialize temporary JavaScript semantic project: {error}")
    })?;
    file.write_all(&bytes).map_err(|error| {
        format!(
            "failed to write temporary JavaScript semantic project {}: {error}",
            path.display()
        )
    })?;
    Ok(Some(path))
}

#[cfg(windows)]
fn prepare_windows_python_project(
    root: &Path,
    files: &[FileRecord],
) -> Result<Option<PathBuf>, String> {
    let python_files = files
        .iter()
        .filter(|file| file.language.eq_ignore_ascii_case("python"))
        .map(|file| repository_relative_path(root, Path::new(&file.file_path)))
        .collect::<Result<Vec<_>, _>>()?;
    if python_files.is_empty() {
        return Ok(None);
    }

    let path = root.join("scip-pyrightconfig.json");
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing Python semantic config {}",
            path.display()
        ));
    }
    let config = serde_json::json!({
        "include": python_files.into_iter().map(|path| path.0).collect::<Vec<_>>()
    });
    let bytes = serde_json::to_vec_pretty(&config).map_err(|error| {
        format!("failed to serialize temporary Python semantic config: {error}")
    })?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            format!(
                "failed to create temporary Python semantic config {}: {error}",
                path.display()
            )
        })?;
    file.write_all(&bytes).map_err(|error| {
        format!(
            "failed to write temporary Python semantic config {}: {error}",
            path.display()
        )
    })?;
    Ok(Some(path))
}

fn cleanup_temporary_project(path: Option<PathBuf>, indexer_name: &str) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    fs::remove_file(&path).map_err(|error| {
        format!(
            "{} indexing completed but temporary semantic project cleanup failed for {}: {error}",
            indexer_name,
            path.display()
        )
    })
}

fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{}", rest));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path
}

fn external_runtime_path_value(path: &Path) -> String {
    strip_windows_verbatim_prefix(path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn project_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("sniff-project")
        .to_string()
}

fn validate_expected_documents(
    root: &Path,
    files: &[FileRecord],
    kind: SemanticIndexerKind,
    index: SemanticIndex,
) -> Result<SemanticIndex, String> {
    let expected = files
        .iter()
        .filter(|file| language_kind(file) == Some(kind))
        .map(|file| repository_relative_path(root, Path::new(&file.file_path)))
        .collect::<Result<Vec<_>, _>>()?;
    let missing = expected
        .into_iter()
        .filter(|path| !index.documents.contains_key(path))
        .map(|path| path.0)
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(index)
    } else {
        Err(format!(
            "{} SCIP output omitted {} eligible source document(s): {}",
            kind.display_name(),
            missing.len(),
            missing.join(", ")
        ))
    }
}

fn repository_relative_path(root: &Path, file: &Path) -> Result<RepositoryPath, String> {
    let canonical = strip_windows_verbatim_prefix(fs::canonicalize(file).map_err(|error| {
        format!(
            "failed to resolve expected semantic source {}: {error}",
            file.display()
        )
    })?);
    let normalized_root = strip_windows_verbatim_prefix(root.to_path_buf());
    let relative = canonical.strip_prefix(&normalized_root).map_err(|_| {
        format!(
            "semantic source {} is outside repository root {}",
            file.display(),
            normalized_root.display()
        )
    })?;
    let text = relative.to_string_lossy().replace('\\', "/");
    if text.is_empty() || text.starts_with("../") || text.contains('\0') {
        return Err(format!(
            "semantic source has unsafe repository-relative path: {}",
            relative.display()
        ));
    }
    Ok(RepositoryPath(text))
}

fn language_kind(file: &FileRecord) -> Option<SemanticIndexerKind> {
    match file.language.to_ascii_lowercase().as_str() {
        "typescript" | "javascript" => Some(SemanticIndexerKind::TypeScriptJavaScript),
        "python" => Some(SemanticIndexerKind::Python),
        "go" => Some(SemanticIndexerKind::Go),
        "kotlin" => Some(SemanticIndexerKind::Kotlin),
        "rust" => Some(SemanticIndexerKind::Rust),
        _ => None,
    }
}

fn compact_process_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut combined = Vec::with_capacity((stdout.len() + stderr.len()).min(MAX_PROCESS_OUTPUT));
    combined.extend_from_slice(&stdout[..stdout.len().min(MAX_PROCESS_OUTPUT)]);
    if combined.len() < MAX_PROCESS_OUTPUT {
        combined.extend_from_slice(
            &stderr[..stderr
                .len()
                .min(MAX_PROCESS_OUTPUT.saturating_sub(combined.len()))],
        );
    }
    let text = String::from_utf8_lossy(&combined);
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.len() <= MAX_COMPACT_ERROR_OUTPUT {
        return compact;
    }

    let head_len = MAX_COMPACT_ERROR_OUTPUT / 2;
    let tail_len = MAX_COMPACT_ERROR_OUTPUT - head_len;
    let head = &compact[..head_len];
    let tail = &compact[compact.len() - tail_len..];
    format!("{head} ... [provider output elided] ... {tail}")
}

#[cfg(test)]
#[path = "tests/semantic_indexer_runner.rs"]
mod tests;
