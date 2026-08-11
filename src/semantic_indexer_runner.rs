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

const INDEX_TIMEOUT: Duration = Duration::from_secs(60 * 60);
#[cfg(debug_assertions)]
const INDEXER_TIMEOUT_ENV: &str = "SNIFF_INTERNAL_INDEXER_TIMEOUT_SECS";
const MAX_PROCESS_OUTPUT: usize = 2 * 1024 * 1024;
const INDEXER_MEMORY_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const INDEXER_PROCESS_LIMIT: u32 = 512;
const MAX_COMPACT_ERROR_OUTPUT: usize = 8 * 1024;
const INDEXER_CACHE_DIR: &str = ".sniff-indexer-cache";
const INDEXER_TEMP_DIR: &str = ".sniff-indexer-tmp";
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
    gradle_launcher_jar: PathBuf,
    gradle_main_class: &'static str,
    project_root: PathBuf,
}

struct TemporaryIndexerDirectory(PathBuf);

impl Drop for TemporaryIndexerDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TemporaryIndexerWorkspace {
    fn cleanup(self, indexer_name: &str) -> Result<(), String> {
        fs::remove_dir_all(&self.directory).map_err(|error| {
            format!(
                "{} indexing completed but temporary workspace cleanup failed for {}: {error}",
                indexer_name,
                self.directory.display()
            )
        })
    }
}

pub(crate) async fn run_required_indexers(
    repository_root: &Path,
    files: &[FileRecord],
) -> Result<BTreeMap<SemanticIndexerKind, SemanticIndex>, String> {
    let root =
        strip_windows_verbatim_prefix(fs::canonicalize(repository_root).map_err(|error| {
            format!(
                "failed to resolve semantic index repository root {}: {error}",
                repository_root.display()
            )
        })?);
    let store = SemanticIndexerStore::for_user()?;
    let mut indexes = BTreeMap::new();
    for kind in required_indexers(files) {
        let spec = pinned_indexer(kind)?;
        if kind == SemanticIndexerKind::Kotlin {
            reject_unsupported_android_gradle(&root, files)?;
        }
        let installed = store.verify(spec)?;
        let index_path = root.join("index.scip");
        if index_path.exists() {
            return Err(format!(
                "refusing to overwrite existing SCIP output {}; remove or relocate it before indexing",
                index_path.display()
            ));
        }
        if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
            eprintln!("[sniff] semantic indexer start: {}", spec.display_name);
        }
        if let Err(error) = run_one(spec, &root, &installed, files).await {
            let _ = fs::remove_file(&index_path);
            return Err(error);
        }
        if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
            eprintln!("[sniff] semantic indexer complete: {}", spec.display_name);
        }
        let index_files = files_for_indexer(files, kind);
        let expected_languages = expected_document_languages(&root, &index_files)?;
        let result = crate::semantic_index_scip::ingest_scip_file_with_expected_languages(
            &root,
            &index_path,
            Some(&expected_languages),
            missing_position_encoding(kind),
        )
        .and_then(|index| validate_expected_documents(&root, files, kind, index));
        let cleanup = fs::remove_file(&index_path);
        if let Err(error) = cleanup
            && result.is_ok()
        {
            return Err(format!(
                "failed to remove generated SCIP output {}: {error}",
                index_path.display()
            ));
        }
        indexes.insert(kind, result?);
    }
    Ok(indexes)
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
) -> Result<(), String> {
    let source_digest_before = source_integrity_digest(files)?;
    let cache_root =
        (spec.kind == SemanticIndexerKind::Kotlin).then(|| root.join(INDEXER_CACHE_DIR));
    if let Some(cache_root) = &cache_root
        && cache_root.exists()
    {
        return Err(format!(
            "refusing to reuse an unexpected semantic indexer cache {}; remove it before indexing",
            cache_root.display()
        ));
    }
    let temporary_dir = root.join(INDEXER_TEMP_DIR);
    if temporary_dir.exists() {
        return Err(format!(
            "refusing to reuse an unexpected semantic indexer temp directory {}; remove it before indexing",
            temporary_dir.display()
        ));
    }
    fs::create_dir(&temporary_dir).map_err(|error| {
        format!(
            "failed to create private semantic indexer temp directory {}: {error}",
            temporary_dir.display()
        )
    })?;
    let _temporary_dir_cleanup = TemporaryIndexerDirectory(temporary_dir.clone());
    let workspace = prepare_indexer_workspace(spec, root)?;
    let temporary_project = if spec.kind == SemanticIndexerKind::TypeScriptJavaScript {
        prepare_mixed_typescript_javascript_project(spec, root, files)?
    } else {
        #[cfg(windows)]
        if spec.kind == SemanticIndexerKind::Python {
            prepare_windows_python_project(root, files)?
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
        Some(prepare_windows_python_environment(&temporary_dir)?)
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
    let sandbox_command =
        build_indexer_sandbox_command(spec, root, installed, arguments, workspace.as_ref())?;
    if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
        eprintln!(
            "[sniff] semantic indexer sandbox ready: {}",
            spec.display_name
        );
    }
    if let Some(cache_root) = &cache_root {
        fs::create_dir(cache_root).map_err(|error| {
            format!(
                "failed to create private semantic indexer cache {}: {error}",
                cache_root.display()
            )
        })?;
        write_private_gradle_properties(root, cache_root)?;
    }
    let output = if spec.kind == SemanticIndexerKind::Kotlin {
        let mut preparation = sandbox_command.clone();
        preparation.allow_network = true;
        preparation
            .env
            .retain(|(name, _)| name != "SNIFF_GRADLE_OFFLINE");
        let preparation = run_sandbox_command(preparation, spec.display_name).await;
        match preparation {
            Ok(output) if output.status_code == Some(0) && !output.timed_out => {
                let index_path = root.join("index.scip");
                if let Err(error) = fs::remove_file(&index_path)
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    Err(format!(
                        "{} dependency preparation emitted an index that could not be cleared: {error}",
                        spec.display_name
                    ))
                } else {
                    run_sandbox_command(sandbox_command, spec.display_name).await
                }
            }
            Ok(output) => Err(format!(
                "{} dependency preparation failed with {}; output: {}; launcher trace: {}",
                spec.display_name,
                output
                    .status_code
                    .map_or_else(|| "signal".to_string(), |status| status.to_string()),
                compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes()),
                gradle_launcher_trace(root)
            )),
            Err(error) => Err(error),
        }
    } else {
        if std::env::var_os("SNIFF_DEBUG_INDEXERS").is_some() {
            eprintln!(
                "[sniff] semantic indexer process start: {}",
                spec.display_name
            );
        }
        run_sandbox_command(sandbox_command, spec.display_name).await
    };
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
        (Err(error), Ok(_)) | (Ok(()), Err(error)) => return Err(error),
        (Err(project_error), Err(workspace_error)) => {
            return Err(format!("{project_error}; additionally, {workspace_error}"));
        }
    }
    if let Some(cache_root) = cache_root
        && cache_root.exists()
    {
        fs::remove_dir_all(&cache_root).map_err(|error| {
            format!(
                "{} indexing completed but private cache cleanup failed for {}: {error}",
                spec.display_name,
                cache_root.display()
            )
        })?;
    }
    let source_digest_after = source_integrity_digest(files)?;
    if source_digest_before != source_digest_after {
        return Err(format!(
            "{} indexing changed an eligible source file; refusing to trust its SCIP output",
            spec.display_name
        ));
    }
    let output = output?;
    if output.timed_out {
        return Err(format!(
            "{} indexing timed out after {}",
            spec.display_name,
            format_timeout(index_timeout())
        ));
    }
    if output.status_code == Some(0) {
        let index_path = root.join("index.scip");
        if !index_path.is_file() {
            return Err(format!(
                "{} exited successfully but did not emit SCIP index {}; output: {}",
                spec.display_name,
                index_path.display(),
                compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
            ));
        }
        return Ok(());
    }
    Err(format!(
        "{} indexing failed with {}; output: {}",
        spec.display_name,
        output
            .status_code
            .map_or_else(|| "signal".to_string(), |status| status.to_string()),
        compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
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

fn build_indexer_sandbox_command(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
    arguments: Vec<String>,
    workspace: Option<&TemporaryIndexerWorkspace>,
) -> Result<SandboxCommand, String> {
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
            let java = resolve_runtime("java")?;
            let mut args = Vec::new();
            args.push(format!(
                "-Duser.home={}",
                sandbox_repository_argument(root, &root.to_string_lossy())
            ));
            args.push(format!(
                "-Djava.io.tmpdir={}",
                sandbox_repository_argument(root, &root.join(INDEXER_CACHE_DIR).to_string_lossy(),)
            ));
            #[cfg(windows)]
            if spec.kind == SemanticIndexerKind::Kotlin {
                let patch_dir = entrypoint
                    .parent()
                    .ok_or_else(|| "scip-java entrypoint has no parent directory".to_string())?
                    .join("scip-java-v0.13.1-patch");
                args.extend([
                    "-cp".to_string(),
                    windows_java_classpath(&patch_dir, &entrypoint),
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
    push_external_read_only(
        root,
        &mut persistent_read_only_paths,
        installed_root.clone(),
    );
    #[cfg(windows)]
    if spec.runtime == IndexerRuntime::JavaJar {
        collect_windows_runtime_images(root, &mut executable_paths, &runtime_root)?;
    }
    push_external_read_only(root, &mut persistent_read_only_paths, runtime_root);
    for dependency in runtime_dependency_paths(&runtime_path)? {
        push_external_read_only(root, &mut persistent_read_only_paths, dependency);
    }
    let mut path_prefixes = Vec::new();
    let mut env = Vec::new();
    let sandbox_home = sandbox_repository_argument(root, &root.to_string_lossy());
    env.push(("HOME".to_string(), sandbox_home.clone()));
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
        let cargo = resolve_runtime("cargo")?;
        for name in ["cargo", "rustc"] {
            let runtime = resolve_runtime(name)?;
            let runtime_root = runtime_mount_root(&runtime);
            push_external_read_only(root, &mut persistent_read_only_paths, runtime_root);
            #[cfg(windows)]
            push_external_read_only(root, &mut executable_paths, runtime.clone());
            path_prefixes.push(runtime_bin_directory(&runtime, name)?);
        }
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
                #[cfg(windows)]
                collect_windows_runtime_images(
                    root,
                    &mut executable_paths,
                    &rustup_home.join("toolchains"),
                )?;
                env.push((
                    "RUSTUP_HOME".to_string(),
                    rustup_home.to_string_lossy().to_string(),
                ));
            }
        }
    }
    let gradle_jvm_args = if spec.kind == SemanticIndexerKind::Kotlin {
        let gradle = resolve_runtime("gradle")?;
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
            java_home.to_string_lossy().to_string(),
        ));
    }
    if let Some(workspace) = workspace {
        read_only_paths.push(fs::canonicalize(&workspace.directory).map_err(|error| {
            format!(
                "failed to resolve temporary indexer workspace {}: {error}",
                workspace.directory.display()
            )
        })?);
        env.push((
            "SNIFF_INTERNAL_GRADLE_LAUNCHER".to_string(),
            "1".to_string(),
        ));
        env.push((
            "SNIFF_GRADLE_LAUNCHER_JAR".to_string(),
            sandbox_repository_argument(root, &workspace.gradle_launcher_jar.to_string_lossy()),
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

    Ok(SandboxCommand {
        root: root.to_path_buf(),
        workdir: PathBuf::from("."),
        program,
        args,
        read_only_paths,
        persistent_read_only_paths,
        executable_paths,
        env,
        allow_network: false,
        #[cfg(target_os = "macos")]
        allow_local_network: spec.kind == SemanticIndexerKind::Kotlin,
        timeout: index_timeout(),
        output_limit: MAX_PROCESS_OUTPUT,
        memory_limit: INDEXER_MEMORY_LIMIT,
        process_limit: INDEXER_PROCESS_LIMIT,
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
    const MAX_RUNTIME_ENTRIES: usize = 20_000;

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
            }
        }
    }
    Ok(())
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
    let home = sandbox_repository_argument(root, &root.to_string_lossy()).replace('\\', "\\\\");
    let project_cache =
        sandbox_repository_argument(root, &cache_root.join("project-cache").to_string_lossy())
            .replace('\\', "\\\\");
    fs::write(
        cache_root.join("gradle.properties"),
        format!(
            "systemProp.user.home={home}\norg.gradle.daemon=false\norg.gradle.parallel=false\norg.gradle.workers.max=32\norg.gradle.projectcachedir={project_cache}\n"
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
        agent.display()
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

fn reject_unsupported_android_gradle(root: &Path, files: &[FileRecord]) -> Result<(), String> {
    let root = fs::canonicalize(root).map_err(|error| {
        format!("failed to resolve repository root for Kotlin Gradle capability: {error}")
    })?;
    let mut directories = BTreeSet::new();
    for file in files {
        if language_kind(file) != Some(SemanticIndexerKind::Kotlin) {
            continue;
        }
        let path = fs::canonicalize(&file.file_path).map_err(|error| {
            format!(
                "failed to inspect Kotlin source {} for Gradle capability: {error}",
                file.file_path
            )
        })?;
        let mut directory = path.parent();
        while let Some(current) = directory {
            if !current.starts_with(&root) {
                return Err(format!(
                    "Kotlin source {} is outside repository root {}",
                    file.file_path,
                    root.display()
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
            let source = fs::read_to_string(&path).map_err(|error| {
                format!(
                    "failed to inspect Gradle build script {} for Kotlin capability: {error}",
                    path.display()
                )
            })?;
            if gradle_script_uses_android(&source) {
                return Err(format!(
                    "scip-java does not support Android Gradle integration; detected Android module {}. Sniff refuses a weaker Kotlin graph provider",
                    path.display()
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

    let directory = create_temporary_workspace("sniff-kotlin-gradle")?;
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
        let (gradle_launcher_jar, gradle_main_class) = if project_gradle_wrapper.is_file() {
            let wrapper_jar = root.join("gradle/wrapper/gradle-wrapper.jar");
            if !wrapper_jar.is_file() {
                return Err(format!(
                    "Gradle wrapper launcher is missing at {}; refusing to execute the batch wrapper through a shell",
                    wrapper_jar.display()
                ));
            }
            (wrapper_jar, "org.gradle.wrapper.GradleWrapperMain")
        } else {
            let system_gradle = find_system_gradle()?;
            (
                system_gradle_launcher_jar(&system_gradle)?,
                "org.gradle.launcher.GradleMain",
            )
        };
        Ok(TemporaryIndexerWorkspace {
            directory: directory.clone(),
            gradle_launcher_jar,
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
fn system_gradle_launcher_jar(gradle: &Path) -> Result<PathBuf, String> {
    let home = gradle.parent().and_then(Path::parent).ok_or_else(|| {
        format!(
            "system Gradle has no installation root: {}",
            gradle.display()
        )
    })?;
    let lib = home.join("lib");
    let mut candidates = fs::read_dir(&lib)
        .map_err(|error| {
            format!(
                "failed to inspect system Gradle libraries at {}: {error}",
                lib.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };
            path.is_file()
                && name.ends_with(".jar")
                && (name.starts_with("gradle-gradle-cli-main-")
                    || name.starts_with("gradle-launcher-"))
        })
        .collect::<Vec<_>>();
    candidates.sort();
    match candidates.as_slice() {
        [launcher] => Ok(launcher.clone()),
        [] => Err(format!(
            "system Gradle at {} has no supported launcher jar in {}; reinstall Gradle",
            gradle.display(),
            lib.display()
        )),
        _ => Err(format!(
            "system Gradle at {} has multiple launcher jars in {}; refusing an ambiguous runtime",
            gradle.display(),
            lib.display()
        )),
    }
}

#[cfg(windows)]
fn create_temporary_workspace(prefix: &str) -> Result<PathBuf, String> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0..1000u32 {
        let directory = base.join(format!("{prefix}-{pid}-{attempt}"));
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

    let path = root.join(format!(".sniff-jsconfig-{}.json", std::process::id()));
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

#[cfg(windows)]
fn windows_java_classpath(patch_dir: &Path, launcher: &Path) -> String {
    let patch_dir = strip_windows_verbatim_prefix(patch_dir.to_path_buf());
    let launcher = strip_windows_verbatim_prefix(launcher.to_path_buf());
    format!("{};{}", patch_dir.display(), launcher.display())
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
