use crate::semantic_index::{RepositoryPath, SemanticIndex, SemanticPositionEncoding};
use crate::semantic_indexer_installation::SemanticIndexerStore;
use crate::semantic_indexer_manifest::{
    IndexerRuntime, PinnedIndexer, SemanticIndexerKind, pinned_indexer, required_indexers,
};
use crate::types::FileRecord;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const INDEX_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_PROCESS_OUTPUT: usize = 2 * 1024 * 1024;
const MAX_COMPACT_ERROR_OUTPUT: usize = 8 * 1024;
const WINDOWS_SCIP_PYTHON_BOOTSTRAP: &str = "const path=require('path'); const NativeRegExp=RegExp; function PatchedRegExp(pattern, flags) { if (pattern === path.sep) pattern = path.sep + path.sep; return new NativeRegExp(pattern, flags); } PatchedRegExp.prototype=NativeRegExp.prototype; Object.setPrototypeOf(PatchedRegExp, NativeRegExp); global.RegExp=PatchedRegExp; require(process.argv[1]);";

struct TemporaryIndexerWorkspace {
    directory: PathBuf,
    path_prefix: PathBuf,
    gradle_wrapper: PathBuf,
    project_root: PathBuf,
}

impl TemporaryIndexerWorkspace {
    fn path_environment(&self) -> OsString {
        let mut path = self.path_prefix.as_os_str().to_os_string();
        if let Some(existing) = std::env::var_os("PATH") {
            path.push(";");
            path.push(existing);
        }
        path
    }

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
        if let Err(error) = run_one(spec, &root, &installed.entrypoint, files).await {
            let _ = fs::remove_file(&index_path);
            return Err(error);
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
    entrypoint: &Path,
    files: &[FileRecord],
) -> Result<(), String> {
    let workspace = prepare_indexer_workspace(spec, root)?;
    let temporary_project = prepare_mixed_typescript_javascript_project(spec, root, files)?;
    let arguments = indexer_arguments_with_workspace(
        spec,
        root,
        files,
        temporary_project.as_deref(),
        workspace.as_ref(),
    );
    let mut command = match spec.runtime {
        IndexerRuntime::NodeScript => {
            let mut command = Command::new("node");
            if spec.kind == SemanticIndexerKind::Python && cfg!(windows) {
                command
                    .arg("-e")
                    .arg(WINDOWS_SCIP_PYTHON_BOOTSTRAP)
                    .arg(entrypoint);
            } else {
                command.arg(entrypoint);
            }
            command.args(arguments);
            command
        }
        IndexerRuntime::Native => {
            let mut command = Command::new(entrypoint);
            command.args(arguments);
            command
        }
        IndexerRuntime::JavaJar => {
            let mut command = Command::new("java");
            command.arg("-jar").arg(entrypoint);
            command.args(arguments);
            command
        }
    };
    command.current_dir(root).kill_on_drop(true);
    if let Some(workspace) = workspace.as_ref() {
        command
            .env("PATH", workspace.path_environment())
            .env("SNIFF_INTERNAL_GRADLE_LAUNCHER", "1")
            .env("SNIFF_GRADLE_WRAPPER", &workspace.gradle_wrapper)
            .env("SNIFF_GRADLE_PROJECT", &workspace.project_root);
    }
    let output = match timeout(INDEX_TIMEOUT, command.output()).await {
        Err(_) => Err(format!(
            "{} indexing timed out after {} minutes",
            spec.display_name,
            INDEX_TIMEOUT.as_secs() / 60
        )),
        Ok(Err(error)) => Err(format!(
            "{} indexing could not start: {error}",
            spec.display_name
        )),
        Ok(Ok(output)) => Ok(output),
    };
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
    let output = output?;
    if output.status.success() {
        let index_path = root.join("index.scip");
        if !index_path.is_file() {
            return Err(format!(
                "{} exited successfully but did not emit SCIP index {}; output: {}",
                spec.display_name,
                index_path.display(),
                compact_process_output(&output.stdout, &output.stderr)
            ));
        }
        return Ok(());
    }
    Err(format!(
        "{} indexing failed with {}; output: {}",
        spec.display_name,
        output.status,
        compact_process_output(&output.stdout, &output.stderr)
    ))
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
    files: &[FileRecord],
    extra_project: Option<&Path>,
) -> Vec<String> {
    match spec.kind {
        SemanticIndexerKind::TypeScriptJavaScript => {
            let mut arguments = vec!["index".to_string()];
            let has_typescript = root.join("tsconfig.json").is_file();
            let has_javascript = files
                .iter()
                .any(|file| file.language.eq_ignore_ascii_case("javascript"));
            if let Some(extra_project) = extra_project {
                arguments.push(".".to_string());
                arguments.push(extra_project.to_string_lossy().to_string());
            }
            if !has_typescript && has_javascript {
                arguments.push("--infer-tsconfig".to_string());
            }
            arguments
        }
        SemanticIndexerKind::Python => vec![
            "index".to_string(),
            ".".to_string(),
            "--project-name".to_string(),
            project_name(root),
        ],
        SemanticIndexerKind::Go => Vec::new(),
        SemanticIndexerKind::Kotlin => vec!["index".to_string()],
        SemanticIndexerKind::Rust => vec!["scip".to_string(), ".".to_string()],
    }
}

fn indexer_arguments_with_workspace(
    spec: PinnedIndexer,
    root: &Path,
    files: &[FileRecord],
    extra_project: Option<&Path>,
    workspace: Option<&TemporaryIndexerWorkspace>,
) -> Vec<String> {
    let arguments = indexer_arguments_with_project(spec, root, files, extra_project);
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
    if !unix_wrapper.is_file() {
        return Ok(None);
    }

    let gradle_wrapper = root.join("gradlew.bat");
    if !gradle_wrapper.is_file() {
        return Err(format!(
            "scip-java cannot index this Windows Gradle project: {} exists but {} is missing; refusing to use a weaker system-Gradle fallback",
            unix_wrapper.display(),
            gradle_wrapper.display()
        ));
    }

    let directory = create_temporary_workspace("sniff-kotlin-gradle")?;
    let result = (|| {
        let path_prefix = directory.join("bin");
        fs::create_dir(&path_prefix).map_err(|error| {
            format!(
                "failed to create temporary Kotlin Gradle launcher directory {}: {error}",
                path_prefix.display()
            )
        })?;
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
        // Java ProcessBuilder cannot launch a Windows batch file by the bare
        // `gradle` name, so reuse Sniff as a temporary launcher instead of
        // shipping another executable.
        fs::write(path_prefix.join("gradle.exe"), current_executable_bytes()?).map_err(
            |error| {
                format!(
                    "failed to create temporary Windows Gradle launcher {}: {error}",
                    path_prefix.join("gradle.exe").display()
                )
            },
        )?;
        Ok(TemporaryIndexerWorkspace {
            directory: directory.clone(),
            path_prefix,
            gradle_wrapper,
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
fn current_executable_bytes() -> Result<Vec<u8>, String> {
    let executable = std::env::current_exe().map_err(|error| {
        format!("failed to resolve Sniff executable for Gradle launcher: {error}")
    })?;
    fs::read(&executable).map_err(|error| {
        format!(
            "failed to read Sniff executable {} for Gradle launcher: {error}",
            executable.display()
        )
    })
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
