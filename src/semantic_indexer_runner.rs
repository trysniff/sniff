use crate::semantic_index::{RepositoryPath, SemanticIndex, SemanticPositionEncoding};
use crate::semantic_indexer_installation::SemanticIndexerStore;
use crate::semantic_indexer_manifest::{
    IndexerRuntime, PinnedIndexer, SemanticIndexerKind, pinned_indexer, required_indexers,
};
use crate::types::FileRecord;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const INDEX_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_PROCESS_OUTPUT: usize = 2 * 1024 * 1024;
const MAX_COMPACT_ERROR_OUTPUT: usize = 8 * 1024;

pub(crate) async fn run_required_indexers(
    repository_root: &Path,
    files: &[FileRecord],
) -> Result<BTreeMap<SemanticIndexerKind, SemanticIndex>, String> {
    let root = fs::canonicalize(repository_root).map_err(|error| {
        format!(
            "failed to resolve semantic index repository root {}: {error}",
            repository_root.display()
        )
    })?;
    let store = SemanticIndexerStore::for_user()?;
    let mut indexes = BTreeMap::new();
    for kind in required_indexers(files) {
        let spec = pinned_indexer(kind)?;
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
    let mut command = match spec.runtime {
        IndexerRuntime::NodeScript => {
            let mut command = Command::new("node");
            command.arg(entrypoint);
            command.args(indexer_arguments(spec, root, files));
            command
        }
        IndexerRuntime::Native => {
            let mut command = Command::new(entrypoint);
            command.args(indexer_arguments(spec, root, files));
            command
        }
        IndexerRuntime::JavaJar => {
            let mut command = Command::new("java");
            command.arg("-jar").arg(entrypoint);
            command.args(indexer_arguments(spec, root, files));
            command
        }
    };
    command.current_dir(root).kill_on_drop(true);
    let output = timeout(INDEX_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            format!(
                "{} indexing timed out after {} minutes",
                spec.display_name,
                INDEX_TIMEOUT.as_secs() / 60
            )
        })?
        .map_err(|error| format!("{} indexing could not start: {error}", spec.display_name))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{} indexing failed with {}; output: {}",
        spec.display_name,
        output.status,
        compact_process_output(&output.stdout, &output.stderr)
    ))
}

fn indexer_arguments(spec: PinnedIndexer, root: &Path, files: &[FileRecord]) -> Vec<String> {
    match spec.kind {
        SemanticIndexerKind::TypeScriptJavaScript => {
            let mut arguments = vec!["index".to_string()];
            let has_typescript = root.join("tsconfig.json").is_file();
            let has_javascript = files
                .iter()
                .any(|file| file.language.eq_ignore_ascii_case("javascript"));
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
    let canonical = fs::canonicalize(file).map_err(|error| {
        format!(
            "failed to resolve expected semantic source {}: {error}",
            file.display()
        )
    })?;
    let relative = canonical.strip_prefix(root).map_err(|_| {
        format!(
            "semantic source {} is outside repository root {}",
            file.display(),
            root.display()
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
