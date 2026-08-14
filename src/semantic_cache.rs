use crate::types::{FileRecord, LocalFileSymbols};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const CACHE_FORMAT_VERSION: u32 = 3;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const INDEX_CONTRACT: &str = concat!("source-index-v3/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheDisposition {
    Hit,
    Built,
}

#[derive(Debug, Serialize, Deserialize)]
struct SemanticArtifact {
    format_version: u32,
    index_contract: String,
    source_hash: String,
    payload_hash: String,
    language: String,
    file_record: FileRecord,
    symbols: LocalFileSymbols,
}

#[derive(Debug, Clone)]
pub(crate) struct SemanticIndexCache {
    root: PathBuf,
}

impl SemanticIndexCache {
    pub(crate) fn for_repository(repository_root: &Path) -> Result<Self, String> {
        let cache_base = cache_base_directory()?;
        let canonical_root = fs::canonicalize(repository_root).map_err(|error| {
            format!(
                "failed to resolve semantic-cache repository root {}: {error}",
                repository_root.display()
            )
        })?;
        let repository_key = sha256_text(&normalize_path(&canonical_root));
        Ok(Self::at(cache_base.join("semantic").join(repository_key)))
    }

    pub(crate) fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub(crate) fn load_or_build(
        &self,
        file: &FileRecord,
    ) -> Result<(LocalFileSymbols, CacheDisposition), String> {
        verify_source_snapshot(file)?;
        let source_hash = sha256_text(&file.source);
        let key = artifact_key(Path::new(&file.file_path), &source_hash)?;
        let artifact_path = self.artifact_path(&key);
        if artifact_path.exists() {
            let mut artifact = read_artifact(&artifact_path)?;
            validate_artifact(&artifact, file, &source_hash, &artifact_path)?;
            rebind_paths(&mut artifact, &file.file_path);
            return Ok((artifact.symbols, CacheDisposition::Hit));
        }

        let symbols = crate::parser::parse_file_symbols_checked(&file.file_path)
            .map_err(|error| format!("symbol parse failed for {}: {error}", file.file_path))?;
        verify_source_snapshot(file)?;
        let payload_hash = semantic_payload_hash(file, &symbols)?;
        let artifact = SemanticArtifact {
            format_version: CACHE_FORMAT_VERSION,
            index_contract: INDEX_CONTRACT.to_string(),
            source_hash,
            payload_hash,
            language: file.language.clone(),
            file_record: file.clone(),
            symbols: symbols.clone(),
        };
        write_artifact(&artifact_path, &artifact)?;
        Ok((symbols, CacheDisposition::Built))
    }

    pub(crate) fn load_or_build_file(
        &self,
        file_path: &Path,
    ) -> Result<(FileRecord, CacheDisposition), String> {
        let source = fs::read_to_string(file_path).map_err(|error| {
            format!(
                "failed to read source file for semantic indexing {}: {error}",
                file_path.display()
            )
        })?;
        let source_hash = sha256_text(&source);
        let key = artifact_key(file_path, &source_hash)?;
        let artifact_path = self.artifact_path(&key);
        if artifact_path.exists() {
            let mut artifact = read_artifact(&artifact_path)?;
            let current_path = file_path.to_string_lossy();
            validate_artifact_source(&artifact, &source, &source_hash, &artifact_path)?;
            rebind_paths(&mut artifact, &current_path);
            return Ok((artifact.file_record, CacheDisposition::Hit));
        }

        let file_path_text = file_path.to_string_lossy();
        let file_record = crate::parser::parse_file_checked(&file_path_text)?;
        let symbols = crate::parser::parse_file_symbols_checked(&file_path_text)
            .map_err(|error| format!("symbol parse failed for {file_path_text}: {error}"))?;
        verify_source_snapshot(&file_record)?;
        let payload_hash = semantic_payload_hash(&file_record, &symbols)?;
        let artifact = SemanticArtifact {
            format_version: CACHE_FORMAT_VERSION,
            index_contract: INDEX_CONTRACT.to_string(),
            source_hash,
            payload_hash,
            language: file_record.language.clone(),
            file_record: file_record.clone(),
            symbols,
        };
        write_artifact(&artifact_path, &artifact)?;
        Ok((file_record, CacheDisposition::Built))
    }

    fn artifact_path(&self, key: &str) -> PathBuf {
        self.root.join(&key[..2]).join(format!("{key}.json"))
    }
}

fn cache_base_directory() -> Result<PathBuf, String> {
    if let Some(configured) = std::env::var_os("SNIFF_CACHE_DIR")
        && !configured.is_empty()
    {
        return Ok(PathBuf::from(configured));
    }
    #[cfg(windows)]
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return Ok(PathBuf::from(local_app_data).join("Sniff").join("cache"));
    }
    if let Some(xdg_cache) = std::env::var_os("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(xdg_cache).join("sniff"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".cache").join("sniff"));
    }
    Err("cannot locate a durable cache directory; set SNIFF_CACHE_DIR".to_string())
}

fn normalize_path(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    #[cfg(windows)]
    {
        normalized.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        normalized
    }
}

fn sha256_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn semantic_payload_hash(
    file_record: &FileRecord,
    symbols: &LocalFileSymbols,
) -> Result<String, String> {
    let payload = serde_json::to_vec(&(file_record, symbols))
        .map_err(|error| format!("failed to hash semantic cache payload: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(payload)))
}

fn artifact_key(path: &Path, source_hash: &str) -> Result<String, String> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .ok_or_else(|| {
            format!(
                "source file has no semantic-cache extension: {}",
                path.display()
            )
        })?;
    Ok(sha256_text(&format!(
        "{INDEX_CONTRACT}\0{}\0{source_hash}",
        extension.to_ascii_lowercase()
    )))
}

fn verify_source_snapshot(file: &FileRecord) -> Result<(), String> {
    let current = fs::read_to_string(&file.file_path).map_err(|error| {
        format!(
            "failed to verify source snapshot {}: {error}",
            file.file_path
        )
    })?;
    if current != file.source {
        return Err(format!(
            "source changed while semantic indexing {}; rerun Sniff against a stable checkout",
            file.file_path
        ));
    }
    Ok(())
}

fn read_artifact(path: &Path) -> Result<SemanticArtifact, String> {
    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "failed to inspect semantic cache {}: {error}",
            path.display()
        )
    })?;
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err(format!(
            "semantic cache artifact exceeds {} bytes: {}",
            MAX_ARTIFACT_BYTES,
            path.display()
        ));
    }
    let file = File::open(path)
        .map_err(|error| format!("failed to open semantic cache {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read semantic cache {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "semantic cache artifact is corrupt at {}: {error}; remove the artifact and rerun",
            path.display()
        )
    })
}

fn validate_artifact(
    artifact: &SemanticArtifact,
    file: &FileRecord,
    source_hash: &str,
    path: &Path,
) -> Result<(), String> {
    if artifact.format_version != CACHE_FORMAT_VERSION
        || artifact.index_contract != INDEX_CONTRACT
        || artifact.source_hash != source_hash
        || artifact.payload_hash != semantic_payload_hash(&artifact.file_record, &artifact.symbols)?
        || !artifact.language.eq_ignore_ascii_case(&file.language)
        || artifact.file_record.source != file.source
    {
        return Err(format!(
            "semantic cache artifact identity mismatch at {}; remove the artifact and rerun",
            path.display()
        ));
    }
    Ok(())
}

fn validate_artifact_source(
    artifact: &SemanticArtifact,
    source: &str,
    source_hash: &str,
    path: &Path,
) -> Result<(), String> {
    if artifact.format_version != CACHE_FORMAT_VERSION
        || artifact.index_contract != INDEX_CONTRACT
        || artifact.source_hash != source_hash
        || artifact.payload_hash != semantic_payload_hash(&artifact.file_record, &artifact.symbols)?
        || artifact.language != artifact.file_record.language
        || artifact.file_record.source != source
    {
        return Err(format!(
            "semantic cache artifact identity mismatch at {}; remove the artifact and rerun",
            path.display()
        ));
    }
    Ok(())
}

fn rebind_paths(artifact: &mut SemanticArtifact, file_path: &str) {
    artifact.file_record.file_path = file_path.to_string();
    for method in &mut artifact.file_record.methods {
        method.file_path = file_path.to_string();
    }
    artifact.symbols.file_path = file_path.to_string();
}

fn write_artifact(path: &Path, artifact: &SemanticArtifact) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "semantic cache artifact has no parent directory: {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create semantic cache directory {}: {error}",
            parent.display()
        )
    })?;
    #[cfg(unix)]
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "failed to secure semantic cache directory {}: {error}",
            parent.display()
        )
    })?;
    let bytes = serde_json::to_vec(artifact)
        .map_err(|error| format!("failed to serialize semantic cache artifact: {error}"))?;
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err(format!(
            "semantic cache artifact for {} exceeds {} bytes",
            artifact.symbols.file_path, MAX_ARTIFACT_BYTES
        ));
    }

    static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
    let temp_path = parent.join(format!(
        ".{}.{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("semantic-cache"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut temp = options.open(&temp_path).map_err(|error| {
        format!(
            "failed to create semantic cache temporary file {}: {error}",
            temp_path.display()
        )
    })?;
    let write_result = (|| {
        temp.write_all(&bytes).map_err(|error| {
            format!(
                "failed to write semantic cache temporary file {}: {error}",
                temp_path.display()
            )
        })?;
        temp.sync_all().map_err(|error| {
            format!(
                "failed to sync semantic cache temporary file {}: {error}",
                temp_path.display()
            )
        })?;
        drop(temp);
        match fs::rename(&temp_path, path) {
            Ok(()) => Ok(()),
            Err(_) if path.exists() => {
                fs::remove_file(&temp_path).map_err(|error| {
                    format!(
                        "failed to remove raced semantic cache file {}: {error}",
                        temp_path.display()
                    )
                })?;
                Ok(())
            }
            Err(error) => Err(format!(
                "failed to commit semantic cache artifact {}: {error}",
                path.display()
            )),
        }
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

#[cfg(test)]
#[path = "tests/semantic_cache.rs"]
mod tests;
