use crate::config::ResolvedConfig;
use crate::types::FileRecord;
use std::path::{Path, PathBuf};

const REPOSITORY_MARKERS: &[&str] = &[
    ".git",
    "Cargo.toml",
    "pyproject.toml",
    "package.json",
    "settings.gradle",
    "settings.gradle.kts",
];

pub(super) async fn parse_files(
    file_paths: &[String],
    semantic_cache: Option<&crate::semantic_cache::SemanticIndexCache>,
) -> Result<Vec<FileRecord>, String> {
    let mut file_records = Vec::new();
    for fp in file_paths {
        let fp_clone = fp.clone();
        let cache = semantic_cache.cloned();
        let record = match tokio::task::spawn_blocking(move || {
            if let Some(cache) = cache {
                cache
                    .load_or_build_file(std::path::Path::new(&fp_clone))
                    .map(|(record, _)| record)
            } else {
                crate::parser::parse_file_checked(&fp_clone)
            }
        })
        .await
        {
            Ok(Ok(record)) => record,
            Ok(Err(err)) => return Err(err),
            Err(err) => {
                return Err(format!("parser task failed for {fp}: {err}"));
            }
        };
        if !record.language.is_empty() {
            file_records.push(record);
        }
    }
    Ok(file_records)
}

pub(super) async fn scan_files(
    path: &str,
    config: &ResolvedConfig,
) -> Result<Vec<FileRecord>, String> {
    scan_files_with_cache(path, config, None).await
}

pub(super) async fn scan_files_with_cache(
    path: &str,
    config: &ResolvedConfig,
    semantic_cache: Option<&crate::semantic_cache::SemanticIndexCache>,
) -> Result<Vec<FileRecord>, String> {
    let file_paths = crate::walker::walk(path, config)?;
    if file_paths.is_empty() {
        return Ok(Vec::new());
    }

    parse_files(&file_paths, semantic_cache).await
}

#[cfg(test)]
pub(super) async fn scan_evidence_files(
    path: &str,
    config: &ResolvedConfig,
) -> Result<Vec<FileRecord>, String> {
    scan_evidence_files_with_cache(path, config, None).await
}

async fn scan_evidence_files_with_cache(
    path: &str,
    config: &ResolvedConfig,
    semantic_cache: Option<&crate::semantic_cache::SemanticIndexCache>,
) -> Result<Vec<FileRecord>, String> {
    let file_paths = crate::walker::walk_evidence(path, config)?;
    if file_paths.is_empty() {
        return Ok(Vec::new());
    }
    parse_files(&file_paths, semantic_cache).await
}

pub(super) fn repository_root_for_target(target: &Path) -> PathBuf {
    let resolved = strip_windows_verbatim_prefix(
        std::fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf()),
    );
    let mut candidate = if resolved.is_dir() {
        resolved.clone()
    } else {
        resolved
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    loop {
        if REPOSITORY_MARKERS
            .iter()
            .any(|marker| candidate.join(marker).exists())
        {
            return candidate;
        }
        let Some(parent) = candidate.parent() else {
            break;
        };
        if parent == candidate {
            break;
        }
        candidate = parent.to_path_buf();
    }
    if resolved.is_dir() {
        resolved
    } else {
        resolved
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
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

#[cfg(test)]
pub(super) async fn scan_context_files(
    path: &str,
    config: &ResolvedConfig,
) -> Result<(PathBuf, Vec<FileRecord>), String> {
    scan_context_files_with_cache(path, config, None).await
}

pub(super) async fn scan_context_files_with_cache(
    path: &str,
    config: &ResolvedConfig,
    semantic_cache: Option<&crate::semantic_cache::SemanticIndexCache>,
) -> Result<(PathBuf, Vec<FileRecord>), String> {
    let target = Path::new(path);
    let root = repository_root_for_target(target);
    if !target.is_file() {
        return Ok((
            root,
            scan_evidence_files_with_cache(path, config, semantic_cache).await?,
        ));
    }

    let root_text = root.to_string_lossy().to_string();
    let mut paths = crate::walker::walk(&root_text, config)?;
    paths.extend(crate::walker::walk_evidence(&root_text, config)?);
    paths.sort();
    paths.dedup();
    Ok((root, parse_files(&paths, semantic_cache).await?))
}

#[cfg(test)]
mod tests {
    use super::{
        repository_root_for_target, scan_context_files, scan_evidence_files, scan_files,
        scan_files_with_cache, strip_windows_verbatim_prefix,
    };
    use crate::config::ResolvedConfig;
    use crate::semantic_cache::{CacheDisposition, SemanticIndexCache};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn unsupported_files_are_dropped_from_scan_results() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-scan-filter-{nanos}"));
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("note.txt"), "plain text\n").unwrap();
        fs::write(src_dir.join("main.rs"), "fn main() {}\n").unwrap();

        let files = scan_files(root.to_str().unwrap(), &ResolvedConfig::default())
            .await
            .expect("scan should complete");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language, "rust");
        assert!(files[0].file_path.ends_with("main.rs"));

        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn production_inventory_writes_the_shared_semantic_artifact() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-inventory-cache-{nanos}"));
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let source_path = src_dir.join("main.rs");
        fs::write(&source_path, "pub fn cached_inventory() {}\n").unwrap();
        let cache = SemanticIndexCache::at(root.join("cache"));

        let files = scan_files_with_cache(
            root.to_str().unwrap(),
            &ResolvedConfig::default(),
            Some(&cache),
        )
        .await
        .unwrap();
        let (_, disposition) = cache.load_or_build_file(&source_path).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].methods.len(), 1);
        assert_eq!(disposition, CacheDisposition::Hit);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn tests_are_indexed_as_evidence_without_joining_production_targets() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-evidence-scan-{nanos}"));
        let src_dir = root.join("src");
        let tests_dir = root.join("tests");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&tests_dir).unwrap();
        fs::write(src_dir.join("api.rs"), "pub fn stable_api() {}\n").unwrap();
        fs::write(
            tests_dir.join("api_contract.rs"),
            "#[test]\nfn stable_api_contract() {}\n",
        )
        .unwrap();

        let config = ResolvedConfig::default();
        let production = scan_files(root.to_str().unwrap(), &config).await.unwrap();
        let evidence = scan_evidence_files(root.to_str().unwrap(), &config)
            .await
            .unwrap();

        assert_eq!(production.len(), 1);
        assert!(production[0].file_path.ends_with("api.rs"));
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].file_path.ends_with("api_contract.rs"));

        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn file_targets_index_the_repository_without_expanding_review_targets() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-context-scan-{nanos}"));
        let src_dir = root.join("src");
        let tests_dir = root.join("tests");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&tests_dir).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        let target = src_dir.join("target.py");
        fs::write(&target, "def target():\n    return 1\n").unwrap();
        fs::write(
            src_dir.join("caller.py"),
            "from target import target\n\ndef caller():\n    return target()\n",
        )
        .unwrap();
        fs::write(
            tests_dir.join("test_target.py"),
            "from target import target\n\ndef test_target():\n    assert target() == 1\n",
        )
        .unwrap();

        let config = ResolvedConfig::default();
        let review_targets = scan_files(target.to_str().unwrap(), &config).await.unwrap();
        let (context_root, context) = scan_context_files(target.to_str().unwrap(), &config)
            .await
            .unwrap();
        let canonical_root = strip_windows_verbatim_prefix(fs::canonicalize(&root).unwrap());

        assert_eq!(review_targets.len(), 1);
        assert_eq!(repository_root_for_target(&target), canonical_root);
        assert_eq!(context_root, canonical_root);
        assert_eq!(context.len(), 3);
        assert!(
            context
                .iter()
                .any(|file| file.file_path.ends_with("caller.py"))
        );
        assert!(
            context
                .iter()
                .any(|file| file.file_path.ends_with("test_target.py"))
        );
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    #[ignore = "set SNIFF_LIVE_TARGET_FILE and SNIFF_LIVE_TARGET_METHOD to verify file-target context without LLM calls"]
    async fn live_file_target_resolves_repository_callers() {
        let target = std::env::var("SNIFF_LIVE_TARGET_FILE")
            .expect("SNIFF_LIVE_TARGET_FILE must name a source file");
        let method_names = std::env::var("SNIFF_LIVE_TARGET_METHOD")
            .expect("SNIFF_LIVE_TARGET_METHOD must name one or more semicolon-separated methods")
            .split(';')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(
            !method_names.is_empty(),
            "at least one target method is required"
        );
        let minimum_callers = std::env::var("SNIFF_LIVE_TARGET_MIN_CALLERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let config = ResolvedConfig::default();
        let mut targets = scan_files(&target, &config)
            .await
            .expect("scan target file");
        let (root, mut context) = scan_context_files(&target, &config)
            .await
            .expect("scan repository context");
        let target_paths = targets
            .iter()
            .map(|file| file.file_path.clone())
            .collect::<std::collections::HashSet<_>>();
        context.retain(|file| !target_paths.contains(&file.file_path));
        let root_text = root.to_string_lossy();
        let (_, _) = crate::cli::run::pipeline::graph::build_static_flags(
            &mut targets,
            &context,
            &root_text,
            &config,
            None,
        )
        .expect("build live target graph");
        for method_name in method_names {
            let method = targets
                .iter()
                .flat_map(|file| &file.methods)
                .find(|method| method.name == method_name)
                .expect("find target method");
            assert!(
                method.references.len() >= minimum_callers,
                "{}::{} has {} resolved callers; expected at least {minimum_callers}",
                method.file_path,
                method.name,
                method.references.len()
            );
        }
    }
}
