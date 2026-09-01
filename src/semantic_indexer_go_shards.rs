use crate::semantic_index::RepositoryPath;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GoShardLimits {
    pub(super) target_source_bytes: u64,
    pub(super) max_packages: usize,
}

pub(super) const GO_SHARD_LIMITS: GoShardLimits = GoShardLimits {
    target_source_bytes: 2 * 1024 * 1024,
    max_packages: 48,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GoPackage {
    pub(super) import_path: String,
    pub(super) source_documents: BTreeSet<RepositoryPath>,
    pub(super) source_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GoPackageShard {
    pub(super) packages: Vec<GoPackage>,
    pub(super) source_bytes: u64,
}

impl GoPackageShard {
    pub(super) fn patterns(&self) -> Vec<String> {
        self.packages
            .iter()
            .map(|package| package.import_path.clone())
            .collect()
    }

    pub(super) fn source_documents(&self) -> BTreeSet<RepositoryPath> {
        self.packages
            .iter()
            .flat_map(|package| package.source_documents.iter().cloned())
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListPackage {
    import_path: String,
    dir: String,
    #[serde(default)]
    go_files: Vec<String>,
    #[serde(default)]
    cgo_files: Vec<String>,
    #[serde(default)]
    test_go_files: Vec<String>,
    #[serde(default)]
    x_test_go_files: Vec<String>,
}

pub(super) fn parse_go_package_inventory(
    repository_root: &Path,
    output: &str,
) -> Result<Vec<GoPackage>, String> {
    let root = fs::canonicalize(repository_root).map_err(|error| {
        format!(
            "failed to resolve staged Go repository root {}: {error}",
            repository_root.display()
        )
    })?;
    let mut packages = BTreeMap::new();
    let mut document_owners = BTreeMap::<RepositoryPath, String>::new();
    let stream = serde_json::Deserializer::from_str(output).into_iter::<GoListPackage>();
    for item in stream {
        let item =
            item.map_err(|error| format!("Go package inventory is invalid JSON: {error}"))?;
        if item.import_path.trim().is_empty() || item.import_path == "command-line-arguments" {
            return Err("Go package inventory contains an invalid import path".to_string());
        }
        let relative_directory = go_package_relative_directory(&root, &item.dir)?;
        let mut source_documents = BTreeSet::new();
        let mut source_bytes = 0u64;
        for file_name in item
            .go_files
            .iter()
            .chain(&item.cgo_files)
            .chain(&item.test_go_files)
            .chain(&item.x_test_go_files)
        {
            require_plain_file_name(file_name)?;
            let relative = relative_directory.join(file_name);
            let relative = RepositoryPath(relative.to_string_lossy().replace('\\', "/"));
            let source = root.join(Path::new(&relative.0));
            let metadata = fs::symlink_metadata(&source).map_err(|error| {
                format!(
                    "Go package {} lists unreadable source {}: {error}",
                    item.import_path, relative.0
                )
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "Go package {} source is not a plain file: {}",
                    item.import_path, relative.0
                ));
            }
            source_bytes = source_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| format!("Go package {} source size overflowed", item.import_path))?;
            source_documents.insert(relative);
        }
        if source_documents.is_empty() {
            return Err(format!(
                "Go package {} has no compiler-selected source documents",
                item.import_path
            ));
        }
        for document in &source_documents {
            if let Some(owner) = document_owners.insert(document.clone(), item.import_path.clone())
            {
                return Err(format!(
                    "Go source document {} belongs to both {owner} and {}",
                    document.0, item.import_path
                ));
            }
        }
        let package = GoPackage {
            import_path: item.import_path.clone(),
            source_documents,
            source_bytes,
        };
        if packages.insert(item.import_path.clone(), package).is_some() {
            return Err(format!(
                "Go package inventory repeats import path {}",
                item.import_path
            ));
        }
    }
    if packages.is_empty() {
        return Err("Go package inventory selected no repository packages".to_string());
    }
    Ok(packages.into_values().collect())
}

pub(super) fn plan_go_package_shards_with_limits(
    mut packages: Vec<GoPackage>,
    limits: GoShardLimits,
) -> Result<Vec<GoPackageShard>, String> {
    let GoShardLimits {
        target_source_bytes,
        max_packages,
    } = limits;
    if packages.is_empty() {
        return Err("Go package sharding requires at least one package".to_string());
    }
    if target_source_bytes == 0 || max_packages == 0 {
        return Err("Go package sharding limits must be positive".to_string());
    }
    let total_source_bytes = packages.iter().try_fold(0u64, |total, package| {
        total
            .checked_add(package.source_bytes)
            .ok_or_else(|| "Go package inventory source size overflowed".to_string())
    })?;
    let by_bytes = total_source_bytes.div_ceil(target_source_bytes).max(1);
    let by_count = packages.len().div_ceil(max_packages);
    let shard_count = usize::try_from(by_bytes)
        .map_err(|_| "Go package shard count overflowed".to_string())?
        .max(by_count)
        .min(packages.len());

    packages.sort_by(|left, right| {
        right
            .source_bytes
            .cmp(&left.source_bytes)
            .then_with(|| left.import_path.cmp(&right.import_path))
    });
    let mut shards = (0..shard_count)
        .map(|_| GoPackageShard {
            packages: Vec::new(),
            source_bytes: 0,
        })
        .collect::<Vec<_>>();
    for package in packages {
        let (index, _) = shards
            .iter()
            .enumerate()
            .filter(|(_, shard)| shard.packages.len() < max_packages)
            .min_by_key(|(index, shard)| (shard.source_bytes, *index))
            .ok_or_else(|| "Go package sharding exhausted every bounded shard".to_string())?;
        shards[index].source_bytes = shards[index]
            .source_bytes
            .checked_add(package.source_bytes)
            .ok_or_else(|| "Go package shard source size overflowed".to_string())?;
        shards[index].packages.push(package);
    }
    for shard in &mut shards {
        shard
            .packages
            .sort_by(|left, right| left.import_path.cmp(&right.import_path));
    }
    shards.sort_by(|left, right| {
        left.packages[0]
            .import_path
            .cmp(&right.packages[0].import_path)
    });
    validate_shard_coverage(&shards)?;
    Ok(shards)
}

pub(super) fn shard_pairs(shard_count: usize) -> Vec<(usize, usize)> {
    (0..shard_count)
        .flat_map(|left| ((left + 1)..shard_count).map(move |right| (left, right)))
        .collect()
}

fn validate_shard_coverage(shards: &[GoPackageShard]) -> Result<(), String> {
    let mut packages = BTreeSet::new();
    let mut documents = BTreeSet::new();
    for shard in shards {
        if shard.packages.is_empty() {
            return Err("Go package sharding produced an empty shard".to_string());
        }
        for package in &shard.packages {
            if !packages.insert(&package.import_path) {
                return Err(format!(
                    "Go package {} appeared in more than one shard",
                    package.import_path
                ));
            }
            for document in &package.source_documents {
                if !documents.insert(document) {
                    return Err(format!(
                        "Go source document {} appeared in more than one shard",
                        document.0
                    ));
                }
            }
        }
    }
    Ok(())
}

fn go_package_relative_directory(root: &Path, raw: &str) -> Result<PathBuf, String> {
    let normalized = raw.replace('\\', "/");
    if normalized == "/workspace" {
        return Ok(PathBuf::new());
    }
    if let Some(relative) = normalized.strip_prefix("/workspace/") {
        let relative = PathBuf::from(relative);
        require_safe_relative_path(&relative)?;
        return Ok(relative);
    }
    let directory = fs::canonicalize(raw)
        .map_err(|error| format!("failed to resolve Go package directory {raw}: {error}"))?;
    let relative = directory.strip_prefix(root).map_err(|_| {
        format!(
            "Go package directory {} is outside the staged repository",
            directory.display()
        )
    })?;
    require_safe_relative_path(relative)?;
    Ok(relative.to_path_buf())
}

fn require_plain_file_name(name: &str) -> Result<(), String> {
    let path = Path::new(name);
    let mut components = path.components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        return Ok(());
    }
    Err(format!(
        "Go package inventory contains unsafe source name {name:?}"
    ))
}

fn require_safe_relative_path(path: &Path) -> Result<(), String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "Go package inventory contains unsafe repository directory {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, bytes: u64) -> GoPackage {
        GoPackage {
            import_path: format!("example.test/{name}"),
            source_documents: BTreeSet::from([RepositoryPath(format!("{name}/{name}.go"))]),
            source_bytes: bytes,
        }
    }

    #[test]
    fn parses_streamed_go_list_inventory_and_source_weights() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("a")).unwrap();
        fs::create_dir(root.path().join("b")).unwrap();
        fs::write(root.path().join("a/a.go"), "package a\n").unwrap();
        fs::write(root.path().join("a/a_test.go"), "package a\n").unwrap();
        fs::write(root.path().join("b/b.go"), "package b\n").unwrap();
        let output = concat!(
            r#"{"ImportPath":"example.test/a","Dir":"/workspace/a","GoFiles":["a.go"],"TestGoFiles":["a_test.go"]}"#,
            r#"{"ImportPath":"example.test/b","Dir":"/workspace/b","GoFiles":["b.go"]}"#,
        );

        let packages = parse_go_package_inventory(root.path(), output).unwrap();

        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].import_path, "example.test/a");
        assert_eq!(packages[0].source_documents.len(), 2);
        assert_eq!(packages[0].source_bytes, 20);
        assert_eq!(packages[1].source_bytes, 10);
    }

    #[test]
    fn weighted_shards_are_deterministic_and_cover_every_pair() {
        let packages = vec![
            package("a", 8),
            package("b", 7),
            package("c", 6),
            package("d", 5),
            package("e", 4),
        ];

        let limits = GoShardLimits {
            target_source_bytes: 10,
            max_packages: 2,
        };
        let first = plan_go_package_shards_with_limits(packages.clone(), limits).unwrap();
        let second = plan_go_package_shards_with_limits(packages, limits).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 3);
        assert!(first.iter().all(|shard| shard.packages.len() <= 2));
        assert_eq!(shard_pairs(first.len()), vec![(0, 1), (0, 2), (1, 2)]);
        let selected = first
            .iter()
            .flat_map(GoPackageShard::patterns)
            .collect::<BTreeSet<_>>();
        assert_eq!(selected.len(), 5);
    }

    #[test]
    fn inventory_rejects_paths_outside_the_repository() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("escape.go"), "package escape\n").unwrap();
        let output = format!(
            r#"{{"ImportPath":"example.test/escape","Dir":{},"GoFiles":["escape.go"]}}"#,
            serde_json::to_string(&outside.path().to_string_lossy()).unwrap()
        );

        let error = parse_go_package_inventory(root.path(), &output).unwrap_err();

        assert!(error.contains("outside the staged repository"));
    }
}
