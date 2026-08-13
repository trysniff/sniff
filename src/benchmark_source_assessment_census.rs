use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub(super) struct RepositoryCensus {
    pub(super) method_counts: BTreeMap<String, usize>,
    pub(super) observed_method_count: Option<usize>,
    pub(super) dominant_language: Option<String>,
    pub(super) supported_project_shape: bool,
    pub(super) source_inventory_sha256: String,
    pub(super) parse_failure: Option<String>,
}

pub(super) fn census_repository(root: &Path) -> Result<RepositoryCensus, String> {
    if root.join(".git").exists() {
        let status = super::assessment_state::git(
            root,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?;
        if !status.trim().is_empty() {
            return Ok(RepositoryCensus {
                method_counts: BTreeMap::new(),
                observed_method_count: None,
                dominant_language: None,
                supported_project_shape: false,
                source_inventory_sha256: sha256(&[]),
                parse_failure: Some(format!(
                    "checkout is not reproducibly clean under its Git attributes: {}",
                    status.lines().take(8).collect::<Vec<_>>().join("; ")
                )),
            });
        }
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("failed to resolve source-assessment checkout: {error}"))?;
    let paths = crate::walker::walk(
        canonical_root
            .to_str()
            .ok_or_else(|| "source-assessment checkout path is not UTF-8".to_string())?,
        &crate::config::ResolvedConfig::default(),
    )?;
    let mut counts = BTreeMap::new();
    let mut inventory = Vec::new();
    for path in paths {
        let canonical_path = fs::canonicalize(&path)
            .map_err(|error| format!("failed to resolve assessed source {path}: {error}"))?;
        let relative = canonical_path
            .strip_prefix(&canonical_root)
            .map_err(|_| "source-assessment path escaped its checkout".to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&canonical_path)
            .map_err(|error| format!("failed to read assessed source {relative}: {error}"))?;
        let record = match crate::parser::parse_file_checked(&canonical_path.to_string_lossy()) {
            Ok(record) => record,
            Err(error) => {
                return Ok(RepositoryCensus {
                    method_counts: BTreeMap::new(),
                    observed_method_count: None,
                    dominant_language: None,
                    supported_project_shape: false,
                    source_inventory_sha256: sha256(&[]),
                    parse_failure: Some(format!("{relative}: {error}")),
                });
            }
        };
        *counts.entry(record.language).or_insert(0_usize) += record.methods.len();
        inventory.push((relative, sha256(&bytes), record.methods.len()));
    }
    counts.retain(|_, count| *count > 0);
    let observed_method_count = counts.values().try_fold(0_usize, |total, count| {
        total
            .checked_add(*count)
            .ok_or_else(|| "source-assessment method census overflowed".to_string())
    })?;
    let dominant_language = counts
        .iter()
        .max_by(
            |(left_language, left_count), (right_language, right_count)| {
                left_count
                    .cmp(right_count)
                    .then_with(|| right_language.cmp(left_language))
            },
        )
        .map(|(language, _)| language.clone());
    let inventory_bytes = serde_json::to_vec(&inventory)
        .map_err(|error| format!("failed to commit source inventory: {error}"))?;
    Ok(RepositoryCensus {
        method_counts: counts,
        observed_method_count: Some(observed_method_count),
        dominant_language,
        supported_project_shape: true,
        source_inventory_sha256: sha256(&inventory_bytes),
        parse_failure: None,
    })
}

pub(super) fn license_path(root: &Path) -> Result<Option<String>, String> {
    let files = super::assessment_state::git(root, &["ls-files", "-z"])?;
    let mut licenses = files
        .split('\0')
        .filter(|path| !path.is_empty())
        .filter(|path| {
            Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    let name = name.to_ascii_lowercase();
                    ["license", "licence", "copying", "notice"]
                        .iter()
                        .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}.")))
                })
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    licenses.sort_by(|left, right| {
        left.matches('/')
            .count()
            .cmp(&right.matches('/').count())
            .then_with(|| left.cmp(right))
    });
    Ok(licenses.into_iter().next())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
