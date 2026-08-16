use super::{
    HISTORICAL_V2_EXECUTION_HARNESS_SCHEMA_VERSION, HistoricalV2ExecutionBaseImage,
    HistoricalV2ExecutionHarness,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

const HARNESS_BYTES: &[u8] =
    include_bytes!("benchmark_assets/historical-v2-execution-harness.json");
const HARNESS_CONTRACT: &str = "sniffbench-historical-v2-execution-harness-v1";
const UPSTREAM_REPOSITORY: &str = "github.com/SWE-rebench/SWE-rebench-V2";
const UPSTREAM_REVISION: &str = "c71902a8cf8d2b725f63d51f199f4d3e56f68d2d";
const BASE_DOCKERFILES_TREE_OID: &str = "a528bfd81b78b88c43907966d2223fabfe6b93b6";
const EXECUTION_PLATFORM: &str = "linux/amd64";
const REQUIRED_LANGUAGES: &[&str] = &["go", "javascript", "kotlin", "python", "rust", "typescript"];

pub fn historical_v2_execution_harness() -> Result<HistoricalV2ExecutionHarness, String> {
    validate_historical_v2_execution_harness(HARNESS_BYTES)
}

pub fn validate_historical_v2_execution_harness(
    bytes: &[u8],
) -> Result<HistoricalV2ExecutionHarness, String> {
    let harness = serde_json::from_slice::<HistoricalV2ExecutionHarness>(bytes)
        .map_err(|error| format!("invalid historical-v2 execution harness: {error}"))?;
    if harness.schema_version != HISTORICAL_V2_EXECUTION_HARNESS_SCHEMA_VERSION
        || harness.execution_harness_contract != HARNESS_CONTRACT
        || harness.upstream_repository != UPSTREAM_REPOSITORY
        || harness.upstream_revision != UPSTREAM_REVISION
        || harness.base_dockerfiles_tree_oid != BASE_DOCKERFILES_TREE_OID
        || harness.execution_platform != EXECUTION_PLATFORM
        || !harness.install_network_enabled
        || harness.test_network_enabled
        || !harness.dataset_labels_forbidden
        || !harness.install_failures_are_terminal
        || harness.execution_harness_sha256 != harness_sha256(&harness)?
    {
        return Err("historical-v2 execution harness commitment changed".to_string());
    }
    validate_images(&harness.supported_images)?;
    Ok(harness)
}

pub fn resolve_historical_v2_base_image<'a>(
    harness: &'a HistoricalV2ExecutionHarness,
    language: &str,
    requested_name: &str,
) -> Result<&'a HistoricalV2ExecutionBaseImage, String> {
    let canonical_name = requested_name
        .strip_suffix(":latest")
        .unwrap_or(requested_name);
    harness
        .supported_images
        .iter()
        .find(|image| {
            image.base_image_name == canonical_name
                && image
                    .languages
                    .iter()
                    .any(|candidate| candidate == language)
        })
        .ok_or_else(|| {
            format!("historical-v2 base image is not pinned for {language}: {requested_name}")
        })
}

pub fn validate_historical_v2_execution_harness_repository(
    root: &Path,
    harness: &HistoricalV2ExecutionHarness,
) -> Result<(), String> {
    if harness != &historical_v2_execution_harness()? {
        return Err("historical-v2 execution harness artifact changed".to_string());
    }
    validate_harness_repository_identity(root, harness)
}

fn validate_harness_repository_identity(
    root: &Path,
    harness: &HistoricalV2ExecutionHarness,
) -> Result<(), String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("failed to resolve execution harness repository: {error}"))?;
    if !root.is_dir() {
        return Err("historical-v2 execution harness repository is not a directory".to_string());
    }
    if git_text(&root, &["rev-parse", "HEAD"])? != harness.upstream_revision
        || git_text(&root, &["rev-parse", "--is-shallow-repository"])? != "false"
        || !git_text(
            &root,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?
        .is_empty()
        || git_text(&root, &["rev-parse", "HEAD:base_dockerfiles"])?
            != harness.base_dockerfiles_tree_oid
    {
        return Err("historical-v2 execution harness Git identity changed".to_string());
    }
    let origin = git_text(&root, &["remote", "get-url", "origin"])?;
    if canonical_repository(&origin).as_deref() != Some(harness.upstream_repository.as_str()) {
        return Err("historical-v2 execution harness origin changed".to_string());
    }
    for image in &harness.supported_images {
        let object = format!("HEAD:{}", image.dockerfile_path);
        if git_text(&root, &["rev-parse", &object])? != image.git_blob_oid {
            return Err(format!(
                "historical-v2 execution Dockerfile changed: {}",
                image.dockerfile_path
            ));
        }
    }
    Ok(())
}

fn validate_images(images: &[HistoricalV2ExecutionBaseImage]) -> Result<(), String> {
    let mut names = BTreeSet::new();
    let mut languages = BTreeMap::<&str, usize>::new();
    for image in images {
        if image.base_image_name.is_empty()
            || !names.insert(image.base_image_name.as_str())
            || !safe_dockerfile_path(&image.dockerfile_path)
            || !is_git_oid(&image.git_blob_oid)
            || image.languages.is_empty()
        {
            return Err("historical-v2 execution image manifest is invalid".to_string());
        }
        let mut image_languages = BTreeSet::new();
        for language in &image.languages {
            if !REQUIRED_LANGUAGES.contains(&language.as_str())
                || !image_languages.insert(language.as_str())
            {
                return Err("historical-v2 execution image language is invalid".to_string());
            }
            *languages.entry(language).or_default() += 1;
        }
    }
    if REQUIRED_LANGUAGES
        .iter()
        .any(|language| !languages.contains_key(language))
    {
        return Err("historical-v2 execution image manifest misses a language".to_string());
    }
    Ok(())
}

fn safe_dockerfile_path(path: &str) -> bool {
    path.starts_with("base_dockerfiles/Dockerfile_")
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn is_git_oid(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn harness_sha256(harness: &HistoricalV2ExecutionHarness) -> Result<String, String> {
    let mut committed = harness.clone();
    committed.execution_harness_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 execution harness: {error}"))
}

fn canonical_repository(value: &str) -> Option<String> {
    let normalized = value.trim().trim_end_matches('/').trim_end_matches(".git");
    let path = normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
        .or_else(|| normalized.strip_prefix("ssh://git@"))
        .or_else(|| normalized.strip_prefix("git@github.com:"))?;
    let path = if path.starts_with("github.com/") {
        path.to_string()
    } else {
        format!("github.com/{path}")
    };
    let mut segments = path.split('/');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some("github.com"), Some(owner), Some(repository), None)
            if !owner.is_empty() && !repository.is_empty() =>
        {
            Some(format!("github.com/{owner}/{repository}"))
        }
        _ => None,
    }
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute Git for execution harness: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "execution harness Git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_string())
        .map_err(|_| "execution harness Git output is not UTF-8".to_string())
}

#[cfg(test)]
#[path = "benchmark_history_v2_execution_harness_tests.rs"]
mod tests;
