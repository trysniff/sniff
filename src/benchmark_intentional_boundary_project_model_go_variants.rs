use super::super::intentional_boundary_project_model::hash_json;
use super::IntentionalBoundaryProjectModelVariant;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path};

pub(super) const GO_VARIANT_LIMIT: usize = 2_048;
const GO_CONSTRAINT_SCHEMA_VERSION: u32 = 1;
const GO_CONSTRAINT_HELPER_NAME: &str = "sniff-build-constraints.go";
const GO_CONSTRAINT_REQUEST_NAME: &str = "sniff-build-constraints-request.json";
const GO_CONSTRAINT_HELPER_SOURCE: &str =
    include_str!("../assets/go-tooling/sniff-build-constraints.go");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoDistPlatform {
    #[serde(rename = "GOOS")]
    goos: String,
    #[serde(rename = "GOARCH")]
    goarch: String,
    #[serde(rename = "CgoSupported")]
    cgo_supported: bool,
    #[serde(rename = "FirstClass")]
    _first_class: bool,
    #[serde(default, rename = "Broken")]
    broken: bool,
}

#[derive(Serialize)]
struct GoConstraintRequest<'a> {
    schema_version: u32,
    source_repository_paths: &'a [String],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoConstraintResponse {
    schema_version: u32,
    files: Vec<GoConstraintFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoConstraintFile {
    repository_path: String,
    tags: Vec<String>,
}

pub(super) struct GoConstraintInvocation {
    pub(super) helper_repository_path: String,
    pub(super) request_repository_path: String,
}

pub(super) fn stage_go_constraint_invocation(
    root: &Path,
    cache: &Path,
    source_repository_paths: &[String],
) -> Result<GoConstraintInvocation, String> {
    if source_repository_paths
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err("Go constraint source paths are not strictly ordered".to_string());
    }
    let helper = cache.join(GO_CONSTRAINT_HELPER_NAME);
    let request = cache.join(GO_CONSTRAINT_REQUEST_NAME);
    write_new(&helper, GO_CONSTRAINT_HELPER_SOURCE.as_bytes())?;
    let request_bytes = serde_json::to_vec(&GoConstraintRequest {
        schema_version: GO_CONSTRAINT_SCHEMA_VERSION,
        source_repository_paths,
    })
    .map_err(|error| format!("failed to serialize Go constraint request: {error}"))?;
    write_new(&request, &request_bytes)?;
    Ok(GoConstraintInvocation {
        helper_repository_path: runtime_repository_path(root, &helper)?,
        request_repository_path: runtime_repository_path(root, &request)?,
    })
}

pub(super) fn go_project_model_pipeline_identity(
    toolchain_identity_sha256: &str,
) -> Result<String, String> {
    hash_json(&(
        "sniff-go-project-model-pipeline-v1",
        toolchain_identity_sha256,
        GO_CONSTRAINT_HELPER_SOURCE,
    ))
}

pub(super) fn parse_go_constraint_tags(
    stdout: &str,
    source_repository_paths: &[String],
    platform_stdout: &str,
) -> Result<Vec<String>, String> {
    let response: GoConstraintResponse = serde_json::from_str(stdout)
        .map_err(|error| format!("Go constraint discovery returned invalid JSON: {error}"))?;
    if response.schema_version != GO_CONSTRAINT_SCHEMA_VERSION
        || response.files.len() != source_repository_paths.len()
    {
        return Err("Go constraint discovery returned an incompatible census".to_string());
    }
    let platforms = parse_go_dist_platforms(platform_stdout)?;
    let platform_tags = platforms
        .iter()
        .flat_map(|platform| [&platform.goos, &platform.goarch])
        .collect::<BTreeSet<_>>();
    let architecture_tags = platforms
        .iter()
        .map(|platform| platform.goarch.as_str())
        .collect::<BTreeSet<_>>();
    let mut custom = BTreeSet::new();
    for (file, expected_path) in response.files.iter().zip(source_repository_paths) {
        if file.repository_path != *expected_path
            || file.tags.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(
                "Go constraint discovery returned reordered paths or repeated tags".to_string(),
            );
        }
        for tag in &file.tags {
            if tag.is_empty() || tag.contains(',') || tag.chars().any(char::is_whitespace) {
                return Err("Go constraint discovery returned an invalid tag".to_string());
            }
            if platform_tags.contains(tag)
                || matches!(tag.as_str(), "cgo" | "gc" | "gccgo" | "unix")
                || is_go_release_tag(tag)
                || tag == "ignore"
            {
                continue;
            }
            if matches!(tag.as_str(), "race" | "msan" | "asan" | "fuzz")
                || tag.starts_with("goexperiment.")
                || architecture_tags
                    .iter()
                    .any(|architecture| tag.starts_with(&format!("{architecture}.")))
            {
                return Err(format!(
                    "Go source requires unsupported compiler build mode tag {tag}"
                ));
            }
            custom.insert(tag.clone());
        }
    }
    Ok(custom.into_iter().collect())
}

pub(super) fn parse_go_dist_variants(
    stdout: &str,
    build_tags: &[String],
) -> Result<Vec<IntentionalBoundaryProjectModelVariant>, String> {
    if build_tags.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("Go custom build tags are not strictly ordered".to_string());
    }
    let platforms = parse_go_dist_platforms(stdout)?;
    let platform_context_count = platforms.iter().try_fold(0usize, |count, platform| {
        count.checked_add(if platform.cgo_supported { 2 } else { 1 })
    });
    let shift = u32::try_from(build_tags.len())
        .map_err(|_| "Go custom build-tag domain is unbounded".to_string())?;
    let assignments = 1usize
        .checked_shl(shift)
        .ok_or_else(|| "Go custom build-tag domain is unbounded".to_string())?;
    let variant_count = platform_context_count
        .and_then(|count| count.checked_mul(assignments))
        .ok_or_else(|| "Go build-variant domain is unbounded".to_string())?;
    if variant_count > GO_VARIANT_LIMIT {
        return Err(format!(
            "Go build-variant domain has {variant_count} contexts, exceeding the strict limit of {GO_VARIANT_LIMIT}"
        ));
    }

    let mut variants = Vec::with_capacity(variant_count);
    for platform in platforms {
        for cgo_enabled in
            [false, true]
                .into_iter()
                .take(if platform.cgo_supported { 2 } else { 1 })
        {
            for assignment in 0..assignments {
                let selected_tags = build_tags
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| assignment & (1usize << index) != 0)
                    .map(|(_, tag)| tag.clone())
                    .collect();
                variants.push(IntentionalBoundaryProjectModelVariant::Go {
                    goos: platform.goos.clone(),
                    goarch: platform.goarch.clone(),
                    cgo_enabled,
                    build_tags: selected_tags,
                });
            }
        }
    }
    variants.sort();
    if variants.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("Go platform discovery repeated a build variant".to_string());
    }
    Ok(variants)
}

fn parse_go_dist_platforms(stdout: &str) -> Result<Vec<GoDistPlatform>, String> {
    let platforms: Vec<GoDistPlatform> = serde_json::from_str(stdout)
        .map_err(|error| format!("Go platform discovery returned invalid JSON: {error}"))?;
    if platforms.is_empty() {
        return Err("Go platform discovery returned no supported platforms".to_string());
    }
    let mut platform_keys = BTreeSet::new();
    for platform in &platforms {
        if !platform_component_is_valid(&platform.goos)
            || !platform_component_is_valid(&platform.goarch)
            || platform.broken
            || !platform_keys.insert((platform.goos.clone(), platform.goarch.clone()))
        {
            return Err(
                "Go platform discovery returned an invalid or repeated platform".to_string(),
            );
        }
    }
    Ok(platforms)
}

fn platform_component_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn is_go_release_tag(tag: &str) -> bool {
    tag.strip_prefix("go1.")
        .is_some_and(|minor| !minor.is_empty() && minor.bytes().all(|byte| byte.is_ascii_digit()))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => std::io::Write::write_all(&mut file, bytes)
            .map_err(|error| format!("failed to write {}: {error}", path.display())),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(format!(
            "Go constraint runtime file already exists: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "failed to create Go constraint runtime file {}: {error}",
            path.display()
        )),
    }
}

fn runtime_repository_path(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "Go constraint runtime path escaped its repository snapshot".to_string())?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("Go constraint runtime path is not safely repository-relative".to_string());
    }
    Ok(relative.to_string_lossy().replace('\\', "/"))
}
