use super::super::intentional_boundary_project_model::hash_json;
use super::{
    IntentionalBoundaryProjectModelGoArchitecture, IntentionalBoundaryProjectModelVariant,
};
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

#[derive(Debug, PartialEq, Eq)]
pub(super) struct GoConstraintTagDomain {
    pub(super) custom_build_tags: Vec<String>,
    pub(super) architecture_feature_tags: Vec<String>,
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
    dependency_preparation_identity: &str,
) -> Result<String, String> {
    hash_json(&(
        "sniff-go-project-model-pipeline-v2",
        toolchain_identity_sha256,
        dependency_preparation_identity,
        GO_CONSTRAINT_HELPER_SOURCE,
    ))
}

pub(super) fn parse_go_constraint_tags(
    stdout: &str,
    source_repository_paths: &[String],
    platform_stdout: &str,
) -> Result<GoConstraintTagDomain, String> {
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
    let mut architecture_features = BTreeSet::new();
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
                || matches!(tag.as_str(), "cgo" | "gc" | "unix")
                || is_go_release_tag(tag)
                || tag == "ignore"
            {
                continue;
            }
            if matches!(tag.as_str(), "gccgo" | "race" | "msan" | "asan" | "fuzz")
                || tag.starts_with("goexperiment.")
            {
                return Err(format!(
                    "Go source requires unsupported compiler build mode tag {tag}"
                ));
            }
            if let Some((architecture, feature)) = tag.split_once('.')
                && architecture_tags.contains(architecture)
            {
                if go_architecture_environment_variable(architecture).is_none() {
                    return Err(format!(
                        "Go source requires an unsupported architecture feature tag {tag}"
                    ));
                }
                if !valid_architecture_feature(architecture, feature) {
                    return Err(format!(
                        "Go source requires an unsupported architecture feature tag {tag}"
                    ));
                }
                architecture_features.insert(tag.clone());
                continue;
            }
            custom.insert(tag.clone());
        }
    }
    Ok(GoConstraintTagDomain {
        custom_build_tags: custom.into_iter().collect(),
        architecture_feature_tags: architecture_features.into_iter().collect(),
    })
}

fn valid_architecture_feature(goarch: &str, feature: &str) -> bool {
    match goarch {
        "386" => matches!(feature, "sse2" | "softfloat"),
        "amd64" => version_level(feature, 'v').is_some_and(|level| level >= 1),
        "arm" => feature.parse::<u32>().is_ok_and(|level| level >= 5),
        "arm64" => feature
            .strip_prefix('v')
            .and_then(|level| level.split_once('.'))
            .is_some_and(|(major, minor)| {
                major.parse::<u32>().is_ok_and(|major| major >= 8) && minor.parse::<u32>().is_ok()
            }),
        "mips" | "mipsle" | "mips64" | "mips64le" => {
            matches!(feature, "hardfloat" | "softfloat")
        }
        "ppc64" | "ppc64le" => feature
            .strip_prefix("power")
            .and_then(|level| level.parse::<u32>().ok())
            .is_some_and(|level| level >= 8),
        "riscv64" => feature
            .strip_prefix("rva")
            .and_then(|level| level.strip_suffix("u64"))
            .is_some_and(|level| {
                !level.is_empty() && level.bytes().all(|byte| byte.is_ascii_digit())
            }),
        "wasm" => matches!(feature, "satconv" | "signext"),
        _ => false,
    }
}

pub(in crate::benchmark::release) fn valid_go_architecture_configuration(
    goarch: &str,
    value: &str,
) -> bool {
    if goarch != "wasm" {
        return valid_architecture_feature(goarch, value);
    }
    let features = value.split(',').collect::<Vec<_>>();
    !features.is_empty()
        && !features.iter().any(|feature| feature.is_empty())
        && !features.windows(2).any(|pair| pair[0] >= pair[1])
        && features
            .iter()
            .all(|feature| valid_architecture_feature(goarch, feature))
}

fn version_level(value: &str, prefix: char) -> Option<u32> {
    value.strip_prefix(prefix)?.parse().ok()
}

pub(super) fn parse_go_dist_variants(
    stdout: &str,
    tag_domain: &GoConstraintTagDomain,
) -> Result<Vec<IntentionalBoundaryProjectModelVariant>, String> {
    let build_tags = &tag_domain.custom_build_tags;
    if build_tags.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("Go custom build tags are not strictly ordered".to_string());
    }
    if tag_domain
        .architecture_feature_tags
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err("Go architecture feature tags are not strictly ordered".to_string());
    }
    let platforms = parse_go_dist_platforms(stdout)?;
    let architecture_contexts = platforms
        .iter()
        .map(|platform| {
            architecture_configurations(&platform.goarch, &tag_domain.architecture_feature_tags)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let platform_context_count = platforms.iter().zip(&architecture_contexts).try_fold(
        0usize,
        |count, (platform, architectures)| {
            (if platform.cgo_supported { 2usize } else { 1 })
                .checked_mul(architectures.len())
                .and_then(|platform_count| count.checked_add(platform_count))
        },
    );
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
    for (platform, architectures) in platforms.into_iter().zip(architecture_contexts) {
        for cgo_enabled in
            [false, true]
                .into_iter()
                .take(if platform.cgo_supported { 2 } else { 1 })
        {
            for architecture in &architectures {
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
                        architecture: architecture.clone(),
                    });
                }
            }
        }
    }
    variants.sort();
    if variants.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("Go platform discovery repeated a build variant".to_string());
    }
    Ok(variants)
}

fn architecture_configurations(
    goarch: &str,
    architecture_feature_tags: &[String],
) -> Result<Vec<IntentionalBoundaryProjectModelGoArchitecture>, String> {
    let prefix = format!("{goarch}.");
    let features = architecture_feature_tags
        .iter()
        .filter_map(|tag| tag.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    let mut contexts = BTreeSet::from([IntentionalBoundaryProjectModelGoArchitecture::Default]);
    if features.is_empty() {
        return Ok(contexts.into_iter().collect());
    }
    let environment_variable = go_architecture_environment_variable(goarch).ok_or_else(|| {
        format!("Go architecture {goarch} has feature tags but no modeled environment variable")
    })?;
    if goarch == "wasm" {
        let shift = u32::try_from(features.len())
            .map_err(|_| "Go WebAssembly feature domain is unbounded".to_string())?;
        let assignments = 1usize
            .checked_shl(shift)
            .ok_or_else(|| "Go WebAssembly feature domain is unbounded".to_string())?;
        if assignments > GO_VARIANT_LIMIT {
            return Err(format!(
                "Go WebAssembly feature domain requires {assignments} contexts, exceeding the limit of {GO_VARIANT_LIMIT}"
            ));
        }
        for assignment in 1..assignments {
            let value = features
                .iter()
                .enumerate()
                .filter(|(index, _)| assignment & (1usize << index) != 0)
                .map(|(_, feature)| *feature)
                .collect::<Vec<_>>()
                .join(",");
            contexts.insert(explicit_architecture(environment_variable, value));
        }
        return Ok(contexts.into_iter().collect());
    }

    for feature in features {
        contexts.insert(explicit_architecture(environment_variable, feature));
        if let Some(alternate) = architecture_alternate(goarch, feature)? {
            contexts.insert(explicit_architecture(environment_variable, alternate));
        }
        if contexts.len() > GO_VARIANT_LIMIT {
            return Err(format!(
                "Go architecture feature domain requires more than {GO_VARIANT_LIMIT} contexts"
            ));
        }
    }
    Ok(contexts.into_iter().collect())
}

fn explicit_architecture(
    environment_variable: &str,
    value: impl Into<String>,
) -> IntentionalBoundaryProjectModelGoArchitecture {
    IntentionalBoundaryProjectModelGoArchitecture::Explicit {
        environment_variable: environment_variable.to_string(),
        value: value.into(),
    }
}

fn architecture_alternate(goarch: &str, feature: &str) -> Result<Option<String>, String> {
    let alternate = match goarch {
        "386" => Some(if feature == "sse2" {
            "softfloat".to_string()
        } else {
            "sse2".to_string()
        }),
        "amd64" => numeric_predecessor(feature, 'v', 1),
        "arm" => integer_predecessor(feature, 5),
        "arm64" => arm64_predecessor(feature)?,
        "mips" | "mipsle" | "mips64" | "mips64le" => Some(
            if feature == "hardfloat" {
                "softfloat"
            } else {
                "hardfloat"
            }
            .to_string(),
        ),
        "ppc64" | "ppc64le" => feature
            .strip_prefix("power")
            .and_then(|value| integer_predecessor(value, 8))
            .map(|value| format!("power{value}")),
        "riscv64" => match feature {
            "rva23u64" => Some("rva22u64".to_string()),
            "rva22u64" => Some("rva20u64".to_string()),
            "rva20u64" => None,
            _ => Some("rva20u64".to_string()),
        },
        _ => {
            return Err(format!(
                "Go architecture feature {goarch}.{feature} has no exact context mapping"
            ));
        }
    };
    Ok(alternate)
}

fn numeric_predecessor(value: &str, prefix: char, minimum: u32) -> Option<String> {
    let number = version_level(value, prefix)?;
    (number > minimum).then(|| format!("{prefix}{}", number - 1))
}

fn integer_predecessor(value: &str, minimum: u32) -> Option<String> {
    let number = value.parse::<u32>().ok()?;
    (number > minimum).then(|| (number - 1).to_string())
}

fn arm64_predecessor(value: &str) -> Result<Option<String>, String> {
    let Some((major, minor)) = value
        .strip_prefix('v')
        .and_then(|value| value.split_once('.'))
    else {
        return Ok(Some("v8.0".to_string()));
    };
    let major = major
        .parse::<u32>()
        .map_err(|_| format!("invalid Go ARM64 feature level {value}"))?;
    let minor = minor
        .parse::<u32>()
        .map_err(|_| format!("invalid Go ARM64 feature level {value}"))?;
    Ok(match (major, minor) {
        (8, 0) => None,
        (_, 0) => Some(format!("v{}.9", major.saturating_sub(1))),
        _ => Some(format!("v{major}.{}", minor - 1)),
    })
}

pub(in crate::benchmark::release) fn go_architecture_environment_variable(
    goarch: &str,
) -> Option<&'static str> {
    match goarch {
        "386" => Some("GO386"),
        "amd64" => Some("GOAMD64"),
        "arm" => Some("GOARM"),
        "arm64" => Some("GOARM64"),
        "mips" | "mipsle" => Some("GOMIPS"),
        "mips64" | "mips64le" => Some("GOMIPS64"),
        "ppc64" | "ppc64le" => Some("GOPPC64"),
        "riscv64" => Some("GORISCV64"),
        "wasm" => Some("GOWASM"),
        _ => None,
    }
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
