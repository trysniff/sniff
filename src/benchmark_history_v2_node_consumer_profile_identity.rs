use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(super) fn package_directory(manifest: &str) -> Result<String, String> {
    manifest
        .strip_suffix("package.json")
        .map(|value| value.trim_end_matches('/').to_string())
        .ok_or_else(|| "Node consumer profile manifest path changed".to_string())
}

pub(super) fn within_package(directory: &str, path: &str) -> bool {
    directory.is_empty() || path.starts_with(&format!("{directory}/"))
}

pub(super) fn package_specifier(name: &str, public_subpath: &str) -> Result<String, String> {
    if name.trim().is_empty() || name.contains('\\') || name.starts_with('.') {
        return Err("Node consumer profile package name is invalid".to_string());
    }
    if public_subpath == "." {
        Ok(name.to_string())
    } else {
        let suffix = public_subpath
            .strip_prefix("./")
            .ok_or_else(|| "Node consumer profile public subpath is invalid".to_string())?;
        Ok(format!("{name}/{suffix}"))
    }
}

pub(super) fn sorted_exposure_ids(exposures: &[&HistoricalV2NodePackageExposure]) -> Vec<String> {
    let mut values = exposures
        .iter()
        .map(|exposure| exposure.exposure_id.clone())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

pub(super) fn is_typescript_javascript_source(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

pub(super) fn require_same_identity(
    observed: &mut Option<String>,
    value: String,
    label: &str,
) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    if observed.as_ref().is_some_and(|existing| existing != &value) {
        return Err(format!("{label} changed across profiles"));
    }
    *observed = Some(value);
    Ok(())
}

pub(super) fn count_by_mode(
    profiles: &[HistoricalV2NodeConsumerProfile],
) -> BTreeMap<HistoricalV2NodeConsumerMode, usize> {
    profiles
        .iter()
        .fold(BTreeMap::new(), |mut counts, profile| {
            *counts.entry(profile.mode).or_insert(0) += 1;
            counts
        })
}

pub(super) fn unresolved_count(profiles: &[HistoricalV2NodeConsumerProfile]) -> usize {
    profiles
        .iter()
        .flat_map(|profile| [&profile.compiler, &profile.runtime])
        .filter(|resolution| {
            matches!(
                resolution,
                HistoricalV2NodeConsumerResolution::Unresolved { .. }
            )
        })
        .count()
}

pub(super) fn profile_id(profile: &HistoricalV2NodeConsumerProfile) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-node-consumer-profile-v1",
        (
            &profile.consumer_surface_slot_id,
            &profile.manifest_repository_path,
            &profile.manifest_object_id,
            &profile.package_name,
            &profile.public_subpath,
            &profile.specifier,
            profile.mode,
            &profile.project_model_execution_id,
            &profile.compiler_project_config_repository_path,
        ),
        (
            &profile.compiler_options_sha256,
            &profile.toolchain_identity_sha256,
            &profile.compiler_module_resolution,
            &profile.compiler_conditions,
            &profile.custom_conditions,
            &profile.declared_exposure_ids,
            &profile.compiler,
            &profile.runtime,
        ),
    ))
    .map(|hash| format!("h2ncp-v1:{hash}"))
}

pub(super) fn consumer_surface_slot_id(
    document: &HistoricalV2NodePackageDocument,
    public_subpath: &str,
    mode: HistoricalV2NodeConsumerMode,
    compiler_project_config_repository_path: Option<&str>,
) -> Result<String, String> {
    let package_identity = document.package_name.as_deref().map_or_else(
        || ("manifest_path", document.manifest_repository_path.as_str()),
        |name| ("package_name", name),
    );
    hash_json(&(
        "sniffbench-historical-v2-node-consumer-surface-slot-v1",
        package_identity,
        public_subpath,
        mode,
        compiler_project_config_repository_path,
    ))
    .map(|hash| format!("h2ncs-v1:{hash}"))
}

pub(super) fn consumer_profile_census_sha256(
    census: &HistoricalV2NodeConsumerProfileCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        &census.node_package_surface_census_sha256,
        &census.typescript_project_model_census_sha256,
        &census.typescript_compiler_version,
        &census.node_runtime_version,
        &census.node_runtime_sha256,
        &census.profiles,
        &census.profile_count_by_mode,
        census.unresolved_resolution_count,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit Node consumer profiles: {error}"))
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("{label} is invalid"))
    }
}
