use super::intentional_boundary_project_model_cargo::{
    CARGO_COMMAND_CONTRACT, validate_cargo_target_classification,
};
use super::intentional_boundary_project_model_go::{
    GO_LIST_COMMAND_CONTRACT, validate_go_target_classification,
};
use super::{
    BoundaryGitEntryKind, INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelProvider as Provider, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryProjectModelTargetStatus as TargetStatus,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundaryTrackedEntry,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub(super) const PROJECT_MODEL_CONTRACT: &str = "sniffbench-intentional-boundary-project-model-v2";

#[derive(Serialize)]
struct NormalizedTarget<'a> {
    provider: Provider,
    manifest_repository_path: &'a str,
    manifest_object_id: &'a str,
    package_name: &'a str,
    package_version: &'a str,
    target_name: &'a str,
    provider_kinds: &'a [String],
    provider_output_types: &'a [String],
    source_repository_paths: &'a [String],
    required_features: &'a [String],
    target_status: &'a TargetStatus,
}

pub(super) fn compute_normalized_model_sha256(
    provider: Provider,
    covered_manifest_repository_paths: &[String],
    targets: &[IntentionalBoundaryProjectModelTarget],
) -> Result<String, String> {
    let mut normalized_targets = targets
        .iter()
        .map(|target| {
            if target.provider != provider {
                return Err("project-model normalization mixed providers".to_string());
            }
            serde_json::to_vec(&normalized_target(target))
                .map_err(|error| format!("failed to normalize project-model target: {error}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    normalized_targets.sort();
    hash_json(&(
        "sniffbench-intentional-boundary-normalized-project-model-v2",
        provider,
        covered_manifest_repository_paths,
        normalized_targets,
    ))
}

pub(super) fn compute_execution_id(
    provider: Provider,
    invocation_anchor_repository_path: &str,
    invocation_anchor_object_id: &str,
    toolchain_identity_sha256: &str,
    command_contract: &str,
    normalized_model_sha256: &str,
) -> Result<String, String> {
    Ok(format!(
        "ibpme-v2:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-project-model-execution-v2",
            provider,
            invocation_anchor_repository_path,
            invocation_anchor_object_id,
            toolchain_identity_sha256,
            command_contract,
            normalized_model_sha256,
        ))?
    ))
}

pub(super) fn compute_target_id(
    target: &IntentionalBoundaryProjectModelTarget,
) -> Result<String, String> {
    Ok(format!(
        "ibpmt-v2:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-project-model-target-v2",
            &target.execution_id,
            normalized_target(target),
        ))?
    ))
}

pub(super) fn finish_project_model_census(
    inventory: &IntentionalBoundaryRepositoryInventory,
    mut executions: Vec<IntentionalBoundaryProjectModelExecution>,
    mut targets: Vec<IntentionalBoundaryProjectModelTarget>,
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    executions.sort();
    targets.sort();
    if executions.windows(2).any(|pair| pair[0] >= pair[1])
        || targets.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("project-model census contains duplicate records".to_string());
    }
    let execution_ids = executions
        .iter()
        .map(|execution| execution.execution_id.as_str())
        .collect::<BTreeSet<_>>();
    if targets
        .iter()
        .any(|target| !execution_ids.contains(target.execution_id.as_str()))
        || executions.iter().any(|execution| {
            execution.target_count
                != targets
                    .iter()
                    .filter(|target| target.execution_id == execution.execution_id)
                    .count()
        })
    {
        return Err("project-model target execution commitment changed".to_string());
    }
    let execution_count_by_provider =
        executions
            .iter()
            .fold(BTreeMap::new(), |mut counts, execution| {
                *counts.entry(execution.provider).or_insert(0) += 1;
                counts
            });
    let target_count_by_status = target_status_counts(&targets);
    let mut census = IntentionalBoundaryProjectModelCensus {
        schema_version: INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
        project_model_contract: PROJECT_MODEL_CONTRACT.to_string(),
        repository: inventory.repository.clone(),
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        executions,
        targets,
        execution_count_by_provider,
        target_count_by_status,
        project_model_census_sha256: String::new(),
    };
    census.project_model_census_sha256 = compute_project_model_census_sha256(&census)?;
    Ok(census)
}

pub fn validate_intentional_boundary_project_model_census_commitment(
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &IntentionalBoundaryProjectModelCensus,
) -> Result<(), String> {
    if census.schema_version != INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION
        || census.project_model_contract != PROJECT_MODEL_CONTRACT
        || census.repository != inventory.repository
        || census.revision != inventory.revision
        || census.inventory_sha256 != inventory.inventory_sha256
        || census.executions.windows(2).any(|pair| pair[0] >= pair[1])
        || census.targets.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("intentional-boundary project-model identity changed".to_string());
    }
    for execution in &census.executions {
        let command_contract = match execution.provider {
            Provider::CargoMetadata => CARGO_COMMAND_CONTRACT,
            Provider::GoList => GO_LIST_COMMAND_CONTRACT,
            Provider::GradleToolingApi => {
                return Err(
                    "intentional-boundary project-model provider is not implemented".to_string(),
                );
            }
        };
        if execution.command_contract != command_contract
            || !is_sha256(&execution.toolchain_identity_sha256)
            || !is_sha256(&execution.normalized_model_sha256)
        {
            return Err("intentional-boundary project-model execution changed".to_string());
        }
        let invocation = regular_inventory_entry(
            inventory,
            &execution.invocation_anchor_repository_path,
            "project-model invocation anchor",
        )?;
        let covered = execution
            .covered_manifest_repository_paths
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if invocation.object_id != execution.invocation_anchor_object_id
            || covered.len() != execution.covered_manifest_repository_paths.len()
            || !covered.contains(&execution.invocation_anchor_repository_path)
        {
            return Err("intentional-boundary project-model invocation changed".to_string());
        }
        for path in &covered {
            regular_inventory_entry(inventory, path, "project-model covered manifest")?;
        }
        let targets = census
            .targets
            .iter()
            .filter(|target| target.execution_id == execution.execution_id)
            .cloned()
            .collect::<Vec<_>>();
        if execution.target_count != targets.len()
            || targets.iter().any(|target| {
                target.provider != execution.provider
                    || !covered.contains(&target.manifest_repository_path)
            })
            || compute_normalized_model_sha256(
                execution.provider,
                &execution.covered_manifest_repository_paths,
                &targets,
            )? != execution.normalized_model_sha256
            || compute_execution_id(
                execution.provider,
                &execution.invocation_anchor_repository_path,
                &execution.invocation_anchor_object_id,
                &execution.toolchain_identity_sha256,
                &execution.command_contract,
                &execution.normalized_model_sha256,
            )? != execution.execution_id
        {
            return Err(
                "intentional-boundary project-model execution commitment changed".to_string(),
            );
        }
    }
    let execution_ids = census
        .executions
        .iter()
        .map(|execution| execution.execution_id.as_str())
        .collect::<BTreeSet<_>>();
    for target in &census.targets {
        let manifest = regular_inventory_entry(
            inventory,
            &target.manifest_repository_path,
            "project-model target manifest",
        )?;
        if !execution_ids.contains(target.execution_id.as_str())
            || manifest.object_id != target.manifest_object_id
            || target.package_name.trim().is_empty()
            || target.package_version.trim().is_empty()
            || target.target_name.trim().is_empty()
            || target.provider_kinds.is_empty()
            || target.provider_output_types.is_empty()
            || !sorted_unique(&target.provider_kinds)
            || !sorted_unique(&target.provider_output_types)
            || !sorted_unique(&target.source_repository_paths)
            || !sorted_unique(&target.required_features)
            || target
                .source_repository_paths
                .iter()
                .any(|path| !is_safe_repository_path(path))
            || !validate_target_classification(inventory, target)
            || compute_target_id(target)? != target.target_id
        {
            return Err("intentional-boundary project-model target commitment changed".to_string());
        }
    }
    let expected_execution_counts =
        census
            .executions
            .iter()
            .fold(BTreeMap::new(), |mut counts, execution| {
                *counts.entry(execution.provider).or_insert(0) += 1;
                counts
            });
    if census.execution_count_by_provider != expected_execution_counts
        || census.target_count_by_status != target_status_counts(&census.targets)
        || compute_project_model_census_sha256(census)? != census.project_model_census_sha256
    {
        return Err("intentional-boundary project-model census commitment changed".to_string());
    }
    Ok(())
}

fn validate_target_classification(
    inventory: &IntentionalBoundaryRepositoryInventory,
    target: &IntentionalBoundaryProjectModelTarget,
) -> bool {
    match target.provider {
        Provider::CargoMetadata => validate_cargo_target_classification(inventory, target),
        Provider::GoList => validate_go_target_classification(inventory, target),
        Provider::GradleToolingApi => false,
    }
}

fn normalized_target(target: &IntentionalBoundaryProjectModelTarget) -> NormalizedTarget<'_> {
    NormalizedTarget {
        provider: target.provider,
        manifest_repository_path: &target.manifest_repository_path,
        manifest_object_id: &target.manifest_object_id,
        package_name: &target.package_name,
        package_version: &target.package_version,
        target_name: &target.target_name,
        provider_kinds: &target.provider_kinds,
        provider_output_types: &target.provider_output_types,
        source_repository_paths: &target.source_repository_paths,
        required_features: &target.required_features,
        target_status: &target.target_status,
    }
}

fn target_status_counts(
    targets: &[IntentionalBoundaryProjectModelTarget],
) -> BTreeMap<String, usize> {
    targets.iter().fold(BTreeMap::new(), |mut counts, target| {
        let status = match target.target_status {
            TargetStatus::Boundary { .. } => "boundary",
            TargetStatus::NonBoundary { .. } => "non_boundary",
            TargetStatus::Unresolved { .. } => "unresolved",
        };
        *counts.entry(status.to_string()).or_insert(0) += 1;
        counts
    })
}

fn compute_project_model_census_sha256(
    census: &IntentionalBoundaryProjectModelCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.project_model_contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        &census.executions,
        &census.targets,
        &census.execution_count_by_provider,
        &census.target_count_by_status,
    ))
}

pub(super) fn regular_inventory_entry<'a>(
    inventory: &'a IntentionalBoundaryRepositoryInventory,
    repository_path: &str,
    label: &str,
) -> Result<&'a IntentionalBoundaryTrackedEntry, String> {
    let entry = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == repository_path)
        .ok_or_else(|| format!("{label} is absent from the immutable Git inventory"))?;
    if entry.kind != BoundaryGitEntryKind::RegularBlob {
        return Err(format!("{label} is not a regular Git blob"));
    }
    Ok(entry)
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_safe_repository_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.contains('\0')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

pub(super) fn hash_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to commit project-model facts: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
