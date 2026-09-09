use super::intentional_boundary_project_model_cargo::{
    CARGO_COMMAND_CONTRACT, validate_cargo_target_classification,
};
use super::intentional_boundary_project_model_go::{
    GO_LIST_COMMAND_CONTRACT, go_architecture_environment_variable,
    valid_go_architecture_configuration, validate_go_target_classification,
};
use super::intentional_boundary_project_model_gradle::{
    GRADLE_TOOLING_COMMAND_CONTRACT, validate_gradle_target_classification,
};
use super::intentional_boundary_project_model_typescript::{
    TYPESCRIPT_PROJECT_MODEL_COMMAND_CONTRACT, validate_typescript_target_classification,
    validate_typescript_variant_inventory,
};
use super::{
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelGoArchitecture, IntentionalBoundaryProjectModelProducerTask,
    IntentionalBoundaryProjectModelProvider as Provider, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryProjectModelTargetStatus as TargetStatus,
    IntentionalBoundaryProjectModelVariant, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundaryTrackedEntry,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Component, Path};

pub(super) const PROJECT_MODEL_CONTRACT: &str = "sniffbench-intentional-boundary-project-model-v7";

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
    ignored_source_repository_paths: &'a [String],
    producer_tasks: &'a [IntentionalBoundaryProjectModelProducerTask],
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
        "sniffbench-intentional-boundary-normalized-project-model-v7",
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
    variant: &IntentionalBoundaryProjectModelVariant,
    normalized_model_sha256: &str,
) -> Result<String, String> {
    Ok(format!(
        "ibpme-v7:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-project-model-execution-v7",
            provider,
            invocation_anchor_repository_path,
            invocation_anchor_object_id,
            toolchain_identity_sha256,
            command_contract,
            variant,
            normalized_model_sha256,
        ))?
    ))
}

pub(super) fn compute_target_id(
    target: &IntentionalBoundaryProjectModelTarget,
) -> Result<String, String> {
    Ok(format!(
        "ibpmt-v7:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-project-model-target-v7",
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
            Provider::GradleToolingApi => GRADLE_TOOLING_COMMAND_CONTRACT,
            Provider::TypeScriptCompilerApi => TYPESCRIPT_PROJECT_MODEL_COMMAND_CONTRACT,
        };
        if execution.command_contract != command_contract
            || !is_sha256(&execution.toolchain_identity_sha256)
            || !is_sha256(&execution.normalized_model_sha256)
            || !valid_execution_variant(execution.provider, &execution.variant)
            || (execution.provider == Provider::TypeScriptCompilerApi
                && !validate_typescript_variant_inventory(inventory, &execution.variant))
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
                &execution.variant,
                &execution.normalized_model_sha256,
            )? != execution.execution_id
            || (execution.provider == Provider::GradleToolingApi
                && !validate_gradle_variant_inventory(inventory, execution, &targets))
        {
            return Err(
                "intentional-boundary project-model execution commitment changed".to_string(),
            );
        }
    }
    for target in &census.targets {
        let Some(execution) = census
            .executions
            .iter()
            .find(|execution| execution.execution_id == target.execution_id)
        else {
            return Err("intentional-boundary project-model target changed execution".to_string());
        };
        let manifest = regular_inventory_entry(
            inventory,
            &target.manifest_repository_path,
            "project-model target manifest",
        )?;
        if manifest.object_id != target.manifest_object_id
            || target.package_name.trim().is_empty()
            || target.package_version.trim().is_empty()
            || target.target_name.trim().is_empty()
            || target.provider_kinds.is_empty()
            || target.provider_output_types.is_empty()
            || !sorted_unique(&target.provider_kinds)
            || !sorted_unique(&target.provider_output_types)
            || !sorted_unique(&target.source_repository_paths)
            || !sorted_unique(&target.ignored_source_repository_paths)
            || target.source_repository_paths.iter().any(|path| {
                target
                    .ignored_source_repository_paths
                    .binary_search(path)
                    .is_ok()
            })
            || target
                .producer_tasks
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !sorted_unique(&target.required_features)
            || target
                .source_repository_paths
                .iter()
                .any(|path| !is_safe_repository_path(path))
            || target
                .ignored_source_repository_paths
                .iter()
                .any(|path| !is_safe_repository_path(path))
            || !validate_target_classification(inventory, target, execution)
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
    execution: &IntentionalBoundaryProjectModelExecution,
) -> bool {
    match target.provider {
        Provider::CargoMetadata => validate_cargo_target_classification(inventory, target),
        Provider::GoList => validate_go_target_classification(inventory, target),
        Provider::GradleToolingApi => validate_gradle_target_classification(inventory, target),
        Provider::TypeScriptCompilerApi => {
            validate_typescript_target_classification(inventory, target, execution)
        }
    }
}

pub(super) fn valid_execution_variant(
    provider: Provider,
    variant: &IntentionalBoundaryProjectModelVariant,
) -> bool {
    match (provider, variant) {
        (
            Provider::GoList,
            IntentionalBoundaryProjectModelVariant::Go {
                goos,
                goarch,
                build_tags,
                architecture,
                ..
            },
        ) => {
            valid_go_platform_component(goos)
                && valid_go_platform_component(goarch)
                && sorted_unique(build_tags)
                && build_tags.iter().all(|tag| {
                    !tag.trim().is_empty()
                        && tag
                            .chars()
                            .all(|value| value.is_alphanumeric() || matches!(value, '_' | '.'))
                })
                && valid_go_architecture(goarch, architecture)
        }
        (Provider::CargoMetadata, IntentionalBoundaryProjectModelVariant::Default) => true,
        (
            Provider::GradleToolingApi,
            IntentionalBoundaryProjectModelVariant::Gradle { kotlin_projects },
        ) => valid_gradle_variant(kotlin_projects),
        (
            Provider::TypeScriptCompilerApi,
            IntentionalBoundaryProjectModelVariant::TypeScript {
                root_config_repository_path,
                compiler_version,
                projects,
                selected_source_repository_paths,
                ignored_source_repository_paths,
            },
        ) => {
            !compiler_version.trim().is_empty()
                && !projects.is_empty()
                && projects.windows(2).all(|pair| pair[0] < pair[1])
                && selected_source_repository_paths
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && ignored_source_repository_paths
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && selected_source_repository_paths
                    .iter()
                    .all(|path| ignored_source_repository_paths.binary_search(path).is_err())
                && match root_config_repository_path {
                    Some(root) => projects
                        .iter()
                        .any(|project| project.config_repository_path.as_ref() == Some(root)),
                    None => {
                        projects.len() == 1
                            && projects[0].config_repository_path.is_none()
                            && projects[0].config_object_id.is_none()
                    }
                }
        }
        _ => false,
    }
}

fn valid_gradle_variant(
    projects: &[super::IntentionalBoundaryProjectModelGradleKotlinProject],
) -> bool {
    projects.windows(2).all(|pair| pair[0] < pair[1])
        && projects.iter().all(|project| {
            !project.project_path.trim().is_empty()
                && project
                    .component_names
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && project
                    .component_names
                    .iter()
                    .all(|component| !component.trim().is_empty())
                && project
                    .publications
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && project.publications.iter().all(valid_gradle_publication)
                && project.source_sets.windows(2).all(|pair| pair[0] < pair[1])
                && project.targets.windows(2).all(|pair| pair[0] < pair[1])
                && valid_gradle_source_set_graph(project)
                && project.source_sets.iter().all(|source_set| {
                    !source_set.name.trim().is_empty()
                        && source_set
                            .source_repository_paths
                            .windows(2)
                            .all(|pair| pair[0] < pair[1])
                        && source_set
                            .source_repository_paths
                            .iter()
                            .all(|path| is_safe_repository_path(path))
                        && source_set
                            .depends_on_source_sets
                            .windows(2)
                            .all(|pair| pair[0] < pair[1])
                        && source_set.depends_on_source_sets.iter().all(|dependency| {
                            dependency != &source_set.name
                                && project
                                    .source_sets
                                    .binary_search_by(|candidate| candidate.name.cmp(dependency))
                                    .is_ok()
                        })
                })
                && project.targets.iter().all(|target| {
                    !target.name.trim().is_empty()
                        && !target.platform_type.trim().is_empty()
                        && target
                            .component_names
                            .windows(2)
                            .all(|pair| pair[0] < pair[1])
                        && target.component_names.iter().all(|component| {
                            !component.trim().is_empty()
                                && project.component_names.binary_search(component).is_ok()
                        })
                        && (!target.publishable || !target.component_names.is_empty())
                        && target.compilations.windows(2).all(|pair| pair[0] < pair[1])
                        && target.compilations.iter().all(|compilation| {
                            !compilation.name.trim().is_empty()
                                && !compilation.default_source_set.trim().is_empty()
                                && compilation
                                    .source_sets
                                    .windows(2)
                                    .all(|pair| pair[0] < pair[1])
                                && compilation
                                    .source_sets
                                    .binary_search(&compilation.default_source_set)
                                    .is_ok()
                                && compilation.source_sets.iter().all(|source_set| {
                                    project
                                        .source_sets
                                        .binary_search_by(|candidate| {
                                            candidate.name.cmp(source_set)
                                        })
                                        .is_ok()
                                })
                        })
                })
        })
}

fn valid_gradle_publication(
    publication: &super::IntentionalBoundaryProjectModelGradlePublication,
) -> bool {
    if publication.name.trim().is_empty() || publication.publication_type.trim().is_empty() {
        return false;
    }
    let coordinates = [
        publication.group_id.as_deref(),
        publication.artifact_id.as_deref(),
        publication.version.as_deref(),
    ];
    coordinates.iter().all(|value| value.is_none())
        || coordinates
            .iter()
            .all(|value| value.is_some_and(|value| !value.trim().is_empty()))
}

pub(super) fn valid_gradle_source_set_graph(
    project: &super::IntentionalBoundaryProjectModelGradleKotlinProject,
) -> bool {
    let mut remaining_dependencies = vec![0usize; project.source_sets.len()];
    let mut dependents = vec![Vec::new(); project.source_sets.len()];
    for (source_index, source_set) in project.source_sets.iter().enumerate() {
        remaining_dependencies[source_index] = source_set.depends_on_source_sets.len();
        for dependency in &source_set.depends_on_source_sets {
            let Ok(dependency_index) = project
                .source_sets
                .binary_search_by(|candidate| candidate.name.cmp(dependency))
            else {
                return false;
            };
            if dependency_index == source_index {
                return false;
            }
            dependents[dependency_index].push(source_index);
        }
    }
    let mut ready = remaining_dependencies
        .iter()
        .enumerate()
        .filter_map(|(index, remaining)| (*remaining == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut visited = 0usize;
    while let Some(index) = ready.pop_front() {
        visited += 1;
        for dependent in &dependents[index] {
            remaining_dependencies[*dependent] -= 1;
            if remaining_dependencies[*dependent] == 0 {
                ready.push_back(*dependent);
            }
        }
    }
    visited == project.source_sets.len()
}

fn validate_gradle_variant_inventory(
    inventory: &IntentionalBoundaryRepositoryInventory,
    execution: &IntentionalBoundaryProjectModelExecution,
    targets: &[IntentionalBoundaryProjectModelTarget],
) -> bool {
    let IntentionalBoundaryProjectModelVariant::Gradle { kotlin_projects } = &execution.variant
    else {
        return false;
    };
    kotlin_projects.iter().all(|project| {
        targets
            .iter()
            .filter(|target| target.target_name == project.project_path)
            .count()
            == 1
            && project.source_sets.iter().all(|source_set| {
                source_set.source_repository_paths.iter().all(|path| {
                    regular_inventory_entry(inventory, path, "Gradle Kotlin source").is_ok()
                })
            })
    })
}

fn valid_go_architecture(
    goarch: &str,
    architecture: &IntentionalBoundaryProjectModelGoArchitecture,
) -> bool {
    match architecture {
        IntentionalBoundaryProjectModelGoArchitecture::Default => true,
        IntentionalBoundaryProjectModelGoArchitecture::Explicit {
            environment_variable,
            value,
        } => {
            go_architecture_environment_variable(goarch) == Some(environment_variable.as_str())
                && !value.is_empty()
                && valid_go_architecture_configuration(goarch, value)
        }
    }
}

fn valid_go_platform_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
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
        ignored_source_repository_paths: &target.ignored_source_repository_paths,
        producer_tasks: &target.producer_tasks,
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
    if !entry.kind.is_file_blob() {
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
