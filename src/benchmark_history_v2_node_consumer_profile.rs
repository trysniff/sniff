use super::{
    BoundaryGitEntryKind, HISTORICAL_V2_NODE_CONSUMER_PROFILE_CENSUS_SCHEMA_VERSION,
    HistoricalV2NodeConsumerMode, HistoricalV2NodeConsumerProfile,
    HistoricalV2NodeConsumerProfileCensus, HistoricalV2NodeConsumerResolution,
    HistoricalV2NodeConsumerUnresolvedReason, HistoricalV2NodePackageDocument,
    HistoricalV2NodePackageEntryKind, HistoricalV2NodePackageExposure,
    HistoricalV2NodePackageSurfaceCensus, HistoricalV2TypeScriptModuleResolution,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelProvider,
    IntentionalBoundaryProjectModelTypeScriptProject, IntentionalBoundaryProjectModelVariant,
    IntentionalBoundaryRepositoryInventory,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[path = "benchmark_history_v2_node_consumer_profile_runtime.rs"]
mod runtime;

#[path = "benchmark_history_v2_node_consumer_profile_identity.rs"]
mod identity;

#[path = "benchmark_history_v2_node_consumer_profile_validation.rs"]
mod validation;

use identity::*;
use validation::*;

const CONSUMER_PROFILE_CONTRACT: &str = "sniffbench-historical-v2-node-consumer-profiles-v1";
const SIDECAR_OUTPUT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
struct CompilerProjectProfile<'a> {
    execution_id: &'a str,
    project: &'a IntentionalBoundaryProjectModelTypeScriptProject,
}

#[derive(Debug, Clone)]
pub(super) struct ConsumerProfileRequest<'a> {
    document: &'a HistoricalV2NodePackageDocument,
    specifier: &'a str,
    mode: HistoricalV2NodeConsumerMode,
    compiler_options: Value,
    exposures: Vec<&'a HistoricalV2NodePackageExposure>,
}

#[derive(Debug, Clone)]
pub(super) struct ConsumerProfileExecutorOutput {
    node_runtime_sha256: String,
    toolchain_identity_sha256: String,
    stdout: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SidecarOutput {
    schema_version: u32,
    typescript_version: String,
    node_version: String,
    compiler_module_resolution: String,
    compiler_conditions: Vec<String>,
    custom_conditions: Vec<String>,
    compiler: SidecarResolution,
    runtime: SidecarResolution,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SidecarResolution {
    selected_exposure_id: Option<String>,
    ambiguous: bool,
    resolved_repository_path: Option<String>,
    evidence_sha256: String,
}

pub(super) fn census_historical_v2_node_consumer_profiles(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    packages: &HistoricalV2NodePackageSurfaceCensus,
    project_model: &IntentionalBoundaryProjectModelCensus,
) -> Result<HistoricalV2NodeConsumerProfileCensus, String> {
    let mut runtime_session = None;
    let census = census_node_consumer_profiles_with_executor(
        inventory,
        packages,
        project_model,
        |request| {
            if runtime_session.is_none() {
                runtime_session = Some(runtime::NodeConsumerProfileRuntime::create(
                    root,
                    &inventory.revision,
                )?);
            }
            let runtime = runtime_session
                .as_ref()
                .expect("consumer runtime initialized above");
            let output = runtime::run_node_consumer_profile(
                runtime,
                inventory,
                request.document,
                request.specifier,
                request.mode,
                &request.compiler_options,
                &request.exposures,
            )?;
            Ok(ConsumerProfileExecutorOutput {
                node_runtime_sha256: output.node_runtime_sha256,
                toolchain_identity_sha256: output.toolchain_identity_sha256,
                stdout: output.stdout,
            })
        },
    );
    if let Some(runtime) = &runtime_session {
        runtime.verify_unchanged()?;
    }
    census
}

pub(super) fn validate_historical_v2_node_consumer_profile_census_commitment(
    inventory: &IntentionalBoundaryRepositoryInventory,
    packages: &HistoricalV2NodePackageSurfaceCensus,
    project_model: &IntentionalBoundaryProjectModelCensus,
    census: &HistoricalV2NodeConsumerProfileCensus,
) -> Result<(), String> {
    validate_inputs(inventory, packages, project_model)?;
    validate_profile_coverage(packages, project_model, &census.profiles)?;
    if census.schema_version != HISTORICAL_V2_NODE_CONSUMER_PROFILE_CENSUS_SCHEMA_VERSION
        || census.contract != CONSUMER_PROFILE_CONTRACT
        || census.repository != inventory.repository
        || census.revision != inventory.revision
        || census.inventory_sha256 != inventory.inventory_sha256
        || census.node_package_surface_census_sha256 != packages.census_sha256
        || census.typescript_project_model_census_sha256
            != project_model.project_model_census_sha256
        || census.profiles.windows(2).any(|pair| pair[0] >= pair[1])
        || census
            .profiles
            .iter()
            .any(|profile| validate_profile(inventory, packages, project_model, profile).is_err())
        || census.profile_count_by_mode != count_by_mode(&census.profiles)
        || census.unresolved_resolution_count != unresolved_count(&census.profiles)
        || census.census_sha256 != consumer_profile_census_sha256(census)?
    {
        return Err("historical-v2 Node consumer-profile commitment changed".to_string());
    }
    let expected_compiler_version = typescript_compiler_version(project_model)?;
    if census.typescript_compiler_version != expected_compiler_version {
        return Err("historical-v2 Node consumer compiler identity changed".to_string());
    }
    let resolver_executed = census
        .profiles
        .iter()
        .any(|profile| profile.toolchain_identity_sha256.is_some());
    let runtime_identity_present =
        census.node_runtime_version.is_some() && census.node_runtime_sha256.is_some();
    if census.node_runtime_version.is_some() != census.node_runtime_sha256.is_some()
        || resolver_executed != runtime_identity_present
    {
        return Err("historical-v2 Node consumer runtime identity changed".to_string());
    }
    Ok(())
}

fn census_node_consumer_profiles_with_executor<F>(
    inventory: &IntentionalBoundaryRepositoryInventory,
    packages: &HistoricalV2NodePackageSurfaceCensus,
    project_model: &IntentionalBoundaryProjectModelCensus,
    mut executor: F,
) -> Result<HistoricalV2NodeConsumerProfileCensus, String>
where
    F: FnMut(&ConsumerProfileRequest<'_>) -> Result<ConsumerProfileExecutorOutput, String>,
{
    validate_inputs(inventory, packages, project_model)?;
    let compiler_version = typescript_compiler_version(project_model)?;
    let mut profiles = Vec::new();
    let mut observed_node_version = None;
    let mut observed_node_sha256 = None;
    for document in &packages.documents {
        let groups = exposure_groups(document, packages)?;
        if groups.is_empty() {
            continue;
        }
        let projects = owning_projects(document, packages, project_model)?;
        for (public_subpath, exposures) in groups {
            let specifier = document
                .package_name
                .as_deref()
                .map(|name| package_specifier(name, &public_subpath))
                .transpose()?;
            if projects.is_empty() || specifier.is_none() {
                let unresolved_projects = if projects.is_empty() {
                    vec![None]
                } else {
                    projects.iter().map(Some).collect::<Vec<_>>()
                };
                for project in unresolved_projects {
                    for mode in [
                        HistoricalV2NodeConsumerMode::Import,
                        HistoricalV2NodeConsumerMode::Require,
                    ] {
                        profiles.push(unresolved_profile(
                            document,
                            &public_subpath,
                            specifier.as_deref(),
                            mode,
                            project,
                            &exposures,
                            if specifier.is_none() {
                                HistoricalV2NodeConsumerUnresolvedReason::MissingPackageName
                            } else {
                                HistoricalV2NodeConsumerUnresolvedReason::NoOwningCompilerProject
                            },
                        )?);
                    }
                }
                continue;
            }
            for project in &projects {
                let compiler_options: Value =
                    serde_json::from_str(&project.project.effective_compiler_options_json)
                        .map_err(|error| {
                            format!(
                                "failed to parse committed TypeScript compiler options: {error}"
                            )
                        })?;
                for mode in [
                    HistoricalV2NodeConsumerMode::Import,
                    HistoricalV2NodeConsumerMode::Require,
                ] {
                    let request = ConsumerProfileRequest {
                        document,
                        specifier: specifier.as_deref().expect("specifier checked above"),
                        mode,
                        compiler_options: compiler_options.clone(),
                        exposures: exposures.clone(),
                    };
                    let execution = executor(&request)?;
                    let output: SidecarOutput =
                        serde_json::from_str(&execution.stdout).map_err(|error| {
                            format!("failed to parse Node consumer-profile output: {error}")
                        })?;
                    if output.schema_version != SIDECAR_OUTPUT_SCHEMA_VERSION
                        || compiler_version.as_deref() != Some(output.typescript_version.as_str())
                    {
                        return Err(
                            "Node consumer-profile compiler output identity changed".to_string()
                        );
                    }
                    require_same_identity(
                        &mut observed_node_version,
                        output.node_version.clone(),
                        "Node consumer runtime version",
                    )?;
                    require_same_identity(
                        &mut observed_node_sha256,
                        execution.node_runtime_sha256.clone(),
                        "Node consumer runtime digest",
                    )?;
                    profiles.push(resolved_profile(
                        inventory,
                        document,
                        &public_subpath,
                        request.specifier,
                        mode,
                        project,
                        &execution.toolchain_identity_sha256,
                        &exposures,
                        output,
                    )?);
                }
            }
        }
    }
    profiles.sort();
    if profiles
        .windows(2)
        .any(|pair| pair[0].profile_id == pair[1].profile_id)
    {
        return Err("historical-v2 Node consumer profiles are non-unique".to_string());
    }
    validate_profile_coverage(packages, project_model, &profiles)?;
    let mut census = HistoricalV2NodeConsumerProfileCensus {
        schema_version: HISTORICAL_V2_NODE_CONSUMER_PROFILE_CENSUS_SCHEMA_VERSION,
        contract: CONSUMER_PROFILE_CONTRACT.to_string(),
        repository: inventory.repository.clone(),
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        node_package_surface_census_sha256: packages.census_sha256.clone(),
        typescript_project_model_census_sha256: project_model.project_model_census_sha256.clone(),
        typescript_compiler_version: compiler_version,
        node_runtime_version: observed_node_version,
        node_runtime_sha256: observed_node_sha256,
        profile_count_by_mode: count_by_mode(&profiles),
        unresolved_resolution_count: unresolved_count(&profiles),
        profiles,
        census_sha256: String::new(),
    };
    census.census_sha256 = consumer_profile_census_sha256(&census)?;
    validate_historical_v2_node_consumer_profile_census_commitment(
        inventory,
        packages,
        project_model,
        &census,
    )?;
    Ok(census)
}

fn validate_inputs(
    inventory: &IntentionalBoundaryRepositoryInventory,
    packages: &HistoricalV2NodePackageSurfaceCensus,
    project_model: &IntentionalBoundaryProjectModelCensus,
) -> Result<(), String> {
    if packages.repository != inventory.repository
        || packages.revision != inventory.revision
        || packages.inventory_sha256 != inventory.inventory_sha256
        || project_model.repository != inventory.repository
        || project_model.revision != inventory.revision
        || project_model.inventory_sha256 != inventory.inventory_sha256
    {
        return Err("historical-v2 Node consumer-profile inputs disagree".to_string());
    }
    Ok(())
}

fn typescript_compiler_version(
    model: &IntentionalBoundaryProjectModelCensus,
) -> Result<Option<String>, String> {
    let mut versions = BTreeSet::new();
    for execution in &model.executions {
        if execution.provider != IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi {
            return Err("Node consumer profiles received a mixed compiler model".to_string());
        }
        let IntentionalBoundaryProjectModelVariant::TypeScript {
            compiler_version, ..
        } = &execution.variant
        else {
            return Err("Node consumer profiles received an untyped compiler world".to_string());
        };
        versions.insert(compiler_version.clone());
    }
    if versions.len() > 1 {
        return Err("Node consumer profiles received multiple compiler versions".to_string());
    }
    Ok(versions.into_iter().next())
}

fn owning_projects<'a>(
    document: &HistoricalV2NodePackageDocument,
    packages: &HistoricalV2NodePackageSurfaceCensus,
    model: &'a IntentionalBoundaryProjectModelCensus,
) -> Result<Vec<CompilerProjectProfile<'a>>, String> {
    let directory = package_directory(&document.manifest_repository_path)?;
    let targets = packages
        .exposures
        .iter()
        .filter(|exposure| exposure.manifest_repository_path == document.manifest_repository_path)
        .map(|exposure| exposure.target_repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut projects = Vec::new();
    for execution in &model.executions {
        let IntentionalBoundaryProjectModelVariant::TypeScript {
            projects: world, ..
        } = &execution.variant
        else {
            return Err("Node consumer profiles received an untyped compiler world".to_string());
        };
        for project in world {
            if project.source_repository_paths.iter().any(|source| {
                within_package(&directory, source) || targets.contains(source.as_str())
            }) {
                projects.push(CompilerProjectProfile {
                    execution_id: &execution.execution_id,
                    project,
                });
            }
        }
    }
    projects.sort_by(|left, right| {
        (left.execution_id, &left.project.config_repository_path)
            .cmp(&(right.execution_id, &right.project.config_repository_path))
    });
    if projects.windows(2).any(|pair| {
        pair[0].execution_id == pair[1].execution_id
            && pair[0].project.config_repository_path == pair[1].project.config_repository_path
    }) {
        return Err("Node consumer profiles repeat a compiler project".to_string());
    }
    Ok(projects)
}

fn exposure_groups<'a>(
    document: &HistoricalV2NodePackageDocument,
    packages: &'a HistoricalV2NodePackageSurfaceCensus,
) -> Result<Vec<(String, Vec<&'a HistoricalV2NodePackageExposure>)>, String> {
    let mut groups = BTreeMap::<String, Vec<_>>::new();
    for exposure in packages
        .exposures
        .iter()
        .filter(|exposure| exposure.manifest_repository_path == document.manifest_repository_path)
    {
        if document.has_exports && exposure.entry_kind != HistoricalV2NodePackageEntryKind::Exports
        {
            continue;
        }
        if !document.has_exports && exposure.entry_kind == HistoricalV2NodePackageEntryKind::Exports
        {
            return Err("Node package declaration census contradicts has_exports".to_string());
        }
        groups
            .entry(exposure.public_subpath.clone())
            .or_default()
            .push(exposure);
    }
    Ok(groups.into_iter().collect())
}

#[allow(clippy::too_many_arguments)]
fn resolved_profile(
    inventory: &IntentionalBoundaryRepositoryInventory,
    document: &HistoricalV2NodePackageDocument,
    public_subpath: &str,
    specifier: &str,
    mode: HistoricalV2NodeConsumerMode,
    project: &CompilerProjectProfile<'_>,
    toolchain_identity_sha256: &str,
    exposures: &[&HistoricalV2NodePackageExposure],
    output: SidecarOutput,
) -> Result<HistoricalV2NodeConsumerProfile, String> {
    require_sha256(
        toolchain_identity_sha256,
        "consumer-profile toolchain identity",
    )?;
    let compiler_options_sha256 =
        sha256(project.project.effective_compiler_options_json.as_bytes());
    let compiler = resolution(inventory, document, exposures, output.compiler, true)?;
    let runtime = resolution(inventory, document, exposures, output.runtime, false)?;
    let declared_exposure_ids = sorted_exposure_ids(exposures);
    let mut profile = HistoricalV2NodeConsumerProfile {
        profile_id: String::new(),
        consumer_surface_slot_id: consumer_surface_slot_id(
            document,
            public_subpath,
            mode,
            project.project.config_repository_path.as_deref(),
        )?,
        manifest_repository_path: document.manifest_repository_path.clone(),
        manifest_object_id: document.manifest_object_id.clone(),
        package_name: document.package_name.clone(),
        public_subpath: public_subpath.to_string(),
        specifier: Some(specifier.to_string()),
        mode,
        project_model_execution_id: Some(project.execution_id.to_string()),
        compiler_project_config_repository_path: project.project.config_repository_path.clone(),
        compiler_options_sha256: Some(compiler_options_sha256),
        toolchain_identity_sha256: Some(toolchain_identity_sha256.to_string()),
        compiler_module_resolution: Some(parse_compiler_module_resolution(
            &output.compiler_module_resolution,
        )?),
        compiler_conditions: output.compiler_conditions,
        custom_conditions: output.custom_conditions,
        declared_exposure_ids,
        compiler,
        runtime,
    };
    profile.profile_id = profile_id(&profile)?;
    Ok(profile)
}

fn unresolved_profile(
    document: &HistoricalV2NodePackageDocument,
    public_subpath: &str,
    specifier: Option<&str>,
    mode: HistoricalV2NodeConsumerMode,
    project: Option<&CompilerProjectProfile<'_>>,
    exposures: &[&HistoricalV2NodePackageExposure],
    reason: HistoricalV2NodeConsumerUnresolvedReason,
) -> Result<HistoricalV2NodeConsumerProfile, String> {
    let evidence_sha256 = sha256(format!("{reason:?}").as_bytes());
    let unresolved = HistoricalV2NodeConsumerResolution::Unresolved {
        reason,
        evidence_sha256,
    };
    let mut profile = HistoricalV2NodeConsumerProfile {
        profile_id: String::new(),
        consumer_surface_slot_id: consumer_surface_slot_id(
            document,
            public_subpath,
            mode,
            project.and_then(|value| value.project.config_repository_path.as_deref()),
        )?,
        manifest_repository_path: document.manifest_repository_path.clone(),
        manifest_object_id: document.manifest_object_id.clone(),
        package_name: document.package_name.clone(),
        public_subpath: public_subpath.to_string(),
        specifier: specifier.map(str::to_string),
        mode,
        project_model_execution_id: project.map(|value| value.execution_id.to_string()),
        compiler_project_config_repository_path: project
            .and_then(|value| value.project.config_repository_path.clone()),
        compiler_options_sha256: project
            .map(|value| sha256(value.project.effective_compiler_options_json.as_bytes())),
        toolchain_identity_sha256: None,
        compiler_module_resolution: None,
        compiler_conditions: Vec::new(),
        custom_conditions: Vec::new(),
        declared_exposure_ids: sorted_exposure_ids(exposures),
        compiler: unresolved.clone(),
        runtime: unresolved,
    };
    profile.profile_id = profile_id(&profile)?;
    Ok(profile)
}

fn resolution(
    inventory: &IntentionalBoundaryRepositoryInventory,
    document: &HistoricalV2NodePackageDocument,
    exposures: &[&HistoricalV2NodePackageExposure],
    output: SidecarResolution,
    compiler: bool,
) -> Result<HistoricalV2NodeConsumerResolution, String> {
    require_sha256(&output.evidence_sha256, "consumer resolution evidence")?;
    let ambiguous_reason = if compiler {
        HistoricalV2NodeConsumerUnresolvedReason::CompilerBranchAmbiguous
    } else {
        HistoricalV2NodeConsumerUnresolvedReason::RuntimeBranchAmbiguous
    };
    let failed_reason = if compiler {
        HistoricalV2NodeConsumerUnresolvedReason::CompilerResolutionFailed
    } else {
        HistoricalV2NodeConsumerUnresolvedReason::RuntimeResolutionFailed
    };
    if output.ambiguous {
        return Ok(HistoricalV2NodeConsumerResolution::Unresolved {
            reason: ambiguous_reason,
            evidence_sha256: output.evidence_sha256,
        });
    }
    let (Some(exposure_id), Some(resolved_repository_path)) =
        (output.selected_exposure_id, output.resolved_repository_path)
    else {
        return Ok(HistoricalV2NodeConsumerResolution::Unresolved {
            reason: failed_reason,
            evidence_sha256: output.evidence_sha256,
        });
    };
    let matching = exposures
        .iter()
        .filter(|exposure| exposure.exposure_id == exposure_id)
        .copied()
        .collect::<Vec<_>>();
    let [selected] = matching.as_slice() else {
        return Ok(HistoricalV2NodeConsumerResolution::Unresolved {
            reason: ambiguous_reason,
            evidence_sha256: output.evidence_sha256,
        });
    };
    let package_directory = package_directory(&document.manifest_repository_path)?;
    if !within_package(&package_directory, &resolved_repository_path) {
        return Ok(HistoricalV2NodeConsumerResolution::Unresolved {
            reason: if compiler {
                HistoricalV2NodeConsumerUnresolvedReason::CompilerTargetOutsidePackage
            } else {
                HistoricalV2NodeConsumerUnresolvedReason::RuntimeTargetOutsidePackage
            },
            evidence_sha256: output.evidence_sha256,
        });
    }
    let entry = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == resolved_repository_path);
    if compiler
        && !entry.is_some_and(|entry| {
            matches!(
                entry.kind,
                BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob
            ) && is_typescript_javascript_source(&entry.repository_path)
        })
    {
        return Ok(HistoricalV2NodeConsumerResolution::Unresolved {
            reason: HistoricalV2NodeConsumerUnresolvedReason::CompilerTargetNotTrackedSource,
            evidence_sha256: output.evidence_sha256,
        });
    }
    Ok(HistoricalV2NodeConsumerResolution::Resolved {
        selected_exposure_id: selected.exposure_id.clone(),
        selected_surface_slot_id: selected.surface_slot_id.clone(),
        declared_target_repository_path: selected.target_repository_path.clone(),
        resolved_repository_path,
        resolved_object_id: entry.map(|entry| entry.object_id.clone()),
        compiler_source_substitution: compiler
            && entry.is_some_and(|entry| entry.repository_path != selected.target_repository_path),
        evidence_sha256: output.evidence_sha256,
    })
}

fn parse_compiler_module_resolution(
    value: &str,
) -> Result<HistoricalV2TypeScriptModuleResolution, String> {
    match value {
        "Classic" => Ok(HistoricalV2TypeScriptModuleResolution::Classic),
        "Node10" | "NodeJs" => Ok(HistoricalV2TypeScriptModuleResolution::Node10),
        "Node16" => Ok(HistoricalV2TypeScriptModuleResolution::Node16),
        "NodeNext" => Ok(HistoricalV2TypeScriptModuleResolution::NodeNext),
        "Bundler" => Ok(HistoricalV2TypeScriptModuleResolution::Bundler),
        _ => Err(format!(
            "unsupported TypeScript compiler module resolution: {value}"
        )),
    }
}

#[cfg(test)]
#[path = "benchmark_history_v2_node_consumer_profile_tests.rs"]
mod tests;
