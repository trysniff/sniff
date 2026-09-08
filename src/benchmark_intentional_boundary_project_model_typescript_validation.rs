use super::*;

pub(in crate::benchmark::release) fn validate_typescript_target_classification(
    inventory: &IntentionalBoundaryRepositoryInventory,
    target: &IntentionalBoundaryProjectModelTarget,
    execution: &IntentionalBoundaryProjectModelExecution,
) -> bool {
    let Ok(compiler_version) = pinned_typescript_compiler_version() else {
        return false;
    };
    let IntentionalBoundaryProjectModelVariant::TypeScript {
        compiler_version: variant_compiler_version,
        projects,
        selected_source_repository_paths,
        ignored_source_repository_paths,
        ..
    } = &execution.variant
    else {
        return false;
    };
    let mut matching_projects = projects.iter().filter(|project| {
        let expected_name = project
            .config_repository_path
            .as_deref()
            .unwrap_or("<inferred>");
        let expected_manifest = project
            .config_repository_path
            .as_deref()
            .unwrap_or(&execution.invocation_anchor_repository_path);
        target.target_name == expected_name && target.manifest_repository_path == expected_manifest
    });
    let Some(project) = matching_projects.next() else {
        return false;
    };
    if matching_projects.next().is_some() {
        return false;
    }
    let all_sources = selected_source_repository_paths
        .iter()
        .chain(ignored_source_repository_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let project_sources = project
        .source_repository_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_ignored = all_sources
        .difference(&project_sources)
        .cloned()
        .collect::<Vec<_>>();
    target.provider == Provider::TypeScriptCompilerApi
        && target.package_name == "typescript-compiler-project"
        && target.package_version == compiler_version
        && target.package_version == *variant_compiler_version
        && target.source_repository_paths == project.source_repository_paths
        && target.ignored_source_repository_paths == expected_ignored
        && target.provider_kinds == ["compiler_project"]
        && target.provider_output_types == ["semantic_index"]
        && target.required_features.is_empty()
        && target.producer_tasks.is_empty()
        && matches!(
            target.target_status,
            TargetStatus::NonBoundary {
                reason: NonBoundaryReason::CompilerProject
            }
        )
        && regular_inventory_entry(
            inventory,
            &target.manifest_repository_path,
            "TypeScript compiler-project target anchor",
        )
        .is_ok()
}

pub(in crate::benchmark::release) fn validate_typescript_variant_inventory(
    inventory: &IntentionalBoundaryRepositoryInventory,
    variant: &IntentionalBoundaryProjectModelVariant,
) -> bool {
    let IntentionalBoundaryProjectModelVariant::TypeScript {
        root_config_repository_path,
        compiler_version,
        projects,
        selected_source_repository_paths,
        ignored_source_repository_paths,
    } = variant
    else {
        return false;
    };
    let Ok(expected_compiler_version) = pinned_typescript_compiler_version() else {
        return false;
    };
    let selected = selected_source_repository_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let project_configs = projects
        .iter()
        .filter_map(|project| project.config_repository_path.clone())
        .collect::<BTreeSet<_>>();
    if compiler_version != expected_compiler_version
        || selected_source_repository_paths
            .iter()
            .chain(ignored_source_repository_paths)
            .any(|path| {
                regular_inventory_entry(inventory, path, "TypeScript variant source").is_err()
                    || !is_typescript_javascript_source(path)
            })
    {
        return false;
    }
    if let Some(root) = root_config_repository_path
        && (!project_configs.contains(root)
            || regular_inventory_entry(inventory, root, "TypeScript variant root").is_err())
    {
        return false;
    }
    projects.iter().all(|project| {
        let config_identity_valid =
            match (&project.config_repository_path, &project.config_object_id) {
                (Some(path), Some(object_id)) => {
                    regular_inventory_entry(inventory, path, "TypeScript variant compiler config")
                        .is_ok_and(|entry| entry.object_id == *object_id)
                }
                (None, None) => root_config_repository_path.is_none(),
                _ => false,
            };
        config_identity_valid
            && project
                .config_reads
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && project.config_reads.iter().all(|read| {
                regular_inventory_entry(
                    inventory,
                    &read.repository_path,
                    "TypeScript variant config dependency",
                )
                .is_ok_and(|entry| entry.object_id == read.object_id)
            })
            && project
                .project_references
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && project
                .project_references
                .iter()
                .all(|reference| project_configs.contains(reference))
            && project
                .source_repository_paths
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && project
                .source_repository_paths
                .iter()
                .all(|path| selected.contains(path))
            && serde_json::from_str::<Value>(&project.effective_compiler_options_json)
                .ok()
                .and_then(|value| serde_json::to_string(&value).ok())
                .is_some_and(|canonical| canonical == project.effective_compiler_options_json)
    })
}
