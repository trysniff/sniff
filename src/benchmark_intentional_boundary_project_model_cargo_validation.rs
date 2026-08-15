use super::*;

pub fn validate_intentional_boundary_cargo_metadata(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    invocation_manifest_repository_path: &str,
    toolchain_identity_sha256: &str,
    stdout: &[u8],
    census: &IntentionalBoundaryProjectModelCensus,
) -> Result<(), String> {
    let expected = parse_intentional_boundary_cargo_metadata(
        root,
        inventory,
        invocation_manifest_repository_path,
        toolchain_identity_sha256,
        stdout,
    )?;
    if census != &expected {
        return Err("intentional-boundary Cargo project model changed".to_string());
    }
    Ok(())
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
    {
        return Err("intentional-boundary project-model identity changed".to_string());
    }
    if census.executions.windows(2).any(|pair| pair[0] >= pair[1])
        || census.targets.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("intentional-boundary project-model ordering changed".to_string());
    }
    for execution in &census.executions {
        if execution.provider != Provider::CargoMetadata
            || execution.command_contract != CARGO_COMMAND_CONTRACT
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
        if invocation.object_id != execution.invocation_anchor_object_id {
            return Err("intentional-boundary project-model invocation changed".to_string());
        }
        let covered = execution
            .covered_manifest_repository_paths
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if covered.len() != execution.covered_manifest_repository_paths.len()
            || !covered.contains(&execution.invocation_anchor_repository_path)
        {
            return Err("intentional-boundary project-model coverage changed".to_string());
        }
        for path in &covered {
            regular_inventory_entry(inventory, path, "project-model covered manifest")?;
        }
        let targets = census
            .targets
            .iter()
            .filter(|target| target.execution_id == execution.execution_id)
            .collect::<Vec<_>>();
        if execution.target_count != targets.len()
            || targets.iter().any(|target| {
                target.provider != execution.provider
                    || !covered.contains(&target.manifest_repository_path)
            })
            || compute_normalized_cargo_model_sha256(
                &execution.covered_manifest_repository_paths,
                &targets.into_iter().cloned().collect::<Vec<_>>(),
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
            || target.provider_crate_types.is_empty()
            || !sorted_unique(&target.provider_kinds)
            || !sorted_unique(&target.provider_crate_types)
            || !sorted_unique(&target.required_features)
            || target
                .source_repository_path
                .as_deref()
                .is_some_and(|path| !is_safe_repository_path(path))
            || target.target_status
                != classify_target(
                    inventory,
                    &target.provider_kinds,
                    target.source_repository_path.as_deref(),
                )
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
    let expected_target_counts = target_status_counts(&census.targets);
    if census.execution_count_by_provider != expected_execution_counts
        || census.target_count_by_status != expected_target_counts
        || compute_project_model_census_sha256(census)? != census.project_model_census_sha256
    {
        return Err("intentional-boundary project-model census commitment changed".to_string());
    }
    Ok(())
}
