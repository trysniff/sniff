use super::*;

pub(super) fn validate_profile(
    inventory: &IntentionalBoundaryRepositoryInventory,
    packages: &HistoricalV2NodePackageSurfaceCensus,
    project_model: &IntentionalBoundaryProjectModelCensus,
    profile: &HistoricalV2NodeConsumerProfile,
) -> Result<(), String> {
    if profile.profile_id != profile_id(profile)?
        || profile.declared_exposure_ids.is_empty()
        || profile
            .declared_exposure_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err("Node consumer profile identity changed".to_string());
    }
    let document = packages
        .documents
        .iter()
        .find(|document| {
            document.manifest_repository_path == profile.manifest_repository_path
                && document.manifest_object_id == profile.manifest_object_id
        })
        .ok_or_else(|| "Node consumer profile references an unknown manifest".to_string())?;
    if profile.consumer_surface_slot_id
        != consumer_surface_slot_id(
            document,
            &profile.public_subpath,
            profile.mode,
            profile.compiler_project_config_repository_path.as_deref(),
        )?
    {
        return Err("Node consumer profile surface identity changed".to_string());
    }
    let declared = packages
        .exposures
        .iter()
        .filter(|exposure| {
            profile
                .declared_exposure_ids
                .contains(&exposure.exposure_id)
        })
        .collect::<Vec<_>>();
    if declared.len() != profile.declared_exposure_ids.len()
        || declared.iter().any(|exposure| {
            exposure.manifest_repository_path != profile.manifest_repository_path
                || exposure.public_subpath != profile.public_subpath
        })
    {
        return Err("Node consumer profile declaration set changed".to_string());
    }
    let expected_declared = exposure_groups(document, packages)?
        .into_iter()
        .find(|(public_subpath, _)| public_subpath == &profile.public_subpath)
        .map(|(_, exposures)| sorted_exposure_ids(&exposures))
        .ok_or_else(|| "Node consumer profile public subpath disappeared".to_string())?;
    if profile.declared_exposure_ids != expected_declared {
        return Err("Node consumer profile declaration coverage changed".to_string());
    }
    validate_resolution(inventory, &declared, &profile.compiler, true)?;
    validate_resolution(inventory, &declared, &profile.runtime, false)?;
    if profile.package_name != document.package_name
        || profile.specifier
            != document
                .package_name
                .as_deref()
                .map(|name| package_specifier(name, &profile.public_subpath))
                .transpose()?
    {
        return Err("Node consumer profile package identity changed".to_string());
    }
    match &profile.project_model_execution_id {
        Some(execution_id) => {
            let config_path = profile.compiler_project_config_repository_path.as_ref();
            let options_sha256 = profile.compiler_options_sha256.as_deref().ok_or_else(|| {
                "Node consumer profile compiler options identity is missing".to_string()
            })?;
            let matching_projects = project_model
                .executions
                .iter()
                .filter(|execution| {
                    execution.execution_id == *execution_id
                        && execution.provider
                            == IntentionalBoundaryProjectModelProvider::TypeScriptCompilerApi
                })
                .flat_map(|execution| match &execution.variant {
                    IntentionalBoundaryProjectModelVariant::TypeScript { projects, .. } => {
                        projects.iter().collect::<Vec<_>>()
                    }
                    _ => Vec::new(),
                })
                .filter(|project| {
                    project.config_repository_path.as_ref() == config_path
                        && sha256(project.effective_compiler_options_json.as_bytes())
                            == options_sha256
                })
                .collect::<Vec<_>>();
            let [project] = matching_projects.as_slice() else {
                return Err("Node consumer profile compiler project changed".to_string());
            };
            if profile.toolchain_identity_sha256.is_some() {
                validate_compiler_metadata(profile, project)?;
            }
        }
        None => {
            if profile.compiler_project_config_repository_path.is_some()
                || profile.compiler_options_sha256.is_some()
            {
                return Err("Node consumer profile invented compiler project metadata".to_string());
            }
        }
    }
    let resolver_executed = profile.toolchain_identity_sha256.is_some();
    if (resolver_executed && profile.project_model_execution_id.is_none())
        || (!resolver_executed
            && profile.package_name.is_some()
            && profile.project_model_execution_id.is_some())
        || (!resolver_executed
            && (matches!(
                profile.compiler,
                HistoricalV2NodeConsumerResolution::Resolved { .. }
            ) || matches!(
                profile.runtime,
                HistoricalV2NodeConsumerResolution::Resolved { .. }
            )))
        || resolver_executed != profile.compiler_module_resolution.is_some()
        || (!resolver_executed
            && (!profile.compiler_conditions.is_empty() || !profile.custom_conditions.is_empty()))
    {
        return Err("Node consumer profile resolver identity changed".to_string());
    }
    if !resolver_executed {
        let expected_reason = if profile.package_name.is_none() {
            HistoricalV2NodeConsumerUnresolvedReason::MissingPackageName
        } else {
            HistoricalV2NodeConsumerUnresolvedReason::NoOwningCompilerProject
        };
        if profile.compiler != profile.runtime
            || !matches!(
                profile.compiler,
                HistoricalV2NodeConsumerResolution::Unresolved { reason, .. }
                    if reason == expected_reason
            )
        {
            return Err("Node consumer profile unresolved provenance changed".to_string());
        }
    }
    for digest in [
        profile.compiler_options_sha256.as_deref(),
        profile.toolchain_identity_sha256.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        require_sha256(digest, "Node consumer profile digest")?;
    }
    Ok(())
}

pub(super) fn validate_profile_coverage(
    packages: &HistoricalV2NodePackageSurfaceCensus,
    project_model: &IntentionalBoundaryProjectModelCensus,
    profiles: &[HistoricalV2NodeConsumerProfile],
) -> Result<(), String> {
    type ProfileKey = (
        String,
        String,
        HistoricalV2NodeConsumerMode,
        Option<String>,
        Option<String>,
    );
    let mut expected = BTreeSet::<ProfileKey>::new();
    for document in &packages.documents {
        let projects = owning_projects(document, packages, project_model)?;
        let project_keys = if projects.is_empty() {
            vec![(None, None)]
        } else {
            projects
                .iter()
                .map(|project| {
                    (
                        Some(project.execution_id.to_string()),
                        project.project.config_repository_path.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        for (public_subpath, _) in exposure_groups(document, packages)? {
            for (execution_id, config_path) in &project_keys {
                for mode in [
                    HistoricalV2NodeConsumerMode::Import,
                    HistoricalV2NodeConsumerMode::Require,
                ] {
                    expected.insert((
                        document.manifest_repository_path.clone(),
                        public_subpath.clone(),
                        mode,
                        execution_id.clone(),
                        config_path.clone(),
                    ));
                }
            }
        }
    }
    let actual = profiles
        .iter()
        .map(|profile| {
            (
                profile.manifest_repository_path.clone(),
                profile.public_subpath.clone(),
                profile.mode,
                profile.project_model_execution_id.clone(),
                profile.compiler_project_config_repository_path.clone(),
            )
        })
        .collect::<Vec<_>>();
    let actual_unique = actual.iter().cloned().collect::<BTreeSet<_>>();
    if actual.len() != actual_unique.len() || actual_unique != expected {
        return Err("historical-v2 Node consumer-profile coverage changed".to_string());
    }
    Ok(())
}

fn validate_compiler_metadata(
    profile: &HistoricalV2NodeConsumerProfile,
    project: &IntentionalBoundaryProjectModelTypeScriptProject,
) -> Result<(), String> {
    let options: Value = serde_json::from_str(&project.effective_compiler_options_json)
        .map_err(|error| format!("failed to parse committed compiler options: {error}"))?;
    let options = options
        .as_object()
        .ok_or_else(|| "committed TypeScript compiler options are not an object".to_string())?;
    let expected_resolution = if let Some(value) = options.get("moduleResolution") {
        match value.as_u64() {
            Some(1) => HistoricalV2TypeScriptModuleResolution::Classic,
            Some(2) => HistoricalV2TypeScriptModuleResolution::Node10,
            Some(3) => HistoricalV2TypeScriptModuleResolution::Node16,
            Some(99) => HistoricalV2TypeScriptModuleResolution::NodeNext,
            Some(100) => HistoricalV2TypeScriptModuleResolution::Bundler,
            _ => return Err("committed TypeScript moduleResolution is unsupported".to_string()),
        }
    } else {
        let module = match options.get("module") {
            Some(value) => value
                .as_u64()
                .ok_or_else(|| "committed TypeScript module kind is unsupported".to_string())?,
            None => {
                let target = match options.get("target") {
                    Some(value) => value.as_u64().ok_or_else(|| {
                        "committed TypeScript target kind is unsupported".to_string()
                    })?,
                    None => 1,
                };
                if target >= 2 { 5 } else { 1 }
            }
        };
        match module {
            1 => HistoricalV2TypeScriptModuleResolution::Node10,
            100 => HistoricalV2TypeScriptModuleResolution::Node16,
            199 => HistoricalV2TypeScriptModuleResolution::NodeNext,
            200 => HistoricalV2TypeScriptModuleResolution::Bundler,
            _ => HistoricalV2TypeScriptModuleResolution::Classic,
        }
    };
    if profile.compiler_module_resolution != Some(expected_resolution) {
        return Err("Node consumer profile module-resolution mode changed".to_string());
    }
    let custom_conditions = match options.get("customConditions") {
        None => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "TypeScript custom condition is not a string".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err("TypeScript customConditions is not an array".to_string()),
    };
    let mut compiler_conditions = vec![
        match profile.mode {
            HistoricalV2NodeConsumerMode::Import => "import",
            HistoricalV2NodeConsumerMode::Require => "require",
        }
        .to_string(),
    ];
    if options.get("noDtsResolution").and_then(Value::as_bool) != Some(true) {
        compiler_conditions.push("types".to_string());
    }
    if expected_resolution != HistoricalV2TypeScriptModuleResolution::Bundler {
        compiler_conditions.push("node".to_string());
    }
    compiler_conditions.extend(custom_conditions.iter().cloned());
    if profile.custom_conditions != custom_conditions
        || profile.compiler_conditions != compiler_conditions
    {
        return Err("Node consumer profile compiler conditions changed".to_string());
    }
    Ok(())
}

fn validate_resolution(
    inventory: &IntentionalBoundaryRepositoryInventory,
    exposures: &[&HistoricalV2NodePackageExposure],
    resolution: &HistoricalV2NodeConsumerResolution,
    compiler: bool,
) -> Result<(), String> {
    match resolution {
        HistoricalV2NodeConsumerResolution::Resolved {
            selected_exposure_id,
            selected_surface_slot_id,
            declared_target_repository_path,
            resolved_repository_path,
            resolved_object_id,
            compiler_source_substitution,
            evidence_sha256,
        } => {
            require_sha256(evidence_sha256, "Node consumer resolution evidence")?;
            let selected = exposures
                .iter()
                .find(|exposure| exposure.exposure_id == *selected_exposure_id)
                .ok_or_else(|| "Node consumer selected an undeclared branch".to_string())?;
            if selected.surface_slot_id != *selected_surface_slot_id
                || selected.target_repository_path != *declared_target_repository_path
                || *compiler_source_substitution
                    != (compiler && resolved_repository_path != declared_target_repository_path)
            {
                return Err("Node consumer selected branch provenance changed".to_string());
            }
            let actual_object = inventory
                .tracked_entries
                .iter()
                .find(|entry| entry.repository_path == *resolved_repository_path)
                .map(|entry| entry.object_id.as_str());
            if resolved_object_id.as_deref() != actual_object
                || (compiler && resolved_object_id.is_none())
            {
                return Err("Node consumer resolved target identity changed".to_string());
            }
        }
        HistoricalV2NodeConsumerResolution::Unresolved {
            evidence_sha256, ..
        } => require_sha256(evidence_sha256, "Node consumer unresolved evidence")?,
    }
    Ok(())
}
