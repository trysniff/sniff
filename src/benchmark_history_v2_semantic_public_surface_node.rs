use super::*;

pub(super) struct CompilerNodePublicRoot<'a> {
    pub(super) profile: &'a HistoricalV2NodeConsumerProfile,
    pub(super) exposure: &'a HistoricalV2NodePackageExposure,
    pub(super) symbol: &'a SemanticSymbol,
    pub(super) definition: &'a SemanticLocation,
}

pub(super) fn compiler_node_public_roots<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    index: &'a SemanticIndex,
) -> Result<Vec<CompilerNodePublicRoot<'a>>, String> {
    if source.node_package_surfaces.revision != source.revision
        || source.node_package_surfaces.inventory_sha256 != source.inventory_sha256
        || source.node_consumer_profiles.revision != source.revision
        || source.node_consumer_profiles.inventory_sha256 != source.inventory_sha256
        || source
            .node_consumer_profiles
            .node_package_surface_census_sha256
            != source.node_package_surfaces.census_sha256
        || source
            .node_consumer_profiles
            .typescript_project_model_census_sha256
            != source.typescript_project_model.project_model_census_sha256
    {
        return Err("historical-v2 Node package surface identity changed".to_string());
    }
    let source_files = source
        .source_files
        .iter()
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut roots = Vec::new();
    let expected_execution = match &index.variant {
        SemanticIndexVariant::Qualified { identity, .. } => Some(identity.0.as_str()),
        SemanticIndexVariant::Unqualified => {
            let executions = source
                .typescript_project_model
                .executions
                .iter()
                .map(|execution| execution.execution_id.as_str())
                .collect::<BTreeSet<_>>();
            if executions.len() > 1 {
                return Err(
                    "historical-v2 unqualified TypeScript index has multiple compiler worlds"
                        .to_string(),
                );
            }
            executions.into_iter().next()
        }
    };
    if expected_execution.is_some()
        && source
            .node_consumer_profiles
            .profiles
            .iter()
            .any(|profile| profile.project_model_execution_id.is_none())
    {
        return Err(
            "historical-v2 Node consumer profile has no compiler-world identity".to_string(),
        );
    }
    for profile in source
        .node_consumer_profiles
        .profiles
        .iter()
        .filter(|profile| profile.project_model_execution_id.as_deref() == expected_execution)
    {
        let HistoricalV2NodeConsumerResolution::Resolved {
            selected_exposure_id,
            selected_surface_slot_id,
            declared_target_repository_path,
            resolved_repository_path,
            resolved_object_id,
            ..
        } = &profile.compiler
        else {
            return Err(format!(
                "historical-v2 Node consumer profile has no compiler root: {}",
                profile.profile_id
            ));
        };
        if !matches!(
            profile.runtime,
            HistoricalV2NodeConsumerResolution::Resolved { .. }
        ) {
            return Err(format!(
                "historical-v2 Node consumer profile has no runtime target: {}",
                profile.profile_id
            ));
        }
        let exposure = source
            .node_package_surfaces
            .exposures
            .iter()
            .find(|exposure| exposure.exposure_id == *selected_exposure_id)
            .ok_or_else(|| {
                "historical-v2 Node consumer profile selected an unknown declaration".to_string()
            })?;
        if !profile
            .declared_exposure_ids
            .contains(&exposure.exposure_id)
            || exposure.surface_slot_id != *selected_surface_slot_id
            || exposure.target_repository_path != *declared_target_repository_path
            || (declared_target_repository_path == resolved_repository_path
                && (exposure.target_status
                    != HistoricalV2NodePackageTargetStatus::TrackedRegularFile
                    || exposure.target_object_id.as_deref() != resolved_object_id.as_deref()))
        {
            return Err(
                "historical-v2 Node consumer profile declaration provenance changed".to_string(),
            );
        }
        let HistoricalV2NodeConsumerResolution::Resolved {
            selected_exposure_id: runtime_exposure_id,
            selected_surface_slot_id: runtime_surface_slot_id,
            declared_target_repository_path: runtime_declared_target,
            ..
        } = &profile.runtime
        else {
            unreachable!("runtime resolution checked above")
        };
        let runtime_exposure = source
            .node_package_surfaces
            .exposures
            .iter()
            .find(|candidate| candidate.exposure_id == *runtime_exposure_id)
            .ok_or_else(|| {
                "historical-v2 Node runtime profile selected an unknown declaration".to_string()
            })?;
        if !profile
            .declared_exposure_ids
            .contains(&runtime_exposure.exposure_id)
            || runtime_exposure.surface_slot_id != *runtime_surface_slot_id
            || runtime_exposure.target_repository_path != *runtime_declared_target
        {
            return Err(
                "historical-v2 Node runtime profile declaration provenance changed".to_string(),
            );
        }
        let file = source_files
            .get(resolved_repository_path.as_str())
            .copied()
            .ok_or_else(|| {
                format!(
                    "historical-v2 Node package target is absent from source census: {}",
                    resolved_repository_path
                )
            })?;
        if !matches!(file.language.as_str(), "typescript" | "javascript")
            || file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required
            || resolved_object_id.as_deref() != Some(file.object_id.as_str())
        {
            return Err(format!(
                "historical-v2 Node package target is not required compiler source: {}",
                resolved_repository_path
            ));
        }
        let candidates = index
            .symbols
            .values()
            .filter(|symbol| {
                symbol.origin == SemanticSymbolOrigin::Repository
                    && symbol.ambiguity_notes.is_empty()
                    && symbol.owner.is_none()
                    && symbol.kind.category == SemanticSymbolCategory::Module
            })
            .filter_map(|symbol| {
                let parsed = scip::symbol::parse_symbol(&symbol.provider_identity).ok()?;
                (parsed.scheme == "scip-typescript").then_some((symbol, parsed))
            })
            .flat_map(|(symbol, _)| {
                symbol
                    .definitions
                    .iter()
                    .filter(|definition| definition.document.0 == *resolved_repository_path)
                    .map(move |definition| (symbol, definition))
            })
            .collect::<Vec<_>>();
        let [(symbol, definition)] = candidates.as_slice() else {
            return Err(format!(
                "historical-v2 compiler resolved Node package exposure {} to {} root module definitions",
                profile.profile_id,
                candidates.len()
            ));
        };
        if !index.documents.contains_key(&definition.document) {
            return Err(format!(
                "historical-v2 compiler omitted Node package root document {}",
                resolved_repository_path
            ));
        }
        roots.push(CompilerNodePublicRoot {
            profile,
            exposure,
            symbol,
            definition,
        });
    }
    Ok(roots)
}
