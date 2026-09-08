use super::super::{
    HistoricalV2NodeConsumerProfile, HistoricalV2NodeConsumerResolution,
    HistoricalV2NodePackageExposure, HistoricalV2PythonDistributionModule,
    HistoricalV2SemanticPublicBinding, HistoricalV2SemanticPublicBindingKind,
    HistoricalV2SemanticPublicReexportHop, HistoricalV2SemanticSnapshotCensus,
    HistoricalV2SourceFile, HistoricalV2SourcePublicNamespace, HistoricalV2SourcePublicReexport,
    HistoricalV2SourcePublicReexportKind, HistoricalV2SourcePublicSymbolKind,
    HistoricalV2SourceSnapshotCensus,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedPublicSlot {
    name: String,
    owner: Option<String>,
    namespace: HistoricalV2SourcePublicNamespace,
    kind: HistoricalV2SourcePublicSymbolKind,
    binding: HistoricalV2SemanticPublicBinding,
}

pub(super) fn validate_complete_reexport_expansions(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
    public_surface_document_paths: &BTreeSet<&str>,
) -> Result<(), String> {
    let source_files = source
        .source_files
        .iter()
        .filter(|file| public_surface_document_paths.contains(file.repository_path.as_str()))
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut expected = BTreeSet::new();
    let mut expected_package_exposures = BTreeSet::new();
    for committed in &semantic.indexers {
        let variant = &committed.variant;
        let indexed_paths = committed
            .indexed_document_paths
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let files = source_files
            .iter()
            .filter(|(path, _)| indexed_paths.contains(**path))
            .map(|(path, file)| (*path, *file))
            .collect::<BTreeMap<_, _>>();
        let direct_bindings = semantic
            .public_bindings
            .iter()
            .filter(|binding| {
                binding.variant == *variant
                    && matches!(
                        binding.binding,
                        HistoricalV2SemanticPublicBindingKind::Definition
                            | HistoricalV2SemanticPublicBindingKind::Reference
                    )
            })
            .map(|binding| (binding.declaration_unit_id.as_str(), binding))
            .collect::<BTreeMap<_, _>>();
        let hops = semantic
            .public_reexport_hops
            .iter()
            .filter(|hop| hop.variant == *variant)
            .map(|hop| (hop.reexport_unit_id.as_str(), hop))
            .collect::<BTreeMap<_, _>>();
        let variant_public_root_paths = semantic
            .public_roots
            .iter()
            .filter(|root| root.variant == *variant)
            .map(|root| root.repository_path.as_str())
            .collect::<BTreeSet<_>>();
        let mut cache = BTreeMap::new();
        for file in files
            .values()
            .filter(|file| {
                !matches!(
                    file.language.as_str(),
                    "typescript" | "javascript" | "python"
                )
            })
            .filter(|file| {
                file.language != "rust"
                    || variant_public_root_paths.contains(file.repository_path.as_str())
            })
        {
            for slot in resolve_expected_file(
                file,
                &files,
                &direct_bindings,
                &hops,
                &mut cache,
                &mut Vec::new(),
            )? {
                if slot.binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
                {
                    expected.insert(slot.binding);
                }
            }
        }
        if committed.census.indexer
            == super::super::IntentionalBoundaryIndexerKind::TypeScriptJavaScript
        {
            if matches!(
                variant,
                crate::semantic_index::SemanticIndexVariant::Qualified { .. }
            ) && source
                .node_consumer_profiles
                .profiles
                .iter()
                .any(|profile| profile.project_model_execution_id.is_none())
            {
                return Err(
                    "historical-v2 semantic validation found a Node profile without a compiler world"
                        .to_string(),
                );
            }
            for profile in source
                .node_consumer_profiles
                .profiles
                .iter()
                .filter(|profile| match variant {
                    crate::semantic_index::SemanticIndexVariant::Qualified { identity, .. } => {
                        profile.project_model_execution_id.as_deref() == Some(identity.0.as_str())
                    }
                    crate::semantic_index::SemanticIndexVariant::Unqualified => true,
                })
            {
                let HistoricalV2NodeConsumerResolution::Resolved {
                    selected_exposure_id,
                    resolved_repository_path,
                    ..
                } = &profile.compiler
                else {
                    return Err(
                        "historical-v2 semantic validation found an unresolved Node compiler profile"
                            .to_string(),
                    );
                };
                if !matches!(
                    profile.runtime,
                    HistoricalV2NodeConsumerResolution::Resolved { .. }
                ) {
                    return Err(
                        "historical-v2 semantic validation found an unresolved Node runtime profile"
                            .to_string(),
                    );
                }
                let exposure = source
                    .node_package_surfaces
                    .exposures
                    .iter()
                    .find(|exposure| exposure.exposure_id == *selected_exposure_id)
                    .ok_or_else(|| {
                        "historical-v2 semantic validation found an unknown selected Node branch"
                            .to_string()
                    })?;
                let file = files
                    .get(resolved_repository_path.as_str())
                    .copied()
                    .ok_or_else(|| {
                        "historical-v2 semantic validation omitted a Node package target"
                            .to_string()
                    })?;
                if !matches!(file.language.as_str(), "typescript" | "javascript") {
                    return Err(
                        "historical-v2 semantic validation found a non-JavaScript Node package target"
                            .to_string(),
                    );
                }
                for slot in resolve_expected_file(
                    file,
                    &files,
                    &direct_bindings,
                    &hops,
                    &mut cache,
                    &mut Vec::new(),
                )?
                .into_iter()
                .filter(|slot| slot.owner.is_none())
                {
                    expected_package_exposures
                        .insert(expected_node_package_slot(profile, exposure, slot)?);
                }
            }
        }
        if committed.census.indexer == super::super::IntentionalBoundaryIndexerKind::Python {
            for root in semantic
                .public_roots
                .iter()
                .filter(|root| root.variant == *variant)
            {
                let super::super::HistoricalV2SemanticPublicRootOrigin::PythonDistributionModule {
                    module_exposure_id,
                    ..
                } = &root.origin
                else {
                    continue;
                };
                let module = source
                    .python_distribution_surfaces
                    .modules
                    .iter()
                    .find(|module| module.module_exposure_id == *module_exposure_id)
                    .ok_or_else(|| {
                        "historical-v2 semantic validation invented a Python distribution root"
                            .to_string()
                    })?;
                let file = files
                    .get(root.repository_path.as_str())
                    .copied()
                    .ok_or_else(|| {
                        "historical-v2 semantic validation omitted a Python distribution root"
                            .to_string()
                    })?;
                for slot in resolve_expected_file(
                    file,
                    &files,
                    &direct_bindings,
                    &hops,
                    &mut cache,
                    &mut Vec::new(),
                )?
                .into_iter()
                .filter(|slot| slot.owner.is_none())
                {
                    expected_package_exposures.insert(expected_python_package_slot(
                        module,
                        &root.repository_path,
                        slot,
                    )?);
                }
            }
        }
        if committed.census.indexer == super::super::IntentionalBoundaryIndexerKind::Kotlin {
            for root in semantic
                .kotlin_compilation_roots
                .iter()
                .filter(|root| root.variant == *variant)
            {
                for repository_path in &root.source_repository_paths {
                    let file = files
                        .get(repository_path.as_str())
                        .copied()
                        .ok_or_else(|| {
                            "historical-v2 semantic validation omitted a Kotlin compilation source"
                                .to_string()
                        })?;
                    for slot in resolve_expected_file(
                        file,
                        &files,
                        &direct_bindings,
                        &hops,
                        &mut cache,
                        &mut Vec::new(),
                    )?
                    .into_iter()
                    .filter(|slot| slot.owner.is_none())
                    {
                        expected_package_exposures
                            .insert(expected_kotlin_package_slot(root, slot)?);
                    }
                }
            }
        }
    }
    let actual = semantic
        .public_bindings
        .iter()
        .filter(|binding| {
            binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(
            "historical-v2 compiler re-export expansion set is incomplete or invented".to_string(),
        );
    }
    let actual_package_exposures = semantic
        .public_bindings
        .iter()
        .filter(|binding| binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure)
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_package_exposures != expected_package_exposures {
        return Err(
            "historical-v2 compiler package exposure set is incomplete or invented".to_string(),
        );
    }
    Ok(())
}

fn expected_python_package_slot(
    module: &HistoricalV2PythonDistributionModule,
    repository_path: &str,
    target: ExpectedPublicSlot,
) -> Result<HistoricalV2SemanticPublicBinding, String> {
    let surface_unit_id =
        super::public_surface::historical_python_distribution_public_surface_unit_id(
            &module.surface_slot_id,
            &target.name,
            target.owner.as_deref(),
            target.namespace,
            target.kind,
        )?;
    let declaration_unit_id =
        super::public_surface::python_distribution_expansion_declaration_unit_id(
            &surface_unit_id,
            &module.module_exposure_id,
            &target.binding.origin_declaration_unit_id,
            &target.binding.symbol_id,
            &target.binding.reexport_path,
        )?;
    let mut binding = target.binding;
    binding.surface_unit_id = surface_unit_id;
    binding.declaration_unit_id = declaration_unit_id;
    binding.repository_path = repository_path.to_string();
    binding.binding = HistoricalV2SemanticPublicBindingKind::PackageExposure;
    binding.externally_reachable = true;
    binding.package_exposure_id = Some(module.module_exposure_id.clone());
    Ok(binding)
}

fn expected_kotlin_package_slot(
    root: &super::super::HistoricalV2SemanticKotlinCompilationRoot,
    target: ExpectedPublicSlot,
) -> Result<HistoricalV2SemanticPublicBinding, String> {
    let surface_unit_id =
        super::public_surface::historical_kotlin_compilation_public_surface_unit_id(
            &root.surface_slot_id,
            &target.name,
            target.owner.as_deref(),
            target.namespace,
            target.kind,
        )?;
    let declaration_unit_id =
        super::public_surface::kotlin_compilation_expansion_declaration_unit_id(
            &surface_unit_id,
            &root.surface_slot_id,
            &target.binding.origin_declaration_unit_id,
            &target.binding.symbol_id,
        )?;
    let mut binding = target.binding;
    binding.surface_unit_id = surface_unit_id;
    binding.declaration_unit_id = declaration_unit_id;
    binding.binding = HistoricalV2SemanticPublicBindingKind::PackageExposure;
    binding.externally_reachable = true;
    binding.package_exposure_id = Some(root.surface_slot_id.clone());
    Ok(binding)
}

fn expected_node_package_slot(
    profile: &HistoricalV2NodeConsumerProfile,
    exposure: &HistoricalV2NodePackageExposure,
    target: ExpectedPublicSlot,
) -> Result<HistoricalV2SemanticPublicBinding, String> {
    let surface_unit_id = super::public_surface::historical_node_package_public_surface_unit_id(
        &profile.consumer_surface_slot_id,
        &target.name,
        target.owner.as_deref(),
        target.namespace,
        target.kind,
    )?;
    let declaration_unit_id = super::public_surface::node_package_expansion_declaration_unit_id(
        &surface_unit_id,
        &exposure.exposure_id,
        &target.binding.origin_declaration_unit_id,
        &target.binding.symbol_id,
        &target.binding.reexport_path,
    )?;
    let mut binding = target.binding;
    binding.surface_unit_id = surface_unit_id;
    binding.declaration_unit_id = declaration_unit_id;
    let HistoricalV2NodeConsumerResolution::Resolved {
        resolved_repository_path,
        ..
    } = &profile.compiler
    else {
        return Err("historical-v2 Node package profile became unresolved".to_string());
    };
    binding.repository_path = resolved_repository_path.clone();
    binding.binding = HistoricalV2SemanticPublicBindingKind::PackageExposure;
    binding.externally_reachable = true;
    binding.package_exposure_id = Some(exposure.exposure_id.clone());
    Ok(binding)
}

fn resolve_expected_file<'a>(
    file: &'a HistoricalV2SourceFile,
    files: &BTreeMap<&'a str, &'a HistoricalV2SourceFile>,
    direct_bindings: &BTreeMap<&str, &HistoricalV2SemanticPublicBinding>,
    hops: &BTreeMap<&str, &HistoricalV2SemanticPublicReexportHop>,
    cache: &mut BTreeMap<String, Vec<ExpectedPublicSlot>>,
    stack: &mut Vec<String>,
) -> Result<Vec<ExpectedPublicSlot>, String> {
    if let Some(slots) = cache.get(&file.repository_path) {
        return Ok(slots.clone());
    }
    if stack.contains(&file.repository_path) {
        stack.push(file.repository_path.clone());
        return Err(format!(
            "historical-v2 semantic validation found a cyclic public re-export path: {}",
            stack.join(" -> ")
        ));
    }
    stack.push(file.repository_path.clone());

    let mut slots = file
        .public_declarations
        .iter()
        .map(|declaration| {
            let binding = direct_bindings
                .get(declaration.declaration_unit_id.as_str())
                .copied()
                .ok_or_else(|| {
                    format!(
                        "historical-v2 semantic validation omitted direct public binding {}",
                        declaration.declaration_unit_id
                    )
                })?;
            Ok(ExpectedPublicSlot {
                name: declaration.name.clone(),
                owner: declaration.owner.clone(),
                namespace: declaration.namespace,
                kind: declaration.kind,
                binding: binding.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let direct_surfaces = slots
        .iter()
        .map(|slot| slot.binding.surface_unit_id.clone())
        .collect::<BTreeSet<_>>();
    let direct_surface_last_anchors = file.public_declarations.iter().fold(
        BTreeMap::<String, usize>::new(),
        |mut anchors, declaration| {
            anchors
                .entry(declaration.surface_unit_id.clone())
                .and_modify(|start| *start = (*start).max(declaration.identifier.start))
                .or_insert(declaration.identifier.start);
            anchors
        },
    );
    let mut wildcard_source_surfaces = BTreeMap::<String, String>::new();

    for reexport in &file.public_reexports {
        let hop = hops
            .get(reexport.reexport_unit_id.as_str())
            .copied()
            .ok_or_else(|| {
                "historical-v2 semantic validation omitted a public re-export hop".to_string()
            })?;
        let target = files
            .get(hop.target_repository_path.as_str())
            .copied()
            .ok_or_else(|| {
                "historical-v2 semantic validation found a non-enumerable re-export target"
                    .to_string()
            })?;
        let target_slots =
            resolve_expected_file(target, files, direct_bindings, hops, cache, stack)?;
        match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                let mut matched = false;
                for target_slot in target_slots.into_iter().filter(|slot| {
                    slot.name != "default"
                        && reexport
                            .name
                            .as_deref()
                            .is_none_or(|name| slot.name == name)
                }) {
                    matched = true;
                    let source_surface_unit_id = target_slot.binding.surface_unit_id.clone();
                    let expanded = expected_expanded_slot(file, reexport, hop, target_slot, None)?;
                    if direct_surfaces.contains(&expanded.binding.surface_unit_id) {
                        if file.language == "python"
                            && direct_surface_last_anchors
                                .get(&expanded.binding.surface_unit_id)
                                .is_some_and(|start| *start < reexport.directive.start)
                        {
                            return Err(format!(
                                "historical-v2 semantic validation found a Python wildcard overwriting an earlier direct public binding in {}",
                                file.repository_path
                            ));
                        }
                        continue;
                    }
                    if let Some(existing) = wildcard_source_surfaces.insert(
                        expanded.binding.surface_unit_id.clone(),
                        source_surface_unit_id.clone(),
                    ) && existing != source_surface_unit_id
                    {
                        return Err(format!(
                            "historical-v2 semantic validation found an ambiguous wildcard export in {}",
                            file.repository_path
                        ));
                    }
                    slots.push(expanded);
                }
                if let Some(name) = reexport.name.as_deref()
                    && !matched
                {
                    return Err(format!(
                        "historical-v2 semantic validation found Python __all__ name {name:?} absent from wildcard target {}",
                        hop.target_repository_path
                    ));
                }
            }
            HistoricalV2SourcePublicReexportKind::Namespace => {
                let namespace_name = reexport.name.as_deref().ok_or_else(|| {
                    "historical-v2 semantic validation found an unnamed namespace re-export"
                        .to_string()
                })?;
                if target_slots.is_empty() {
                    return Err(
                        "historical-v2 semantic validation found an empty namespace target"
                            .to_string(),
                    );
                }
                for target_slot in target_slots {
                    let expanded = expected_expanded_slot(
                        file,
                        reexport,
                        hop,
                        target_slot,
                        Some(namespace_name),
                    )?;
                    if direct_surfaces.contains(&expanded.binding.surface_unit_id) {
                        return Err(format!(
                            "historical-v2 semantic validation found a namespace collision in {}",
                            file.repository_path
                        ));
                    }
                    slots.push(expanded);
                }
            }
        }
    }

    stack.pop();
    slots.sort_by(|left, right| left.binding.cmp(&right.binding));
    cache.insert(file.repository_path.clone(), slots.clone());
    Ok(slots)
}

fn expected_expanded_slot(
    file: &HistoricalV2SourceFile,
    reexport: &HistoricalV2SourcePublicReexport,
    hop: &HistoricalV2SemanticPublicReexportHop,
    target: ExpectedPublicSlot,
    namespace_name: Option<&str>,
) -> Result<ExpectedPublicSlot, String> {
    let (name, owner, namespace, kind) = namespace_name.map_or_else(
        || {
            (
                target.name.clone(),
                target.owner.clone(),
                target.namespace,
                target.kind,
            )
        },
        |name| {
            (
                name.to_string(),
                None,
                HistoricalV2SourcePublicNamespace::Module,
                HistoricalV2SourcePublicSymbolKind::Module,
            )
        },
    );
    let module_identity = super::super::history_v2_source_census::public_module_identity(
        &file.repository_path,
        &file.language,
    );
    let surface_unit_id =
        super::super::history_v2_source_census::historical_public_surface_unit_id(
            &file.language,
            &module_identity,
            &name,
            owner.as_deref(),
            namespace,
            kind,
        )?;
    let mut reexport_path = vec![reexport.reexport_unit_id.clone()];
    reexport_path.extend(target.binding.reexport_path);
    let declaration_unit_id = super::reexport_expansion_declaration_unit_id(
        &surface_unit_id,
        &file.repository_path,
        &target.binding.origin_declaration_unit_id,
        &target.binding.symbol_id,
        &reexport_path,
    )?;
    Ok(ExpectedPublicSlot {
        name,
        owner,
        namespace,
        kind,
        binding: HistoricalV2SemanticPublicBinding {
            indexer: hop.indexer,
            variant: hop.variant.clone(),
            surface_unit_id,
            declaration_unit_id,
            origin_declaration_unit_id: target.binding.origin_declaration_unit_id,
            reexport_path,
            repository_path: file.repository_path.clone(),
            symbol_id: target.binding.symbol_id,
            owner_symbol_id: target.binding.owner_symbol_id,
            exposing_owner_declaration_unit_id: None,
            package_exposure_id: None,
            binding: HistoricalV2SemanticPublicBindingKind::ReexportExpansion,
            externally_reachable: true,
            position_encoding: hop.position_encoding,
            compiler_anchor: hop.compiler_anchor.clone(),
            owner_compiler_anchor: target.binding.owner_compiler_anchor,
        },
    })
}
