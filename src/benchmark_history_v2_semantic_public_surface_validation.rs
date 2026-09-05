use super::super::{
    HistoricalV2NodePackageExposure, HistoricalV2NodePackageTargetStatus,
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
    public_root_paths: &BTreeSet<String>,
) -> Result<(), String> {
    let files = source
        .source_files
        .iter()
        .filter(|file| public_surface_document_paths.contains(file.repository_path.as_str()))
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let direct_bindings = semantic
        .public_bindings
        .iter()
        .filter(|binding| {
            matches!(
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
        .map(|hop| (hop.reexport_unit_id.as_str(), hop))
        .collect::<BTreeMap<_, _>>();

    let mut cache = BTreeMap::new();
    let mut expected = BTreeSet::new();
    for file in files
        .values()
        .filter(|file| !matches!(file.language.as_str(), "typescript" | "javascript"))
        .filter(|file| file.language != "rust" || public_root_paths.contains(&file.repository_path))
    {
        for slot in resolve_expected_file(
            file,
            &files,
            &direct_bindings,
            &hops,
            &mut cache,
            &mut Vec::new(),
        )? {
            if slot.binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion {
                expected.insert(slot.binding);
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
    let mut expected_package_exposures = BTreeSet::new();
    for exposure in &source.node_package_surfaces.exposures {
        if exposure.target_status != HistoricalV2NodePackageTargetStatus::TrackedRegularFile {
            return Err(
                "historical-v2 semantic validation found an unresolved Node package root"
                    .to_string(),
            );
        }
        let file = files
            .get(exposure.target_repository_path.as_str())
            .copied()
            .ok_or_else(|| {
                "historical-v2 semantic validation omitted a Node package target".to_string()
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
            expected_package_exposures.insert(expected_node_package_slot(exposure, slot)?);
        }
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

fn expected_node_package_slot(
    exposure: &HistoricalV2NodePackageExposure,
    target: ExpectedPublicSlot,
) -> Result<HistoricalV2SemanticPublicBinding, String> {
    let surface_unit_id = super::public_surface::historical_node_package_public_surface_unit_id(
        &exposure.surface_slot_id,
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
    binding.repository_path = exposure.target_repository_path.clone();
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
