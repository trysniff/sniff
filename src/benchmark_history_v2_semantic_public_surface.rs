use super::super::{
    HistoricalV2NodePackageExposure, HistoricalV2NodePackageTargetStatus,
    HistoricalV2PublicSurfaceCoverage, HistoricalV2SemanticPublicBinding,
    HistoricalV2SemanticPublicBindingKind, HistoricalV2SemanticPublicReexportHop,
    HistoricalV2SemanticPublicRoot, HistoricalV2SemanticPublicRootOrigin,
    HistoricalV2SemanticSymbol, HistoricalV2SourceFile, HistoricalV2SourcePublicBindingKind,
    HistoricalV2SourcePublicDeclaration, HistoricalV2SourcePublicNamespace,
    HistoricalV2SourcePublicReexport, HistoricalV2SourcePublicReexportKind,
    HistoricalV2SourcePublicSymbolKind, HistoricalV2SourceSemanticCoverage,
    HistoricalV2SourceSnapshotCensus, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryProjectModelProvider, IntentionalBoundaryProjectModelTargetStatus,
};
use super::{
    file_repository_path, flatten_location, hash_json, indexer_for_language, indexer_kind,
    retain_symbol,
};
use crate::semantic_index::{
    RepositoryPath, SemanticIndex, SemanticLocation, SemanticPosition, SemanticPositionEncoding,
    SemanticSourceRange, SemanticSymbol, SemanticSymbolCategory, SemanticSymbolOrigin,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::types::FileRecord;
use scip::types::descriptor::Suffix;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
pub(super) struct PublicSurfaceBindingInputs<'a> {
    pub(super) root: &'a Path,
    pub(super) source: &'a HistoricalV2SourceSnapshotCensus,
    pub(super) indexed_files: &'a [FileRecord],
    pub(super) kind: SemanticIndexerKind,
    pub(super) index: &'a SemanticIndex,
}

pub(super) struct PublicSurfaceBindingOutputs<'a> {
    pub(super) symbols:
        &'a mut BTreeMap<(IntentionalBoundaryIndexerKind, String), HistoricalV2SemanticSymbol>,
    pub(super) bindings: &'a mut Vec<HistoricalV2SemanticPublicBinding>,
    pub(super) roots: &'a mut Vec<HistoricalV2SemanticPublicRoot>,
    pub(super) reexport_hops: &'a mut BTreeMap<String, HistoricalV2SemanticPublicReexportHop>,
    pub(super) public_surface_document_paths: &'a mut BTreeSet<String>,
}

pub(super) fn bind_public_surface(
    inputs: PublicSurfaceBindingInputs<'_>,
    outputs: PublicSurfaceBindingOutputs<'_>,
) -> Result<(), String> {
    let PublicSurfaceBindingInputs {
        root,
        source,
        indexed_files,
        kind,
        index,
    } = inputs;
    let PublicSurfaceBindingOutputs {
        symbols,
        bindings,
        roots,
        reexport_hops,
        public_surface_document_paths,
    } = outputs;
    let records = indexed_files
        .iter()
        .map(|file| Ok((file_repository_path(root, file)?, file)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let source_files = source
        .source_files
        .iter()
        .filter(|file| {
            file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required
                && indexer_for_language(&file.language) == Ok(kind)
        })
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut direct_bindings = BTreeMap::new();
    let rust_library_roots = rust_public_library_target_roots(source)?;
    let indexed_source_paths = indexed_files
        .iter()
        .map(|file| file_repository_path(root, file))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let indexed_rust_library_roots = rust_library_roots
        .intersection(&indexed_source_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let rust_roots = if kind == SemanticIndexerKind::Rust {
        compiler_rust_public_roots(index, &indexed_rust_library_roots)?
    } else {
        BTreeMap::new()
    };
    let node_roots = if kind == SemanticIndexerKind::TypeScriptJavaScript {
        compiler_node_public_roots(source, index)?
    } else {
        Vec::new()
    };
    for (repository_path, (symbol, definition)) in &rust_roots {
        retain_symbol(symbols, indexer_kind(kind), symbol, false, true, false)?;
        roots.push(HistoricalV2SemanticPublicRoot {
            indexer: indexer_kind(kind),
            repository_path: repository_path.clone(),
            module_symbol_id: symbol.id.0.clone(),
            compiler_definition: flatten_location(definition),
            origin: HistoricalV2SemanticPublicRootOrigin::RustCargoLibrary,
        });
    }
    for root in &node_roots {
        retain_symbol(symbols, indexer_kind(kind), root.symbol, false, true, false)?;
        roots.push(HistoricalV2SemanticPublicRoot {
            indexer: indexer_kind(kind),
            repository_path: root.exposure.target_repository_path.clone(),
            module_symbol_id: root.symbol.id.0.clone(),
            compiler_definition: flatten_location(root.definition),
            origin: HistoricalV2SemanticPublicRootOrigin::NodePackageExposure {
                exposure_id: root.exposure.exposure_id.clone(),
                surface_slot_id: root.exposure.surface_slot_id.clone(),
            },
        });
    }
    for file in source_files.values() {
        let path = RepositoryPath(file.repository_path.clone());
        let Some(document) = index.documents.get(&path) else {
            continue;
        };
        public_surface_document_paths.insert(file.repository_path.clone());
        if file.public_surface_coverage != HistoricalV2PublicSurfaceCoverage::Complete {
            return Err(format!(
                "historical-v2 public-surface collector is incomplete for {}",
                file.repository_path
            ));
        }
        let record = records.get(&file.repository_path).ok_or_else(|| {
            format!(
                "historical-v2 public-surface source is missing from parser records: {}",
                file.repository_path
            )
        })?;
        let file_externally_reachable = match kind {
            SemanticIndexerKind::Rust => rust_roots.contains_key(&file.repository_path),
            SemanticIndexerKind::TypeScriptJavaScript => false,
            _ => true,
        };
        for declaration in &file.public_declarations {
            let location = declaration_location(
                file,
                declaration,
                &record.source,
                document.position_encoding,
            )?;
            let (binding, symbol) = match declaration.binding {
                HistoricalV2SourcePublicBindingKind::Definition => (
                    HistoricalV2SemanticPublicBindingKind::Definition,
                    symbol_at_exact_definition(index, declaration, &location)?,
                ),
                HistoricalV2SourcePublicBindingKind::Reference => (
                    HistoricalV2SemanticPublicBindingKind::Reference,
                    symbol_at_exact_reference(index, document, declaration, &location)?,
                ),
            };
            let owner_location = declaration_owner_location(
                file,
                declaration,
                &record.source,
                document.position_encoding,
            )?;
            let owner_symbol = owner_location
                .as_ref()
                .map(|location| {
                    symbol_at_exact_owner_reference(index, document, declaration, location)
                })
                .transpose()?;
            let externally_reachable = file_externally_reachable
                && (kind != SemanticIndexerKind::Rust || owner_symbol.is_none());
            if kind == SemanticIndexerKind::Rust
                && binding == HistoricalV2SemanticPublicBindingKind::Reference
                && matches!(
                    symbol.kind.category,
                    SemanticSymbolCategory::Module
                        | SemanticSymbolCategory::Namespace
                        | SemanticSymbolCategory::Package
                )
            {
                return Err(format!(
                    "historical-v2 Rust public module reference {} was not represented as a namespace re-export",
                    declaration.declaration_unit_id
                ));
            }
            retain_symbol(
                symbols,
                indexer_kind(kind),
                symbol,
                externally_reachable,
                false,
                false,
            )?;
            if let Some(owner_symbol) = owner_symbol {
                retain_symbol(
                    symbols,
                    indexer_kind(kind),
                    owner_symbol,
                    false,
                    false,
                    false,
                )?;
            }
            let public_binding = HistoricalV2SemanticPublicBinding {
                indexer: indexer_kind(kind),
                surface_unit_id: declaration.surface_unit_id.clone(),
                declaration_unit_id: declaration.declaration_unit_id.clone(),
                origin_declaration_unit_id: declaration.declaration_unit_id.clone(),
                reexport_path: Vec::new(),
                repository_path: file.repository_path.clone(),
                symbol_id: symbol.id.0.clone(),
                owner_symbol_id: owner_symbol.map(|symbol| symbol.id.0.clone()),
                exposing_owner_declaration_unit_id: None,
                package_exposure_id: None,
                binding,
                externally_reachable,
                position_encoding: document.position_encoding,
                compiler_anchor: flatten_location(&location),
                owner_compiler_anchor: owner_location.as_ref().map(flatten_location),
            };
            if direct_bindings
                .insert(
                    declaration.declaration_unit_id.clone(),
                    public_binding.clone(),
                )
                .is_some()
            {
                return Err("historical-v2 repeated a direct public declaration".to_string());
            }
            bindings.push(public_binding);
        }
    }

    let mut cache = BTreeMap::new();
    for file in source_files
        .values()
        .filter(|file| public_surface_document_paths.contains(file.repository_path.as_str()))
        .filter(|file| {
            !matches!(
                kind,
                SemanticIndexerKind::Rust | SemanticIndexerKind::TypeScriptJavaScript
            ) || rust_roots.contains_key(&file.repository_path)
        })
    {
        let slots = resolve_file_public_slots(
            file,
            &source_files,
            &records,
            &direct_bindings,
            kind,
            index,
            symbols,
            reexport_hops,
            &mut cache,
            &mut Vec::new(),
        )?;
        for mut slot in slots
            .into_iter()
            .filter(|slot| !slot.binding.reexport_path.is_empty())
        {
            slot.binding.externally_reachable = true;
            let symbol = index
                .symbols
                .get(&crate::semantic_index::SemanticSymbolId(
                    slot.binding.symbol_id.clone(),
                ))
                .ok_or_else(|| {
                    "historical-v2 public expansion points to a missing compiler symbol".to_string()
                })?;
            retain_symbol(symbols, indexer_kind(kind), symbol, true, false, false)?;
            bindings.push(slot.binding);
        }
    }
    for root in node_roots {
        let file = source_files
            .get(root.exposure.target_repository_path.as_str())
            .copied()
            .ok_or_else(|| {
                format!(
                    "historical-v2 Node package root is absent from source census: {}",
                    root.exposure.target_repository_path
                )
            })?;
        let slots = resolve_file_public_slots(
            file,
            &source_files,
            &records,
            &direct_bindings,
            kind,
            index,
            symbols,
            reexport_hops,
            &mut cache,
            &mut Vec::new(),
        )?;
        for slot in slots.into_iter().filter(|slot| slot.owner.is_none()) {
            let expanded = expand_node_package_slot(root.exposure, slot)?;
            let symbol = index
                .symbols
                .get(&crate::semantic_index::SemanticSymbolId(
                    expanded.binding.symbol_id.clone(),
                ))
                .ok_or_else(|| {
                    "historical-v2 Node package expansion points to a missing compiler symbol"
                        .to_string()
                })?;
            retain_symbol(symbols, indexer_kind(kind), symbol, true, false, false)?;
            bindings.push(expanded.binding);
        }
    }
    expand_owner_surfaces(source, index, symbols, bindings)?;
    Ok(())
}

fn expand_owner_surfaces(
    source: &HistoricalV2SourceSnapshotCensus,
    index: &SemanticIndex,
    symbols: &mut BTreeMap<(IntentionalBoundaryIndexerKind, String), HistoricalV2SemanticSymbol>,
    bindings: &mut Vec<HistoricalV2SemanticPublicBinding>,
) -> Result<(), String> {
    let declarations = source
        .source_files
        .iter()
        .flat_map(|file| file.public_declarations.iter())
        .map(|declaration| (declaration.declaration_unit_id.as_str(), declaration))
        .collect::<BTreeMap<_, _>>();
    let members = bindings
        .iter()
        .filter(|binding| {
            !binding.externally_reachable
                && matches!(
                    binding.binding,
                    HistoricalV2SemanticPublicBindingKind::Definition
                        | HistoricalV2SemanticPublicBindingKind::Reference
                )
                && binding.owner_symbol_id.is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let owners = bindings
        .iter()
        .filter(|binding| {
            binding.indexer == IntentionalBoundaryIndexerKind::Rust
                && binding.externally_reachable
                && binding.owner_symbol_id.is_none()
                && binding.binding != HistoricalV2SemanticPublicBindingKind::OwnerExpansion
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut expansions = Vec::new();
    for member in members {
        let declaration = declarations
            .get(member.origin_declaration_unit_id.as_str())
            .copied()
            .ok_or_else(|| {
                "historical-v2 Rust owner member has no source declaration".to_string()
            })?;
        let source_owner = declaration
            .owner
            .as_deref()
            .ok_or_else(|| "historical-v2 Rust owner member has no source owner".to_string())?;
        for owner in owners.iter().filter(|owner| {
            owner.indexer == member.indexer
                && Some(owner.symbol_id.as_str()) == member.owner_symbol_id.as_deref()
        }) {
            let surface_unit_id = super::super::history_v2_source_census::historical_public_owner_member_surface_unit_id(
                &owner.surface_unit_id,
                source_owner,
                &declaration.name,
                declaration.namespace,
                declaration.kind,
            )?;
            let declaration_unit_id = owner_expansion_declaration_unit_id(
                &surface_unit_id,
                &member.origin_declaration_unit_id,
                &member.symbol_id,
                &owner.declaration_unit_id,
            )?;
            let mut expansion = member.clone();
            expansion.surface_unit_id = surface_unit_id;
            expansion.declaration_unit_id = declaration_unit_id;
            expansion.exposing_owner_declaration_unit_id = Some(owner.declaration_unit_id.clone());
            expansion.package_exposure_id = owner.package_exposure_id.clone();
            expansion.binding = HistoricalV2SemanticPublicBindingKind::OwnerExpansion;
            expansion.externally_reachable = true;
            expansion.reexport_path.clear();
            expansions.push(expansion);
        }
    }
    for expansion in &expansions {
        let symbol = index
            .symbols
            .get(&crate::semantic_index::SemanticSymbolId(
                expansion.symbol_id.clone(),
            ))
            .ok_or_else(|| {
                "historical-v2 Rust owner surface points to a missing compiler symbol".to_string()
            })?;
        retain_symbol(
            symbols,
            IntentionalBoundaryIndexerKind::Rust,
            symbol,
            true,
            false,
            false,
        )?;
    }
    bindings.extend(expansions);
    Ok(())
}

struct CompilerNodePublicRoot<'a> {
    exposure: &'a HistoricalV2NodePackageExposure,
    symbol: &'a SemanticSymbol,
    definition: &'a SemanticLocation,
}

fn compiler_node_public_roots<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    index: &'a SemanticIndex,
) -> Result<Vec<CompilerNodePublicRoot<'a>>, String> {
    if source.node_package_surfaces.revision != source.revision
        || source.node_package_surfaces.inventory_sha256 != source.inventory_sha256
    {
        return Err("historical-v2 Node package surface identity changed".to_string());
    }
    let source_files = source
        .source_files
        .iter()
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut roots = Vec::new();
    for exposure in &source.node_package_surfaces.exposures {
        if exposure.target_status != HistoricalV2NodePackageTargetStatus::TrackedRegularFile {
            return Err(format!(
                "historical-v2 Node package exposure has no tracked compiler root: {}",
                exposure.exposure_id
            ));
        }
        let file = source_files
            .get(exposure.target_repository_path.as_str())
            .copied()
            .ok_or_else(|| {
                format!(
                    "historical-v2 Node package target is absent from source census: {}",
                    exposure.target_repository_path
                )
            })?;
        if !matches!(file.language.as_str(), "typescript" | "javascript")
            || file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required
            || exposure.target_object_id.as_deref() != Some(file.object_id.as_str())
        {
            return Err(format!(
                "historical-v2 Node package target is not required compiler source: {}",
                exposure.target_repository_path
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
                    .filter(|definition| definition.document.0 == exposure.target_repository_path)
                    .map(move |definition| (symbol, definition))
            })
            .collect::<Vec<_>>();
        let [(symbol, definition)] = candidates.as_slice() else {
            return Err(format!(
                "historical-v2 compiler resolved Node package exposure {} to {} root module definitions",
                exposure.exposure_id,
                candidates.len()
            ));
        };
        if !index.documents.contains_key(&definition.document) {
            return Err(format!(
                "historical-v2 compiler omitted Node package root document {}",
                exposure.target_repository_path
            ));
        }
        roots.push(CompilerNodePublicRoot {
            exposure,
            symbol,
            definition,
        });
    }
    Ok(roots)
}

fn expand_node_package_slot(
    exposure: &HistoricalV2NodePackageExposure,
    target: ResolvedPublicSlot,
) -> Result<ResolvedPublicSlot, String> {
    let surface_unit_id = historical_node_package_public_surface_unit_id(
        &exposure.surface_slot_id,
        &target.name,
        target.owner.as_deref(),
        target.namespace,
        target.kind,
    )?;
    let declaration_unit_id = node_package_expansion_declaration_unit_id(
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
    Ok(ResolvedPublicSlot {
        name: target.name,
        owner: target.owner,
        namespace: target.namespace,
        kind: target.kind,
        binding,
    })
}

pub(super) fn historical_node_package_public_surface_unit_id(
    surface_slot_id: &str,
    name: &str,
    owner: Option<&str>,
    namespace: HistoricalV2SourcePublicNamespace,
    kind: HistoricalV2SourcePublicSymbolKind,
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-node-package-public-surface-v1",
        surface_slot_id,
        name,
        owner,
        namespace,
        kind,
    ))
    .map(|hash| format!("h2nps-v1:{hash}"))
}

pub(super) fn node_package_expansion_declaration_unit_id(
    surface_unit_id: &str,
    exposure_id: &str,
    origin_declaration_unit_id: &str,
    symbol_id: &str,
    reexport_path: &[String],
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-node-package-expansion-v1",
        surface_unit_id,
        exposure_id,
        origin_declaration_unit_id,
        symbol_id,
        reexport_path,
    ))
    .map(|hash| format!("h2nex-v1:{hash}"))
}

pub(super) fn owner_expansion_declaration_unit_id(
    surface_unit_id: &str,
    origin_declaration_unit_id: &str,
    symbol_id: &str,
    exposing_owner_declaration_unit_id: &str,
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-public-owner-expansion-v1",
        surface_unit_id,
        origin_declaration_unit_id,
        symbol_id,
        exposing_owner_declaration_unit_id,
    ))
    .map(|hash| format!("h2oe-v1:{hash}"))
}

pub(super) fn rust_public_library_target_roots(
    source: &HistoricalV2SourceSnapshotCensus,
) -> Result<BTreeSet<String>, String> {
    let mut roots = BTreeSet::new();
    for target in &source.cargo_project_model.targets {
        if target.provider != IntentionalBoundaryProjectModelProvider::CargoMetadata {
            return Err("historical-v2 Cargo project model mixed providers".to_string());
        }
        let IntentionalBoundaryProjectModelTargetStatus::Boundary {
            declaration_kind: IntentionalBoundaryManifestDeclarationKind::PublishedModule,
            target,
        } = &target.target_status
        else {
            continue;
        };
        let IntentionalBoundaryManifestTarget::RepositoryPath { repository_path } = target else {
            return Err(
                "historical-v2 Cargo library target has a non-file public root".to_string(),
            );
        };
        let source_file = source
            .source_files
            .iter()
            .find(|file| file.repository_path == *repository_path)
            .ok_or_else(|| {
                format!(
                    "historical-v2 Cargo library root is absent from source census: {repository_path}"
                )
            })?;
        if source_file.language != "rust"
            || source_file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required
        {
            return Err(format!(
                "historical-v2 Cargo library root is not required Rust source: {repository_path}"
            ));
        }
        if !roots.insert(repository_path.clone()) {
            return Err(format!(
                "historical-v2 Cargo project model repeats a library root: {repository_path}"
            ));
        }
    }
    Ok(roots)
}

fn compiler_rust_public_roots<'a>(
    index: &'a SemanticIndex,
    library_roots: &BTreeSet<String>,
) -> Result<BTreeMap<String, (&'a SemanticSymbol, &'a SemanticLocation)>, String> {
    let mut roots = BTreeMap::new();
    for symbol in index.symbols.values() {
        if symbol.origin != SemanticSymbolOrigin::Repository
            || !symbol.ambiguity_notes.is_empty()
            || symbol.kind.category != SemanticSymbolCategory::Module
        {
            continue;
        }
        let parsed = scip::symbol::parse_symbol(&symbol.provider_identity).map_err(|error| {
            format!(
                "historical-v2 Rust module has invalid compiler identity {:?}: {error:?}",
                symbol.provider_identity
            )
        })?;
        let [descriptor] = parsed.descriptors.as_slice() else {
            continue;
        };
        if parsed.scheme != "rust-analyzer"
            || descriptor.name != "crate"
            || descriptor.suffix.enum_value().ok() != Some(Suffix::Namespace)
        {
            continue;
        }
        let matching_definitions = symbol
            .definitions
            .iter()
            .filter(|definition| library_roots.contains(&definition.document.0))
            .collect::<Vec<_>>();
        if matching_definitions.len() > 1 {
            return Err(format!(
                "historical-v2 Rust crate root {} has {} library definitions",
                symbol.id.0,
                matching_definitions.len()
            ));
        }
        let Some(definition) = matching_definitions.first().copied() else {
            continue;
        };
        if !index.documents.contains_key(&definition.document) {
            return Err(format!(
                "historical-v2 Rust crate root {} has no compiler document",
                symbol.id.0
            ));
        }
        if roots
            .insert(definition.document.0.clone(), (symbol, definition))
            .is_some()
        {
            return Err(format!(
                "historical-v2 Rust compiler emitted multiple crate roots for {}",
                definition.document.0
            ));
        }
    }
    if roots.keys().collect::<BTreeSet<_>>() != library_roots.iter().collect::<BTreeSet<_>>() {
        let missing = library_roots
            .iter()
            .filter(|path| !roots.contains_key(*path))
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "historical-v2 Rust compiler omitted exact library crate root(s): {}",
            missing.join(", ")
        ));
    }
    Ok(roots)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPublicSlot {
    name: String,
    owner: Option<String>,
    namespace: HistoricalV2SourcePublicNamespace,
    kind: HistoricalV2SourcePublicSymbolKind,
    binding: HistoricalV2SemanticPublicBinding,
}

#[allow(clippy::too_many_arguments)]
fn resolve_file_public_slots(
    file: &HistoricalV2SourceFile,
    source_files: &BTreeMap<&str, &HistoricalV2SourceFile>,
    records: &BTreeMap<String, &FileRecord>,
    direct_bindings: &BTreeMap<String, HistoricalV2SemanticPublicBinding>,
    kind: SemanticIndexerKind,
    index: &SemanticIndex,
    symbols: &mut BTreeMap<(IntentionalBoundaryIndexerKind, String), HistoricalV2SemanticSymbol>,
    reexport_hops: &mut BTreeMap<String, HistoricalV2SemanticPublicReexportHop>,
    cache: &mut BTreeMap<String, Vec<ResolvedPublicSlot>>,
    stack: &mut Vec<String>,
) -> Result<Vec<ResolvedPublicSlot>, String> {
    if let Some(cached) = cache.get(&file.repository_path) {
        return Ok(cached.clone());
    }
    if stack.contains(&file.repository_path) {
        stack.push(file.repository_path.clone());
        return Err(format!(
            "historical-v2 compiler found a cyclic public re-export path: {}",
            stack.join(" -> ")
        ));
    }
    stack.push(file.repository_path.clone());
    if file.public_surface_coverage != HistoricalV2PublicSurfaceCoverage::Complete {
        return Err(format!(
            "historical-v2 public-surface collector is incomplete for {}",
            file.repository_path
        ));
    }
    let document = index
        .documents
        .get(&RepositoryPath(file.repository_path.clone()))
        .ok_or_else(|| {
            format!(
                "historical-v2 compiler omitted a public-surface document: {}",
                file.repository_path
            )
        })?;
    let record = records.get(&file.repository_path).ok_or_else(|| {
        format!(
            "historical-v2 public-surface source is missing from parser records: {}",
            file.repository_path
        )
    })?;
    let mut slots = file
        .public_declarations
        .iter()
        .map(|declaration| {
            let binding = direct_bindings
                .get(&declaration.declaration_unit_id)
                .ok_or_else(|| {
                    format!(
                        "historical-v2 compiler omitted direct public binding {}",
                        declaration.declaration_unit_id
                    )
                })?;
            Ok(ResolvedPublicSlot {
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
        let (hop, module_symbol) =
            resolve_public_reexport(file, reexport, &record.source, document, kind, index)?;
        retain_symbol(
            symbols,
            indexer_kind(kind),
            module_symbol,
            false,
            false,
            true,
        )?;
        if let Some(existing) = reexport_hops.insert(reexport.reexport_unit_id.clone(), hop.clone())
            && existing != hop
        {
            return Err("historical-v2 compiler changed a repeated re-export hop".to_string());
        }
        let target = source_files
            .get(hop.target_repository_path.as_str())
            .copied()
            .ok_or_else(|| {
                format!(
                    "historical-v2 public re-export target is not an enumerable repository source: {}",
                    hop.target_repository_path
                )
            })?;
        if indexer_for_language(&target.language)? != kind {
            return Err("historical-v2 public re-export crossed compiler indexers".to_string());
        }
        let target_slots = resolve_file_public_slots(
            target,
            source_files,
            records,
            direct_bindings,
            kind,
            index,
            symbols,
            reexport_hops,
            cache,
            stack,
        )?;
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
                    let expanded = expand_reexport_slot(file, reexport, &hop, target_slot, None)?;
                    if direct_surfaces.contains(&expanded.binding.surface_unit_id) {
                        if file.language == "python"
                            && direct_surface_last_anchors
                                .get(&expanded.binding.surface_unit_id)
                                .is_some_and(|start| *start < reexport.directive.start)
                        {
                            return Err(format!(
                                "historical-v2 Python wildcard overwrites an earlier direct public binding in {}",
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
                            "historical-v2 compiler found an ambiguous wildcard export in {}",
                            file.repository_path
                        ));
                    }
                    slots.push(expanded);
                }
                if let Some(name) = reexport.name.as_deref()
                    && !matched
                {
                    return Err(format!(
                        "historical-v2 Python __all__ name {name:?} is absent from wildcard target {}",
                        hop.target_repository_path
                    ));
                }
            }
            HistoricalV2SourcePublicReexportKind::Namespace => {
                let name = reexport.name.as_deref().ok_or_else(|| {
                    "historical-v2 namespace re-export has no exposed name".to_string()
                })?;
                if target_slots.is_empty() {
                    return Err(format!(
                        "historical-v2 namespace re-export target has no enumerable bindings: {}",
                        hop.target_repository_path
                    ));
                }
                for target_slot in target_slots {
                    let expanded =
                        expand_reexport_slot(file, reexport, &hop, target_slot, Some(name))?;
                    if direct_surfaces.contains(&expanded.binding.surface_unit_id) {
                        return Err(format!(
                            "historical-v2 namespace re-export collides with a direct export in {}",
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

fn expand_reexport_slot(
    file: &HistoricalV2SourceFile,
    reexport: &HistoricalV2SourcePublicReexport,
    hop: &HistoricalV2SemanticPublicReexportHop,
    target: ResolvedPublicSlot,
    namespace_name: Option<&str>,
) -> Result<ResolvedPublicSlot, String> {
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
    let declaration_unit_id = reexport_expansion_declaration_unit_id(
        &surface_unit_id,
        &file.repository_path,
        &target.binding.origin_declaration_unit_id,
        &target.binding.symbol_id,
        &reexport_path,
    )?;
    Ok(ResolvedPublicSlot {
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

pub(super) fn reexport_expansion_declaration_unit_id(
    surface_unit_id: &str,
    repository_path: &str,
    origin_declaration_unit_id: &str,
    symbol_id: &str,
    reexport_path: &[String],
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-public-reexport-expansion-v1",
        surface_unit_id,
        repository_path,
        origin_declaration_unit_id,
        symbol_id,
        reexport_path,
    ))
    .map(|hash| format!("h2x-v1:{hash}"))
}

fn resolve_public_reexport<'a>(
    file: &HistoricalV2SourceFile,
    reexport: &HistoricalV2SourcePublicReexport,
    source: &str,
    document: &crate::semantic_index::SemanticDocument,
    kind: SemanticIndexerKind,
    index: &'a SemanticIndex,
) -> Result<(HistoricalV2SemanticPublicReexportHop, &'a SemanticSymbol), String> {
    let location = reexport_location(file, reexport, source, document.position_encoding)?;
    let occurrences = document
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.range == location.range)
        .collect::<Vec<_>>();
    let [occurrence] = occurrences.as_slice() else {
        return Err(format!(
            "historical-v2 compiler emitted {} occurrence(s) at re-export {}",
            occurrences.len(),
            reexport.reexport_unit_id
        ));
    };
    let symbol_id = occurrence.symbol.as_ref().ok_or_else(|| {
        format!(
            "historical-v2 compiler left re-export {} unresolved",
            reexport.reexport_unit_id
        )
    })?;
    let symbol = index.symbols.get(symbol_id).ok_or_else(|| {
        format!(
            "historical-v2 re-export points to missing compiler module {}",
            symbol_id.0
        )
    })?;
    if symbol.origin != SemanticSymbolOrigin::Repository
        || !symbol.ambiguity_notes.is_empty()
        || !matches!(
            symbol.kind.category,
            SemanticSymbolCategory::Module
                | SemanticSymbolCategory::Namespace
                | SemanticSymbolCategory::Package
        )
    {
        return Err(format!(
            "historical-v2 re-export {} in {} from {:?} has no unambiguous repository module (origin={:?}, category={:?}, ambiguity={:?})",
            reexport.reexport_unit_id,
            file.repository_path,
            reexport.source_module,
            symbol.origin,
            symbol.kind.category,
            symbol.ambiguity_notes,
        ));
    }
    let targets = symbol
        .definitions
        .iter()
        .map(|definition| definition.document.0.clone())
        .collect::<BTreeSet<_>>();
    if targets.len() != 1 {
        return Err(format!(
            "historical-v2 compiler resolved re-export {} to {} module document(s)",
            reexport.reexport_unit_id,
            targets.len()
        ));
    }
    let target_repository_path = targets.iter().next().unwrap();
    if !index
        .documents
        .contains_key(&RepositoryPath(target_repository_path.clone()))
    {
        return Err(format!(
            "historical-v2 compiler omitted re-export target document {}",
            target_repository_path
        ));
    }
    Ok((
        HistoricalV2SemanticPublicReexportHop {
            indexer: indexer_kind(kind),
            reexport_unit_id: reexport.reexport_unit_id.clone(),
            repository_path: file.repository_path.clone(),
            target_repository_path: target_repository_path.clone(),
            module_symbol_id: symbol.id.0.clone(),
            position_encoding: document.position_encoding,
            compiler_anchor: flatten_location(&location),
        },
        symbol,
    ))
}

fn reexport_location(
    file: &HistoricalV2SourceFile,
    reexport: &HistoricalV2SourcePublicReexport,
    source: &str,
    encoding: SemanticPositionEncoding,
) -> Result<SemanticLocation, String> {
    let range = reexport.identifier;
    let valid_range = range.start < range.end
        && range.end <= source.len()
        && source.is_char_boundary(range.start)
        && source.is_char_boundary(range.end);
    let valid_text = valid_range
        && range.start >= reexport.directive.start
        && range.end <= reexport.directive.end
        && match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                let text = &source[range.start..range.end];
                if file.language == "python" {
                    text == reexport.source_module
                } else {
                    text.len() >= 2
                        && matches!(
                            (text.as_bytes()[0], text.as_bytes()[text.len() - 1]),
                            (b'\'', b'\'') | (b'"', b'"')
                        )
                        && text[1..text.len() - 1] == reexport.source_module
                }
            }
            HistoricalV2SourcePublicReexportKind::Namespace => {
                let exposed = reexport.exposed_identifier;
                let valid_exposed = exposed.is_some_and(|exposed| {
                    exposed.start < exposed.end
                        && exposed.start >= reexport.directive.start
                        && exposed.end <= reexport.directive.end
                        && exposed.end <= source.len()
                        && reexport
                            .name
                            .as_deref()
                            .is_some_and(|name| &source[exposed.start..exposed.end] == name)
                });
                if file.language == "python" {
                    valid_exposed
                        && valid_python_namespace_anchor(
                            &source[range.start..range.end],
                            &reexport.source_module,
                            reexport.name.as_deref().unwrap_or_default(),
                        )
                } else {
                    valid_exposed
                        && reexport
                            .name
                            .as_deref()
                            .is_some_and(|name| &source[range.start..range.end] == name)
                }
            }
        };
    if !valid_text {
        return Err(format!(
            "historical-v2 public re-export range changed: {}::{}",
            file.repository_path, reexport.reexport_unit_id
        ));
    }
    Ok(SemanticLocation {
        document: RepositoryPath(file.repository_path.clone()),
        range: SemanticSourceRange {
            start: semantic_position_at_byte(source, range.start, encoding)?,
            end: semantic_position_at_byte(source, range.end, encoding)?,
        },
    })
}

fn symbol_at_exact_definition<'a>(
    index: &'a SemanticIndex,
    declaration: &HistoricalV2SourcePublicDeclaration,
    location: &SemanticLocation,
) -> Result<&'a SemanticSymbol, String> {
    let candidates = index
        .symbols
        .values()
        .filter(|symbol| {
            valid_public_symbol(declaration, symbol) && symbol.definitions.contains(location)
        })
        .collect::<Vec<_>>();
    let [symbol] = candidates.as_slice() else {
        return Err(format!(
            "historical-v2 compiler resolved {} public symbol(s) at the exact definition of {}::{}",
            candidates.len(),
            location.document.0,
            declaration.name
        ));
    };
    Ok(*symbol)
}

fn symbol_at_exact_reference<'a>(
    index: &'a SemanticIndex,
    document: &crate::semantic_index::SemanticDocument,
    declaration: &HistoricalV2SourcePublicDeclaration,
    location: &SemanticLocation,
) -> Result<&'a SemanticSymbol, String> {
    let occurrences = document
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.range == location.range)
        .collect::<Vec<_>>();
    let [occurrence] = occurrences.as_slice() else {
        return Err(format!(
            "historical-v2 compiler emitted {} occurrence(s) at the exact public reference of {}::{}",
            occurrences.len(),
            location.document.0,
            declaration.name
        ));
    };
    let symbol_id = occurrence.symbol.as_ref().ok_or_else(|| {
        format!(
            "historical-v2 compiler left the exact public reference unresolved at {}::{}",
            location.document.0, declaration.name
        )
    })?;
    let symbol = index.symbols.get(symbol_id).ok_or_else(|| {
        format!(
            "historical-v2 public reference points to missing compiler symbol {}",
            symbol_id.0
        )
    })?;
    if !valid_public_symbol(declaration, symbol) {
        return Err(format!(
            "historical-v2 public reference has an incompatible compiler symbol at {}::{}",
            location.document.0, declaration.name
        ));
    }
    Ok(symbol)
}

fn symbol_at_exact_owner_reference<'a>(
    index: &'a SemanticIndex,
    document: &crate::semantic_index::SemanticDocument,
    declaration: &HistoricalV2SourcePublicDeclaration,
    location: &SemanticLocation,
) -> Result<&'a SemanticSymbol, String> {
    let occurrences = document
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.range == location.range)
        .collect::<Vec<_>>();
    if occurrences.is_empty() {
        return Err(format!(
            "historical-v2 compiler omitted the exact owner occurrence of {}::{}",
            location.document.0, declaration.name
        ));
    }
    let symbol_ids = occurrences
        .iter()
        .map(|occurrence| {
            occurrence.symbol.as_ref().ok_or_else(|| {
                format!(
                    "historical-v2 compiler left the exact owner unresolved at {}::{}",
                    location.document.0, declaration.name
                )
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if symbol_ids.len() != 1 {
        return Err(format!(
            "historical-v2 compiler emitted {} distinct symbols at the exact owner of {}::{}",
            symbol_ids.len(),
            location.document.0,
            declaration.name
        ));
    }
    let symbol_id = symbol_ids.iter().next().copied().unwrap();
    let symbol = index.symbols.get(symbol_id).ok_or_else(|| {
        format!(
            "historical-v2 public owner points to missing compiler symbol {}",
            symbol_id.0
        )
    })?;
    if symbol.origin != SemanticSymbolOrigin::Repository
        || !symbol.ambiguity_notes.is_empty()
        || !matches!(
            symbol.kind.category,
            SemanticSymbolCategory::Type | SemanticSymbolCategory::TraitOrInterface
        )
    {
        return Err(format!(
            "historical-v2 public owner has an incompatible compiler symbol at {}::{}",
            location.document.0, declaration.name
        ));
    }
    Ok(symbol)
}

fn valid_public_symbol(
    declaration: &HistoricalV2SourcePublicDeclaration,
    symbol: &SemanticSymbol,
) -> bool {
    symbol.origin == SemanticSymbolOrigin::Repository
        && symbol.ambiguity_notes.is_empty()
        && compatible_public_symbol_kind(declaration.kind, symbol.kind.category)
}

fn declaration_location(
    file: &HistoricalV2SourceFile,
    declaration: &HistoricalV2SourcePublicDeclaration,
    source: &str,
    encoding: SemanticPositionEncoding,
) -> Result<SemanticLocation, String> {
    let range = declaration.identifier;
    if range.start >= range.end
        || range.end > source.len()
        || declaration.exposed_identifier.start >= declaration.exposed_identifier.end
        || declaration.exposed_identifier.end > source.len()
        || !source.is_char_boundary(range.start)
        || !source.is_char_boundary(range.end)
        || !source.is_char_boundary(declaration.exposed_identifier.start)
        || !source.is_char_boundary(declaration.exposed_identifier.end)
        || source[declaration.exposed_identifier.start..declaration.exposed_identifier.end]
            != declaration.name
        || !match declaration.binding {
            HistoricalV2SourcePublicBindingKind::Definition => {
                &source[range.start..range.end] == declaration.target_name.as_str()
            }
            HistoricalV2SourcePublicBindingKind::Reference if file.language == "python" => {
                valid_python_alias_anchor(
                    &source[range.start..range.end],
                    &declaration.target_name,
                    &declaration.name,
                )
            }
            HistoricalV2SourcePublicBindingKind::Reference => {
                &source[range.start..range.end] == declaration.name.as_str()
            }
        }
    {
        return Err(format!(
            "historical-v2 public declaration range changed: {}::{}",
            file.repository_path, declaration.name
        ));
    }
    Ok(SemanticLocation {
        document: RepositoryPath(file.repository_path.clone()),
        range: SemanticSourceRange {
            start: semantic_position_at_byte(source, range.start, encoding)?,
            end: semantic_position_at_byte(source, range.end, encoding)?,
        },
    })
}

fn declaration_owner_location(
    file: &HistoricalV2SourceFile,
    declaration: &HistoricalV2SourcePublicDeclaration,
    source: &str,
    encoding: SemanticPositionEncoding,
) -> Result<Option<SemanticLocation>, String> {
    let Some(range) = declaration.owner_identifier else {
        if declaration.owner_identifier_positions.is_some() {
            return Err(format!(
                "historical-v2 public owner positions have no byte range: {}::{}",
                file.repository_path, declaration.name
            ));
        }
        return Ok(None);
    };
    let owner_name = declaration
        .owner
        .as_deref()
        .and_then(|owner| owner.rsplit("::").next())
        .ok_or_else(|| {
            format!(
                "historical-v2 public owner anchor has no owner: {}::{}",
                file.repository_path, declaration.name
            )
        })?;
    if declaration.owner_identifier_positions.is_none()
        || range.start >= range.end
        || range.end > source.len()
        || !source.is_char_boundary(range.start)
        || !source.is_char_boundary(range.end)
        || &source[range.start..range.end] != owner_name
    {
        return Err(format!(
            "historical-v2 public owner range changed: {}::{}",
            file.repository_path, declaration.name
        ));
    }
    Ok(Some(SemanticLocation {
        document: RepositoryPath(file.repository_path.clone()),
        range: SemanticSourceRange {
            start: semantic_position_at_byte(source, range.start, encoding)?,
            end: semantic_position_at_byte(source, range.end, encoding)?,
        },
    }))
}

fn valid_python_namespace_anchor(anchor: &str, source_module: &str, exposed: &str) -> bool {
    if !source_module.starts_with('.') {
        return anchor == source_module;
    }
    let target = source_module.trim_start_matches('.');
    !target.is_empty() && valid_python_alias_anchor(anchor, target, exposed)
}

fn valid_python_alias_anchor(anchor: &str, target: &str, exposed: &str) -> bool {
    let Ok(tokens) = rustpython_parser::lexer::lex(anchor, rustpython_parser::Mode::Module)
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    let mut before_as = String::new();
    let mut alias = None;
    let mut saw_as = false;
    for (token, _) in tokens {
        match token {
            rustpython_parser::Tok::Name { name } if saw_as => {
                if alias.replace(name).is_some() {
                    return false;
                }
            }
            rustpython_parser::Tok::Name { name } => before_as.push_str(&name),
            rustpython_parser::Tok::Dot if !saw_as => before_as.push('.'),
            rustpython_parser::Tok::As if !saw_as => saw_as = true,
            rustpython_parser::Tok::Newline | rustpython_parser::Tok::EndOfFile => {}
            _ => return false,
        }
    }
    before_as == target
        && match alias {
            Some(alias) => saw_as && alias == exposed,
            None => !saw_as && target == exposed,
        }
}

pub(super) fn semantic_position_at_byte(
    source: &str,
    offset: usize,
    encoding: SemanticPositionEncoding,
) -> Result<SemanticPosition, String> {
    if offset > source.len() || !source.is_char_boundary(offset) {
        return Err("historical-v2 public declaration is not on a UTF-8 boundary".to_string());
    }
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let line_prefix = &source[line_start..offset];
    let character = match encoding {
        SemanticPositionEncoding::Utf8 => line_prefix.len(),
        SemanticPositionEncoding::Utf16 => line_prefix.encode_utf16().count(),
        SemanticPositionEncoding::Utf32 => line_prefix.chars().count(),
    };
    Ok(SemanticPosition {
        line: u32::try_from(line)
            .map_err(|_| "historical-v2 public declaration line exceeds u32".to_string())?,
        character: u32::try_from(character)
            .map_err(|_| "historical-v2 public declaration column exceeds u32".to_string())?,
    })
}

fn compatible_public_symbol_kind(
    declaration: HistoricalV2SourcePublicSymbolKind,
    compiler: SemanticSymbolCategory,
) -> bool {
    matches!(
        (declaration, compiler),
        (
            HistoricalV2SourcePublicSymbolKind::CompilerDefined,
            SemanticSymbolCategory::Callable
                | SemanticSymbolCategory::Constructor
                | SemanticSymbolCategory::Method
                | SemanticSymbolCategory::Type
                | SemanticSymbolCategory::TraitOrInterface
                | SemanticSymbolCategory::Module
                | SemanticSymbolCategory::Namespace
                | SemanticSymbolCategory::Package
                | SemanticSymbolCategory::FieldOrProperty
                | SemanticSymbolCategory::Variable
                | SemanticSymbolCategory::Constant
                | SemanticSymbolCategory::Macro
        ) | (
            HistoricalV2SourcePublicSymbolKind::Callable,
            SemanticSymbolCategory::Callable
        ) | (
            HistoricalV2SourcePublicSymbolKind::Module,
            SemanticSymbolCategory::Module
                | SemanticSymbolCategory::Namespace
                | SemanticSymbolCategory::Package
        ) | (
            HistoricalV2SourcePublicSymbolKind::Method,
            SemanticSymbolCategory::Method
        ) | (
            HistoricalV2SourcePublicSymbolKind::Type,
            SemanticSymbolCategory::Type | SemanticSymbolCategory::TraitOrInterface
        ) | (
            HistoricalV2SourcePublicSymbolKind::Field,
            SemanticSymbolCategory::FieldOrProperty
        ) | (
            HistoricalV2SourcePublicSymbolKind::Variable,
            SemanticSymbolCategory::Variable
        ) | (
            HistoricalV2SourcePublicSymbolKind::Constant,
            SemanticSymbolCategory::Constant
        )
    )
}
