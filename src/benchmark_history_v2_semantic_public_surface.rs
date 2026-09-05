use super::super::{
    HistoricalV2PublicSurfaceCoverage, HistoricalV2SemanticPublicBinding,
    HistoricalV2SemanticPublicBindingKind, HistoricalV2SemanticPublicReexportHop,
    HistoricalV2SemanticSymbol, HistoricalV2SourceFile, HistoricalV2SourcePublicBindingKind,
    HistoricalV2SourcePublicDeclaration, HistoricalV2SourcePublicNamespace,
    HistoricalV2SourcePublicReexport, HistoricalV2SourcePublicReexportKind,
    HistoricalV2SourcePublicSymbolKind, HistoricalV2SourceSemanticCoverage,
    HistoricalV2SourceSnapshotCensus, IntentionalBoundaryIndexerKind,
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
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
pub(super) fn bind_public_surface(
    root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    indexed_files: &[FileRecord],
    kind: SemanticIndexerKind,
    index: &SemanticIndex,
    symbols: &mut BTreeMap<(IntentionalBoundaryIndexerKind, String), HistoricalV2SemanticSymbol>,
    bindings: &mut Vec<HistoricalV2SemanticPublicBinding>,
    reexport_hops: &mut BTreeMap<String, HistoricalV2SemanticPublicReexportHop>,
    public_surface_document_paths: &mut BTreeSet<String>,
) -> Result<(), String> {
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
            retain_symbol(symbols, indexer_kind(kind), symbol, true, false)?;
            let public_binding = HistoricalV2SemanticPublicBinding {
                indexer: indexer_kind(kind),
                surface_unit_id: declaration.surface_unit_id.clone(),
                declaration_unit_id: declaration.declaration_unit_id.clone(),
                origin_declaration_unit_id: declaration.declaration_unit_id.clone(),
                reexport_path: Vec::new(),
                repository_path: file.repository_path.clone(),
                symbol_id: symbol.id.0.clone(),
                binding,
                position_encoding: document.position_encoding,
                compiler_anchor: flatten_location(&location),
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
        for slot in slots
            .into_iter()
            .filter(|slot| !slot.binding.reexport_path.is_empty())
        {
            bindings.push(slot.binding);
        }
    }
    Ok(())
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
    let mut wildcard_symbols = BTreeMap::<String, String>::new();

    for reexport in &file.public_reexports {
        let (hop, module_symbol) =
            resolve_public_reexport(file, reexport, &record.source, document, kind, index)?;
        retain_symbol(symbols, indexer_kind(kind), module_symbol, false, true)?;
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
                for target_slot in target_slots
                    .into_iter()
                    .filter(|slot| slot.name != "default")
                {
                    let expanded = expand_reexport_slot(file, reexport, &hop, target_slot, None)?;
                    if direct_surfaces.contains(&expanded.binding.surface_unit_id) {
                        continue;
                    }
                    if let Some(existing) = wildcard_symbols.insert(
                        expanded.binding.surface_unit_id.clone(),
                        expanded.binding.symbol_id.clone(),
                    ) && existing != expanded.binding.symbol_id
                    {
                        return Err(format!(
                            "historical-v2 compiler found an ambiguous wildcard export in {}",
                            file.repository_path
                        ));
                    }
                    slots.push(expanded);
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
            binding: HistoricalV2SemanticPublicBindingKind::ReexportExpansion,
            position_encoding: hop.position_encoding,
            compiler_anchor: hop.compiler_anchor.clone(),
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
            "historical-v2 re-export {} has no unambiguous repository module",
            reexport.reexport_unit_id
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
        && match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                let text = &source[range.start..range.end];
                text.len() >= 2
                    && matches!(
                        (text.as_bytes()[0], text.as_bytes()[text.len() - 1]),
                        (b'\'', b'\'') | (b'"', b'"')
                    )
                    && text[1..text.len() - 1] == reexport.source_module
            }
            HistoricalV2SourcePublicReexportKind::Namespace => reexport
                .name
                .as_deref()
                .is_some_and(|name| &source[range.start..range.end] == name),
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
        || &source[range.start..range.end]
            != match declaration.binding {
                HistoricalV2SourcePublicBindingKind::Definition => declaration.target_name.as_str(),
                HistoricalV2SourcePublicBindingKind::Reference => declaration.name.as_str(),
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
