use super::super::{
    HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2PublicSurfaceCoverage, HistoricalV2SemanticCensus,
    HistoricalV2SemanticMethodStatus, HistoricalV2SemanticPublicBinding,
    HistoricalV2SemanticPublicBindingKind, HistoricalV2SemanticPublicReexportHop,
    HistoricalV2SemanticSnapshotCensus, HistoricalV2SemanticSymbol, HistoricalV2SourceCensus,
    HistoricalV2SourceFile, HistoricalV2SourcePublicBindingKind,
    HistoricalV2SourcePublicDeclaration, HistoricalV2SourcePublicNamespace,
    HistoricalV2SourcePublicReexport, HistoricalV2SourcePublicReexportKind,
    HistoricalV2SourcePublicSymbolKind, HistoricalV2SourceSemanticCoverage,
    HistoricalV2SourceSnapshotCensus, IntentionalBoundaryIndexerKind,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticSymbolCategory, validate_historical_v2_source_census,
};
use super::{
    SEMANTIC_CENSUS_CONTRACT, indexer_for_language, indexer_kind, semantic_census_sha256,
    semantic_scope, semantic_snapshot_sha256,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use std::collections::{BTreeMap, BTreeSet};

pub fn validate_historical_v2_semantic_census_commitment(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    census: &HistoricalV2SemanticCensus,
) -> Result<(), String> {
    validate_historical_v2_source_census(materialization, roots, source_census)?;
    let scope = semantic_scope(materialization, roots, source_census)?;
    let changed_indexers = scope
        .changed_indexers
        .iter()
        .copied()
        .map(indexer_kind)
        .collect::<Vec<_>>();
    if census.schema_version != HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION
        || census.semantic_census_contract != SEMANTIC_CENSUS_CONTRACT
        || census.canonical_repository != materialization.canonical_repository
        || census.materialization_sha256 != materialization.materialization_sha256
        || census.source_census_sha256 != source_census.source_census_sha256
        || census.changed_indexers != changed_indexers
        || census.semantic_census_sha256 != semantic_census_sha256(census)?
    {
        return Err("historical-v2 semantic census commitment changed".to_string());
    }
    validate_snapshot(
        &source_census.base,
        &census.base,
        &scope.changed_indexers,
        &scope.base_required_paths,
    )?;
    validate_snapshot(
        &source_census.patched,
        &census.patched,
        &scope.changed_indexers,
        &scope.patched_required_paths,
    )?;
    Ok(())
}

pub(super) fn validate_snapshot(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
) -> Result<(), String> {
    let public_declaration_count = source
        .source_files
        .iter()
        .map(|file| file.public_declarations.len())
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or_else(|| "historical-v2 public declaration count overflowed".to_string())?;
    let public_reexport_count = source
        .source_files
        .iter()
        .map(|file| file.public_reexports.len())
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or_else(|| "historical-v2 public re-export count overflowed".to_string())?;
    if semantic.revision != source.revision
        || semantic.source_snapshot_census_sha256 != source.snapshot_census_sha256
        || semantic.required_document_paths
            != required_document_paths.iter().cloned().collect::<Vec<_>>()
        || !is_sha256(&semantic.semantic_snapshot_sha256)
        || semantic.semantic_snapshot_sha256 != semantic_snapshot_sha256(semantic)?
        || source.public_declaration_count != public_declaration_count
        || source.public_reexport_count != public_reexport_count
    {
        return Err("historical-v2 semantic snapshot identity changed".to_string());
    }

    let expected_indexers = source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
        .map(|file| indexer_for_language(&file.language))
        .collect::<Result<BTreeSet<_>, String>>()?
        .intersection(changed_indexers)
        .copied()
        .map(indexer_kind)
        .collect::<BTreeSet<_>>();
    let actual_indexers = validate_indexers(semantic)?;
    if actual_indexers != expected_indexers {
        return Err("historical-v2 semantic snapshot indexer coverage changed".to_string());
    }

    let all_source_paths = source
        .source_files
        .iter()
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let symbols = validate_symbols(semantic, &actual_indexers, &all_source_paths)?;
    let public_surface_document_paths = validate_public_surface_document_paths(
        source,
        semantic,
        &actual_indexers,
        required_document_paths,
    )?;
    let (reexports, reexport_symbols) = validate_reexport_hops(
        source,
        semantic,
        &actual_indexers,
        &symbols,
        &all_source_paths,
        &public_surface_document_paths,
    )?;
    let public_symbols = validate_public_bindings(
        source,
        semantic,
        &actual_indexers,
        &symbols,
        &reexports,
        &public_surface_document_paths,
    )?;
    let referenced_symbols = validate_methods(
        source,
        semantic,
        &actual_indexers,
        &symbols,
        &all_source_paths,
    )?;
    if semantic.symbols.iter().any(|entry| {
        !public_symbols.contains(&(entry.indexer, entry.symbol.symbol_id.as_str()))
            && !reexport_symbols.contains(&(entry.indexer, entry.symbol.symbol_id.as_str()))
            && !referenced_symbols.contains(&(entry.indexer, entry.symbol.symbol_id.as_str()))
    }) {
        return Err("historical-v2 semantic snapshot contains an unrelated symbol".to_string());
    }
    if semantic.symbols.iter().any(|entry| {
        entry.is_reexport_evidence
            != reexport_symbols.contains(&(entry.indexer, entry.symbol.symbol_id.as_str()))
    }) {
        return Err("historical-v2 re-export evidence classification changed".to_string());
    }
    Ok(())
}

fn validate_indexers(
    semantic: &HistoricalV2SemanticSnapshotCensus,
) -> Result<BTreeSet<IntentionalBoundaryIndexerKind>, String> {
    if semantic
        .indexers
        .windows(2)
        .any(|pair| pair[0].indexer >= pair[1].indexer)
    {
        return Err("historical-v2 semantic indexers are not canonical".to_string());
    }
    let indexers = semantic
        .indexers
        .iter()
        .map(|indexer| indexer.indexer)
        .collect::<BTreeSet<_>>();
    for indexer in &semantic.indexers {
        if indexer.tool_name.trim().is_empty()
            || !is_sha256(&indexer.semantic_facts_sha256)
            || !is_sha256(&indexer.diagnostics_sha256)
        {
            return Err("historical-v2 semantic indexer commitment is invalid".to_string());
        }
    }
    Ok(indexers)
}

type SymbolKey<'a> = (IntentionalBoundaryIndexerKind, &'a str);
type ReexportMap<'a> = BTreeMap<
    &'a str,
    (
        &'a HistoricalV2SourceFile,
        &'a HistoricalV2SourcePublicReexport,
        &'a HistoricalV2SemanticPublicReexportHop,
    ),
>;
type DeclarationMap<'a> = BTreeMap<
    &'a str,
    (
        &'a str,
        IntentionalBoundaryIndexerKind,
        &'a HistoricalV2SourcePublicDeclaration,
    ),
>;

fn validate_public_surface_document_paths<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    required_document_paths: &BTreeSet<String>,
) -> Result<BTreeSet<&'a str>, String> {
    if semantic
        .public_surface_document_paths
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err("historical-v2 public-surface document paths are not canonical".to_string());
    }
    let source_files = source
        .source_files
        .iter()
        .map(|file| (file.repository_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let paths = semantic
        .public_surface_document_paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for path in &paths {
        let file = source_files.get(path).ok_or_else(|| {
            "historical-v2 public-surface census invented a source document".to_string()
        })?;
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        if file.semantic_coverage != HistoricalV2SourceSemanticCoverage::Required
            || file.public_surface_coverage != HistoricalV2PublicSurfaceCoverage::Complete
            || !indexers.contains(&indexer)
        {
            return Err(
                "historical-v2 public-surface census included an ineligible document".to_string(),
            );
        }
    }
    for file in source.source_files.iter().filter(|file| {
        required_document_paths.contains(&file.repository_path)
            && file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required
            && file.public_surface_coverage == HistoricalV2PublicSurfaceCoverage::Complete
    }) {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        if indexers.contains(&indexer) && !paths.contains(file.repository_path.as_str()) {
            return Err(
                "historical-v2 compiler omitted a required public-surface document".to_string(),
            );
        }
    }
    Ok(paths)
}

fn validate_symbols<'a>(
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    all_source_paths: &BTreeSet<&str>,
) -> Result<BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>, String> {
    if semantic.symbol_count != semantic.symbols.len()
        || semantic.public_symbol_count
            != semantic
                .symbols
                .iter()
                .filter(|symbol| symbol.is_public_surface)
                .count()
    {
        return Err("historical-v2 semantic symbol counts changed".to_string());
    }
    let mut symbols = BTreeMap::new();
    let mut previous = None;
    for entry in &semantic.symbols {
        let symbol = &entry.symbol;
        let key = (entry.indexer, symbol.symbol_id.as_str());
        if previous.is_some_and(|previous| previous >= key)
            || !indexers.contains(&entry.indexer)
            || symbol.symbol_id.trim().is_empty()
            || symbol.provider_identity.trim().is_empty()
            || symbol.provider_kind.trim().is_empty()
            || symbol.definitions.is_empty()
            || symbol
                .definitions
                .iter()
                .any(|location| !valid_location(location, all_source_paths))
        {
            return Err("historical-v2 semantic symbol is invalid or noncanonical".to_string());
        }
        if symbols.insert(key, entry).is_some() {
            return Err("historical-v2 semantic symbol identity repeated".to_string());
        }
        previous = Some(key);
    }
    Ok(symbols)
}

fn validate_reexport_hops<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    symbols: &BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>,
    all_source_paths: &BTreeSet<&str>,
    public_surface_document_paths: &BTreeSet<&str>,
) -> Result<(ReexportMap<'a>, BTreeSet<SymbolKey<'a>>), String> {
    if semantic.public_reexport_hop_count != semantic.public_reexport_hops.len()
        || semantic
            .public_reexport_hops
            .windows(2)
            .any(|pair| pair[0].reexport_unit_id >= pair[1].reexport_unit_id)
    {
        return Err("historical-v2 public re-export hop count or order changed".to_string());
    }
    let mut expected = BTreeMap::new();
    for file in source
        .source_files
        .iter()
        .filter(|file| public_surface_document_paths.contains(file.repository_path.as_str()))
    {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        if !indexers.contains(&indexer) {
            continue;
        }
        for reexport in &file.public_reexports {
            if expected
                .insert(
                    reexport.reexport_unit_id.as_str(),
                    (file, reexport, indexer),
                )
                .is_some()
            {
                return Err("historical-v2 source repeats a public re-export".to_string());
            }
        }
    }
    if expected.len() != semantic.public_reexport_hops.len() {
        return Err("historical-v2 compiler omitted a public re-export hop".to_string());
    }

    let mut validated = BTreeMap::new();
    let mut reexport_symbols = BTreeSet::new();
    for hop in &semantic.public_reexport_hops {
        let (file, reexport, expected_indexer) = expected
            .get(hop.reexport_unit_id.as_str())
            .copied()
            .ok_or_else(|| "historical-v2 compiler invented a public re-export hop".to_string())?;
        let expected_anchor =
            source_reexport_semantic_range(&file.repository_path, reexport, hop.position_encoding);
        let symbol_key = (hop.indexer, hop.module_symbol_id.as_str());
        let symbol = symbols.get(&symbol_key).ok_or_else(|| {
            "historical-v2 public re-export hop references a missing module symbol".to_string()
        })?;
        if hop.indexer != expected_indexer
            || hop.repository_path != file.repository_path
            || hop.target_repository_path == hop.repository_path
            || !all_source_paths.contains(hop.target_repository_path.as_str())
            || !public_surface_document_paths.contains(hop.target_repository_path.as_str())
            || hop.compiler_anchor != expected_anchor
            || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
            || !matches!(
                symbol.symbol.category,
                IntentionalBoundarySemanticSymbolCategory::Module
                    | IntentionalBoundarySemanticSymbolCategory::Namespace
                    | IntentionalBoundarySemanticSymbolCategory::Package
            )
            || !symbol
                .symbol
                .definitions
                .iter()
                .any(|definition| definition.repository_path == hop.target_repository_path)
        {
            return Err("historical-v2 public re-export hop changed compiler identity".to_string());
        }
        validated.insert(hop.reexport_unit_id.as_str(), (file, reexport, hop));
        reexport_symbols.insert(symbol_key);
    }
    Ok((validated, reexport_symbols))
}

fn validate_public_bindings<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    symbols: &BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>,
    reexports: &ReexportMap<'a>,
    public_surface_document_paths: &BTreeSet<&str>,
) -> Result<BTreeSet<SymbolKey<'a>>, String> {
    if semantic.public_binding_count != semantic.public_bindings.len() {
        return Err("historical-v2 public binding count changed".to_string());
    }
    let mut expected = DeclarationMap::new();
    let mut required_declarations = BTreeSet::new();
    for file in source
        .source_files
        .iter()
        .filter(|file| public_surface_document_paths.contains(file.repository_path.as_str()))
    {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        if !indexers.contains(&indexer) {
            continue;
        }
        if file.public_surface_coverage != HistoricalV2PublicSurfaceCoverage::Complete {
            return Err(format!(
                "historical-v2 public-surface collector is incomplete for {}",
                file.repository_path
            ));
        }
        for declaration in &file.public_declarations {
            if declaration.surface_unit_id.trim().is_empty()
                || declaration.declaration_unit_id.trim().is_empty()
                || declaration.exposed_identifier.start >= declaration.exposed_identifier.end
                || declaration.identifier.start >= declaration.identifier.end
                || declaration.name.trim().is_empty()
                || expected
                    .insert(
                        declaration.declaration_unit_id.as_str(),
                        (file.repository_path.as_str(), indexer, declaration),
                    )
                    .is_some()
            {
                return Err(
                    "historical-v2 source public declaration is invalid or repeated".to_string(),
                );
            }
            required_declarations.insert(declaration.declaration_unit_id.as_str());
        }
    }

    let mut bound_declarations = BTreeSet::new();
    let mut public_symbols = BTreeSet::new();
    let direct_pairs = semantic
        .public_bindings
        .iter()
        .filter(|binding| {
            binding.binding != HistoricalV2SemanticPublicBindingKind::ReexportExpansion
        })
        .map(|binding| {
            (
                binding.declaration_unit_id.as_str(),
                binding.symbol_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut previous = None;
    for binding in &semantic.public_bindings {
        let key = (
            binding.indexer,
            binding.surface_unit_id.as_str(),
            binding.declaration_unit_id.as_str(),
            binding.symbol_id.as_str(),
        );
        if previous.is_some_and(|previous| previous >= key) {
            return Err("historical-v2 public bindings are not canonical".to_string());
        }
        let symbol_key = (binding.indexer, binding.symbol_id.as_str());
        let symbol = symbols.get(&symbol_key).ok_or_else(|| {
            "historical-v2 public binding references a missing symbol".to_string()
        })?;
        match binding.binding {
            HistoricalV2SemanticPublicBindingKind::Definition
            | HistoricalV2SemanticPublicBindingKind::Reference => {
                let (repository_path, indexer, declaration) = expected
                    .get(binding.declaration_unit_id.as_str())
                    .ok_or_else(|| {
                        "historical-v2 public binding invented a declaration".to_string()
                    })?;
                let expected_anchor = declaration_semantic_range(
                    repository_path,
                    declaration,
                    binding.position_encoding,
                );
                let expected_binding = match declaration.binding {
                    HistoricalV2SourcePublicBindingKind::Definition => {
                        HistoricalV2SemanticPublicBindingKind::Definition
                    }
                    HistoricalV2SourcePublicBindingKind::Reference => {
                        HistoricalV2SemanticPublicBindingKind::Reference
                    }
                };
                if binding.indexer != *indexer
                    || binding.surface_unit_id != declaration.surface_unit_id
                    || binding.origin_declaration_unit_id != declaration.declaration_unit_id
                    || !binding.reexport_path.is_empty()
                    || binding.repository_path != *repository_path
                    || binding.binding != expected_binding
                    || binding.compiler_anchor != expected_anchor
                    || binding.compiler_anchor.repository_path != *repository_path
                    || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
                    || (binding.binding == HistoricalV2SemanticPublicBindingKind::Definition
                        && !symbol.symbol.definitions.contains(&binding.compiler_anchor))
                    || !compatible_public_symbol_kind(declaration.kind, symbol.symbol.category)
                    || !bound_declarations.insert(binding.declaration_unit_id.as_str())
                {
                    return Err(
                        "historical-v2 public binding changed compiler identity".to_string()
                    );
                }
            }
            HistoricalV2SemanticPublicBindingKind::ReexportExpansion => {
                validate_expanded_public_binding(
                    binding,
                    symbol,
                    &expected,
                    reexports,
                    &direct_pairs,
                )?;
            }
        }
        public_symbols.insert(symbol_key);
        previous = Some(key);
    }
    if !required_declarations.is_subset(&bound_declarations) {
        return Err("historical-v2 changed public declaration has no compiler binding".to_string());
    }
    super::public_surface_validation::validate_complete_reexport_expansions(
        source,
        semantic,
        public_surface_document_paths,
    )?;
    if semantic.symbols.iter().any(|entry| {
        entry.is_public_surface
            != public_symbols.contains(&(entry.indexer, entry.symbol.symbol_id.as_str()))
    }) {
        return Err("historical-v2 public semantic symbol classification changed".to_string());
    }
    Ok(public_symbols)
}

fn validate_expanded_public_binding<'a>(
    binding: &HistoricalV2SemanticPublicBinding,
    symbol: &HistoricalV2SemanticSymbol,
    declarations: &DeclarationMap<'a>,
    reexports: &ReexportMap<'a>,
    direct_pairs: &BTreeSet<(&str, &str)>,
) -> Result<(), String> {
    let (origin_path, origin_indexer, origin) = declarations
        .get(binding.origin_declaration_unit_id.as_str())
        .copied()
        .ok_or_else(|| "historical-v2 re-export expansion has no origin declaration".to_string())?;
    if binding.reexport_path.is_empty()
        || binding.indexer != origin_indexer
        || symbol.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
        || !compatible_public_symbol_kind(origin.kind, symbol.symbol.category)
        || !direct_pairs.contains(&(
            binding.origin_declaration_unit_id.as_str(),
            binding.symbol_id.as_str(),
        ))
    {
        return Err("historical-v2 re-export expansion changed compiler identity".to_string());
    }

    let mut current_path = binding.repository_path.as_str();
    let mut seen_hops = BTreeSet::new();
    for reexport_id in &binding.reexport_path {
        if !seen_hops.insert(reexport_id.as_str()) {
            return Err("historical-v2 re-export expansion contains a cycle".to_string());
        }
        let (file, _, hop) = reexports
            .get(reexport_id.as_str())
            .copied()
            .ok_or_else(|| "historical-v2 re-export expansion invented a hop".to_string())?;
        if file.repository_path != current_path || hop.indexer != binding.indexer {
            return Err("historical-v2 re-export expansion path is disconnected".to_string());
        }
        current_path = hop.target_repository_path.as_str();
    }
    if current_path != origin_path {
        return Err("historical-v2 re-export expansion misses its origin".to_string());
    }

    let mut name = origin.name.clone();
    let mut owner = origin.owner.clone();
    let mut namespace = origin.namespace;
    let mut kind = origin.kind;
    for reexport_id in binding.reexport_path.iter().rev() {
        let (file, reexport, _) = reexports.get(reexport_id.as_str()).copied().unwrap();
        match reexport.kind {
            HistoricalV2SourcePublicReexportKind::Wildcard => {
                if name == "default" {
                    return Err(
                        "historical-v2 wildcard expansion exposed a default export".to_string()
                    );
                }
            }
            HistoricalV2SourcePublicReexportKind::Namespace => {
                name = reexport.name.clone().ok_or_else(|| {
                    "historical-v2 namespace expansion has no exposed name".to_string()
                })?;
                owner = None;
                namespace = HistoricalV2SourcePublicNamespace::Module;
                kind = HistoricalV2SourcePublicSymbolKind::Module;
            }
        }
        let module_identity = super::super::history_v2_source_census::public_module_identity(
            &file.repository_path,
            &file.language,
        );
        let expected_surface =
            super::super::history_v2_source_census::historical_public_surface_unit_id(
                &file.language,
                &module_identity,
                &name,
                owner.as_deref(),
                namespace,
                kind,
            )?;
        if reexport_id == &binding.reexport_path[0] && binding.surface_unit_id != expected_surface {
            return Err("historical-v2 re-export expansion changed public identity".to_string());
        }
    }
    let outer_hop = reexports
        .get(binding.reexport_path[0].as_str())
        .map(|(_, _, hop)| *hop)
        .unwrap();
    let expected_declaration = super::reexport_expansion_declaration_unit_id(
        &binding.surface_unit_id,
        &binding.repository_path,
        &binding.origin_declaration_unit_id,
        &binding.symbol_id,
        &binding.reexport_path,
    )?;
    if binding.declaration_unit_id != expected_declaration
        || binding.position_encoding != outer_hop.position_encoding
        || binding.compiler_anchor != outer_hop.compiler_anchor
    {
        return Err("historical-v2 re-export expansion changed its compiler anchor".to_string());
    }
    Ok(())
}

fn declaration_semantic_range(
    repository_path: &str,
    declaration: &super::super::HistoricalV2SourcePublicDeclaration,
    encoding: crate::semantic_index::SemanticPositionEncoding,
) -> IntentionalBoundarySemanticRange {
    let range = match encoding {
        crate::semantic_index::SemanticPositionEncoding::Utf8 => {
            declaration.identifier_positions.utf8
        }
        crate::semantic_index::SemanticPositionEncoding::Utf16 => {
            declaration.identifier_positions.utf16
        }
        crate::semantic_index::SemanticPositionEncoding::Utf32 => {
            declaration.identifier_positions.utf32
        }
    };
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: range.start.line_zero_based,
        start_character_zero_based: range.start.character_zero_based,
        end_line_zero_based: range.end.line_zero_based,
        end_character_zero_based: range.end.character_zero_based,
    }
}

fn source_reexport_semantic_range(
    repository_path: &str,
    reexport: &HistoricalV2SourcePublicReexport,
    encoding: crate::semantic_index::SemanticPositionEncoding,
) -> IntentionalBoundarySemanticRange {
    let range = match encoding {
        crate::semantic_index::SemanticPositionEncoding::Utf8 => reexport.identifier_positions.utf8,
        crate::semantic_index::SemanticPositionEncoding::Utf16 => {
            reexport.identifier_positions.utf16
        }
        crate::semantic_index::SemanticPositionEncoding::Utf32 => {
            reexport.identifier_positions.utf32
        }
    };
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: range.start.line_zero_based,
        start_character_zero_based: range.start.character_zero_based,
        end_line_zero_based: range.end.line_zero_based,
        end_character_zero_based: range.end.character_zero_based,
    }
}

fn compatible_public_symbol_kind(
    declaration: HistoricalV2SourcePublicSymbolKind,
    compiler: IntentionalBoundarySemanticSymbolCategory,
) -> bool {
    matches!(
        (declaration, compiler),
        (
            HistoricalV2SourcePublicSymbolKind::CompilerDefined,
            IntentionalBoundarySemanticSymbolCategory::Callable
                | IntentionalBoundarySemanticSymbolCategory::Constructor
                | IntentionalBoundarySemanticSymbolCategory::Method
                | IntentionalBoundarySemanticSymbolCategory::Type
                | IntentionalBoundarySemanticSymbolCategory::TraitOrInterface
                | IntentionalBoundarySemanticSymbolCategory::Module
                | IntentionalBoundarySemanticSymbolCategory::Namespace
                | IntentionalBoundarySemanticSymbolCategory::Package
                | IntentionalBoundarySemanticSymbolCategory::FieldOrProperty
                | IntentionalBoundarySemanticSymbolCategory::Variable
                | IntentionalBoundarySemanticSymbolCategory::Constant
                | IntentionalBoundarySemanticSymbolCategory::Macro
        ) | (
            HistoricalV2SourcePublicSymbolKind::Callable,
            IntentionalBoundarySemanticSymbolCategory::Callable
        ) | (
            HistoricalV2SourcePublicSymbolKind::Module,
            IntentionalBoundarySemanticSymbolCategory::Module
                | IntentionalBoundarySemanticSymbolCategory::Namespace
                | IntentionalBoundarySemanticSymbolCategory::Package
        ) | (
            HistoricalV2SourcePublicSymbolKind::Method,
            IntentionalBoundarySemanticSymbolCategory::Method
        ) | (
            HistoricalV2SourcePublicSymbolKind::Type,
            IntentionalBoundarySemanticSymbolCategory::Type
                | IntentionalBoundarySemanticSymbolCategory::TraitOrInterface
        ) | (
            HistoricalV2SourcePublicSymbolKind::Field,
            IntentionalBoundarySemanticSymbolCategory::FieldOrProperty
        ) | (
            HistoricalV2SourcePublicSymbolKind::Variable,
            IntentionalBoundarySemanticSymbolCategory::Variable
        ) | (
            HistoricalV2SourcePublicSymbolKind::Constant,
            IntentionalBoundarySemanticSymbolCategory::Constant
        )
    )
}

type ExpectedMethod<'a> = (
    &'a str,
    &'a str,
    usize,
    usize,
    IntentionalBoundaryIndexerKind,
);

fn validate_methods<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    symbols: &BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>,
    source_paths: &BTreeSet<&str>,
) -> Result<BTreeSet<SymbolKey<'a>>, String> {
    let mut expected = BTreeMap::<&str, ExpectedMethod<'_>>::new();
    for file in source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
    {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        for method in &file.methods {
            if expected
                .insert(
                    method.parser_unit_id.as_str(),
                    (
                        file.repository_path.as_str(),
                        method.symbol_name.as_str(),
                        method.start_line,
                        method.end_line,
                        indexer,
                    ),
                )
                .is_some()
            {
                return Err("historical-v2 source repeats a semantic method".to_string());
            }
        }
    }
    if semantic.methods.len() != expected.len()
        || semantic
            .methods
            .windows(2)
            .any(|pair| pair[0].parser_unit_id >= pair[1].parser_unit_id)
    {
        return Err("historical-v2 semantic method coverage changed".to_string());
    }

    let mut referenced_symbols = BTreeSet::new();
    let mut resolved = 0_usize;
    let mut compiler_excluded = 0_usize;
    for method in &semantic.methods {
        let expected = expected
            .get(method.parser_unit_id.as_str())
            .ok_or_else(|| "historical-v2 semantic census invented a method".to_string())?;
        if method.repository_path != expected.0
            || method.symbol_name != expected.1
            || method.start_line != expected.2
            || method.end_line != expected.3
            || method.indexer != expected.4
            || !(indexers.contains(&method.indexer)
                || matches!(
                    method.status,
                    HistoricalV2SemanticMethodStatus::CompilerExcluded { .. }
                ))
        {
            return Err("historical-v2 semantic method identity changed".to_string());
        }
        match &method.status {
            HistoricalV2SemanticMethodStatus::Resolved {
                symbol_id,
                joined_definition,
            } => {
                let key = (method.indexer, symbol_id.as_str());
                if symbol_id.trim().is_empty()
                    || !symbols.contains_key(&key)
                    || joined_definition
                        .iter()
                        .any(|location| !valid_location(location, source_paths))
                {
                    return Err(
                        "historical-v2 resolved method has invalid compiler evidence".to_string(),
                    );
                }
                referenced_symbols.insert(key);
                resolved += 1;
            }
            HistoricalV2SemanticMethodStatus::CompilerExcluded { reason } => {
                if reason.trim().is_empty() {
                    return Err(
                        "historical-v2 compiler-excluded method has no evidence".to_string()
                    );
                }
                compiler_excluded += 1;
            }
            HistoricalV2SemanticMethodStatus::Unresolved { detail, .. } => {
                if detail.trim().is_empty() {
                    return Err("historical-v2 unresolved method has no evidence".to_string());
                }
            }
        }
    }
    let unresolved = semantic
        .methods
        .len()
        .checked_sub(resolved + compiler_excluded)
        .ok_or_else(|| "historical-v2 semantic method counts underflowed".to_string())?;
    if semantic.resolved_method_count != resolved
        || semantic.compiler_excluded_method_count != compiler_excluded
        || semantic.unresolved_method_count != unresolved
    {
        return Err("historical-v2 semantic method counts changed".to_string());
    }
    Ok(referenced_symbols)
}

fn valid_location(
    location: &IntentionalBoundarySemanticRange,
    source_paths: &BTreeSet<&str>,
) -> bool {
    source_paths.contains(location.repository_path.as_str())
        && (location.end_line_zero_based > location.start_line_zero_based
            || (location.end_line_zero_based == location.start_line_zero_based
                && location.end_character_zero_based >= location.start_character_zero_based))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
