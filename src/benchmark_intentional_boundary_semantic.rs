use super::{
    INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCallFacts,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticDispatch,
    IntentionalBoundarySemanticImportFacts, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticOccurrenceFacts, IntentionalBoundarySemanticOccurrenceRole,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticRelationshipFacts, IntentionalBoundarySemanticRelationshipKind,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSurface,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticTestFacts, IntentionalBoundarySemanticTestKind,
    IntentionalBoundarySemanticUnresolvedReason, IntentionalBoundarySemanticVisibility,
    IntentionalBoundarySourceCensus, IntentionalBoundarySourceFile,
    intentional_boundary_file_records, validate_intentional_boundary_source_census,
};
use crate::semantic_index::{
    SemanticDispatch, SemanticIndex, SemanticLocation, SemanticOccurrenceRole,
    SemanticRelationshipKind, SemanticResolution, SemanticSurface, SemanticSymbolCategory,
    SemanticSymbolId, SemanticSymbolOrigin, SemanticTestRelationshipKind, SemanticUnresolvedReason,
    SemanticVisibility,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::semantic_method_join::{SemanticMethodCoverage, join_methods};
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SEMANTIC_CENSUS_CONTRACT: &str =
    "sniffbench-intentional-boundary-compiler-semantic-census-v1";
type MethodJoinKey = (String, String, u32, u32);
type ExpectedMethodMap<'a> =
    BTreeMap<MethodJoinKey, &'a super::IntentionalBoundaryMethodCensusEntry>;

pub async fn census_intentional_boundary_semantics(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
) -> Result<IntentionalBoundarySemanticCensus, String> {
    validate_intentional_boundary_source_census(
        repository,
        revision,
        root,
        inventory,
        source_census,
    )?;
    let files = intentional_boundary_file_records(root, inventory, source_census)?;
    let indexes = crate::semantic_indexer_runner::run_required_indexers(root, &files).await?;
    build_semantic_census(root, source_census, &files, &indexes)
}

pub fn validate_intentional_boundary_semantic_census(
    source_census: &IntentionalBoundarySourceCensus,
    census: &IntentionalBoundarySemanticCensus,
) -> Result<(), String> {
    if census.schema_version != INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION
        || census.semantic_contract != SEMANTIC_CENSUS_CONTRACT
        || census.repository != source_census.repository
        || census.revision != source_census.revision
        || census.source_census_sha256 != source_census.census_sha256
    {
        return Err("intentional-boundary semantic census identity changed".to_string());
    }
    let expected_indexers = source_census
        .source_files
        .iter()
        .map(|file| indexer_for_language(&file.language).map(indexer_kind))
        .collect::<Result<BTreeSet<_>, String>>()?;
    let actual_indexers = census
        .indexers
        .iter()
        .map(|indexer| indexer.indexer)
        .collect::<BTreeSet<_>>();
    if actual_indexers != expected_indexers || actual_indexers.len() != census.indexers.len() {
        return Err("intentional-boundary semantic census indexer coverage changed".to_string());
    }
    for indexer in &census.indexers {
        if indexer.tool_name.trim().is_empty()
            || !is_sha256(&indexer.semantic_facts_sha256)
            || !is_sha256(&indexer.diagnostics_sha256)
        {
            return Err("intentional-boundary semantic indexer commitment is invalid".to_string());
        }
    }
    let expected_methods = source_census
        .source_files
        .iter()
        .flat_map(|file| {
            file.methods.iter().map(|method| {
                (
                    method.parser_unit_id.as_str(),
                    (
                        file.repository_path.as_str(),
                        method.symbol_name.as_str(),
                        method.start_line,
                        method.end_line,
                        indexer_for_language(&file.language).map(indexer_kind),
                    ),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    if expected_methods.len() != source_census.method_count
        || census.methods.len() != source_census.method_count
    {
        return Err("intentional-boundary semantic method coverage changed".to_string());
    }
    let mut seen_methods = BTreeSet::new();
    for method in &census.methods {
        let expected = expected_methods
            .get(method.parser_unit_id.as_str())
            .ok_or_else(|| "intentional-boundary semantic census invented a method".to_string())?;
        if !seen_methods.insert(method.parser_unit_id.as_str())
            || method.repository_path != expected.0
            || method.symbol_name != expected.1
            || method.start_line != expected.2
            || method.end_line != expected.3
            || Ok(method.indexer) != expected.4
        {
            return Err("intentional-boundary semantic method identity changed".to_string());
        }
        if !matches!(
            method.status,
            IntentionalBoundarySemanticMethodStatus::Resolved { .. }
        ) && (!method.occurrences.is_empty()
            || !method.calls.is_empty()
            || !method.relationships.is_empty()
            || !method.imports.is_empty()
            || !method.test_relationships.is_empty())
        {
            return Err(
                "unresolved intentional-boundary method contains invented semantic facts"
                    .to_string(),
            );
        }
    }
    let resolved = census
        .methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                IntentionalBoundarySemanticMethodStatus::Resolved { .. }
            )
        })
        .count();
    let compiler_excluded = census
        .methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                IntentionalBoundarySemanticMethodStatus::CompilerExcluded { .. }
            )
        })
        .count();
    if census.resolved_method_count != resolved
        || census.compiler_excluded_method_count != compiler_excluded
        || census.unresolved_method_count != census.methods.len() - resolved - compiler_excluded
        || !is_sha256(&census.semantic_census_sha256)
        || compute_semantic_census_sha256(census)? != census.semantic_census_sha256
    {
        return Err("intentional-boundary semantic census commitment changed".to_string());
    }
    Ok(())
}

fn build_semantic_census(
    root: &Path,
    source_census: &IntentionalBoundarySourceCensus,
    files: &[FileRecord],
    indexes: &BTreeMap<SemanticIndexerKind, SemanticIndex>,
) -> Result<IntentionalBoundarySemanticCensus, String> {
    let expected_indexers = source_census
        .source_files
        .iter()
        .map(|file| indexer_for_language(&file.language))
        .collect::<Result<BTreeSet<_>, String>>()?;
    let actual_indexers = indexes.keys().copied().collect::<BTreeSet<_>>();
    if actual_indexers != expected_indexers {
        return Err("intentional-boundary semantic indexer set is incomplete".to_string());
    }

    let mut expected_methods = method_identity_map(&source_census.source_files)?;
    let mut methods = Vec::with_capacity(source_census.method_count);
    let mut indexers = Vec::with_capacity(indexes.len());
    for (kind, index) in indexes {
        let files_for_indexer = crate::semantic_indexer_runner::files_for_indexer(files, *kind);
        let join = join_methods(root, &files_for_indexer, index)?;
        for binding in join.bindings.values() {
            let key = (
                binding.method.file.0.clone(),
                binding.method.name.clone(),
                binding.method.start_line,
                binding.method.end_line,
            );
            let expected = expected_methods.remove(&key).ok_or_else(|| {
                format!(
                    "semantic index invented or repeated intentional-boundary method {}::{}:{}-{}",
                    key.0, key.1, key.2, key.3
                )
            })?;
            methods.push(flatten_method(
                indexer_kind(*kind),
                expected,
                binding,
                index,
            )?);
        }
        indexers.push(summarize_index(*kind, index)?);
    }
    if !expected_methods.is_empty() {
        return Err(format!(
            "intentional-boundary semantic census omitted {} method(s)",
            expected_methods.len()
        ));
    }
    methods.sort_by(|left, right| left.parser_unit_id.cmp(&right.parser_unit_id));
    indexers.sort_by_key(|indexer| indexer.indexer);
    let resolved_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                IntentionalBoundarySemanticMethodStatus::Resolved { .. }
            )
        })
        .count();
    let compiler_excluded_method_count = methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                IntentionalBoundarySemanticMethodStatus::CompilerExcluded { .. }
            )
        })
        .count();
    let unresolved_method_count =
        methods.len() - resolved_method_count - compiler_excluded_method_count;
    let mut census = IntentionalBoundarySemanticCensus {
        schema_version: INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: SEMANTIC_CENSUS_CONTRACT.to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        indexers,
        methods,
        resolved_method_count,
        compiler_excluded_method_count,
        unresolved_method_count,
        semantic_census_sha256: String::new(),
    };
    census.semantic_census_sha256 = compute_semantic_census_sha256(&census)?;
    Ok(census)
}

fn method_identity_map(
    files: &[IntentionalBoundarySourceFile],
) -> Result<ExpectedMethodMap<'_>, String> {
    let mut methods = BTreeMap::new();
    for file in files {
        for method in &file.methods {
            let start_line = u32::try_from(method.start_line).map_err(|_| {
                format!(
                    "intentional-boundary method {} exceeds semantic line range",
                    method.parser_unit_id
                )
            })?;
            let end_line = u32::try_from(method.end_line).map_err(|_| {
                format!(
                    "intentional-boundary method {} exceeds semantic line range",
                    method.parser_unit_id
                )
            })?;
            let key = (
                file.repository_path.clone(),
                method.symbol_name.clone(),
                start_line,
                end_line,
            );
            if methods.insert(key, method).is_some() {
                return Err("intentional-boundary source census repeats a method key".to_string());
            }
        }
    }
    Ok(methods)
}

fn flatten_method(
    indexer: IntentionalBoundaryIndexerKind,
    expected: &super::IntentionalBoundaryMethodCensusEntry,
    binding: &crate::semantic_method_join::SemanticMethodBinding,
    index: &SemanticIndex,
) -> Result<IntentionalBoundarySemanticMethod, String> {
    let (status, symbol_id) = match (&binding.coverage, &binding.symbol) {
        (SemanticMethodCoverage::CompilerExcluded { reason }, _) => (
            IntentionalBoundarySemanticMethodStatus::CompilerExcluded {
                reason: reason.clone(),
            },
            None,
        ),
        (
            _,
            SemanticResolution::Unresolved {
                reason,
                raw_target,
                detail,
            },
        ) => (
            IntentionalBoundarySemanticMethodStatus::Unresolved {
                reason: unresolved_reason(*reason),
                raw_target: raw_target.clone(),
                detail: detail.clone(),
            },
            None,
        ),
        (_, SemanticResolution::Resolved { value }) => {
            let symbol = index.symbols.get(value).ok_or_else(|| {
                format!(
                    "intentional-boundary semantic binding references missing symbol {}",
                    value.0
                )
            })?;
            (
                IntentionalBoundarySemanticMethodStatus::Resolved {
                    symbol: Box::new(flatten_symbol(symbol)),
                    joined_definition: binding.definition.as_ref().map(flatten_location),
                },
                Some(value),
            )
        }
    };
    let occurrences = symbol_id
        .map(|symbol| flatten_occurrences(index, symbol))
        .unwrap_or_default();
    let calls = symbol_id
        .map(|symbol| flatten_calls(index, symbol))
        .unwrap_or_default();
    let relationships = symbol_id
        .map(|symbol| flatten_relationships(index, symbol))
        .unwrap_or_default();
    let imports = symbol_id
        .map(|symbol| flatten_imports(index, symbol))
        .unwrap_or_default();
    let test_relationships = symbol_id
        .map(|symbol| flatten_test_relationships(index, symbol))
        .unwrap_or_default();
    Ok(IntentionalBoundarySemanticMethod {
        parser_unit_id: expected.parser_unit_id.clone(),
        repository_path: binding.method.file.0.clone(),
        symbol_name: binding.method.name.clone(),
        start_line: binding.method.start_line as usize,
        end_line: binding.method.end_line as usize,
        indexer,
        status,
        occurrences,
        calls,
        relationships,
        imports,
        test_relationships,
    })
}

fn flatten_symbol(
    symbol: &crate::semantic_index::SemanticSymbol,
) -> IntentionalBoundarySemanticSymbolFacts {
    IntentionalBoundarySemanticSymbolFacts {
        symbol_id: symbol.id.0.clone(),
        provider_identity: symbol.provider_identity.clone(),
        display_name: symbol.display_name.clone(),
        category: symbol_category(symbol.kind.category),
        provider_kind: symbol.kind.provider_name.clone(),
        documentation: symbol.documentation.clone(),
        signature: symbol
            .signature
            .as_ref()
            .map(|signature| signature.text.clone()),
        signature_referenced_symbols: symbol
            .signature
            .as_ref()
            .map(|signature| {
                signature
                    .referenced_symbols
                    .iter()
                    .map(|symbol| symbol.0.clone())
                    .collect()
            })
            .unwrap_or_default(),
        owner: symbol.owner.as_ref().map(flatten_symbol_resolution),
        definitions: symbol.definitions.iter().map(flatten_location).collect(),
        visibility: visibility(symbol.visibility),
        surfaces: symbol.surfaces.iter().copied().map(surface).collect(),
        origin: origin(symbol.origin),
        ambiguity_notes: symbol.ambiguity_notes.clone(),
    }
}

fn flatten_occurrences(
    index: &SemanticIndex,
    symbol: &SemanticSymbolId,
) -> Vec<IntentionalBoundarySemanticOccurrenceFacts> {
    index
        .documents
        .values()
        .flat_map(|document| {
            document
                .occurrences
                .iter()
                .filter(|occurrence| occurrence.symbol.as_ref() == Some(symbol))
                .map(|occurrence| IntentionalBoundarySemanticOccurrenceFacts {
                    location: flatten_range(&document.path.0, &occurrence.range),
                    roles: occurrence
                        .roles
                        .iter()
                        .copied()
                        .map(occurrence_role)
                        .collect(),
                    override_documentation: occurrence.override_documentation.clone(),
                })
        })
        .collect()
}

fn flatten_calls(
    index: &SemanticIndex,
    symbol: &SemanticSymbolId,
) -> Vec<IntentionalBoundarySemanticCallFacts> {
    index
        .calls
        .iter()
        .filter(|call| {
            call.caller == *symbol
                || matches!(&call.callee, SemanticResolution::Resolved { value } if value == symbol)
        })
        .map(|call| IntentionalBoundarySemanticCallFacts {
            caller: call.caller.0.clone(),
            callee: flatten_symbol_resolution(&call.callee),
            callsite: flatten_location(&call.callsite),
            dispatch: dispatch(call.dispatch),
        })
        .collect()
}

fn flatten_relationships(
    index: &SemanticIndex,
    symbol: &SemanticSymbolId,
) -> Vec<IntentionalBoundarySemanticRelationshipFacts> {
    index
        .relationships
        .iter()
        .filter(|relationship| relationship.source == *symbol || relationship.target == *symbol)
        .map(
            |relationship| IntentionalBoundarySemanticRelationshipFacts {
                source: relationship.source.0.clone(),
                target: relationship.target.0.clone(),
                kind: relationship_kind(relationship.kind),
            },
        )
        .collect()
}

fn flatten_imports(
    index: &SemanticIndex,
    symbol: &SemanticSymbolId,
) -> Vec<IntentionalBoundarySemanticImportFacts> {
    index
        .imports
        .iter()
        .filter(|import| {
            matches!(&import.target, SemanticResolution::Resolved { value } if value == symbol)
        })
        .map(|import| IntentionalBoundarySemanticImportFacts {
            location: flatten_range(&import.document.0, &import.range),
            target: flatten_symbol_resolution(&import.target),
            reexport: flatten_bool_resolution(&import.reexport),
        })
        .collect()
}

fn flatten_test_relationships(
    index: &SemanticIndex,
    symbol: &SemanticSymbolId,
) -> Vec<IntentionalBoundarySemanticTestFacts> {
    index
        .test_relationships
        .iter()
        .filter(|relationship| {
            relationship.test == *symbol
                || matches!(&relationship.production, SemanticResolution::Resolved { value } if value == symbol)
        })
        .map(|relationship| IntentionalBoundarySemanticTestFacts {
            test_symbol: relationship.test.0.clone(),
            production: flatten_symbol_resolution(&relationship.production),
            kind: test_kind(relationship.kind),
        })
        .collect()
}

fn summarize_index(
    kind: SemanticIndexerKind,
    index: &SemanticIndex,
) -> Result<IntentionalBoundarySemanticIndexerCensus, String> {
    let facts = serde_json::to_vec(&(
        index.format_version,
        &index.provenance.format,
        &index.provenance.tool_name,
        &index.provenance.tool_version,
        index.provenance.source_text_encoding,
        &index.documents,
        &index.symbols,
        &index.relationships,
        &index.imports,
        &index.calls,
        &index.test_relationships,
        &index.unresolved_edges,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary semantic facts: {error}"))?;
    let diagnostics = serde_json::to_vec(&index.provenance.diagnostics).map_err(|error| {
        format!("failed to commit intentional-boundary semantic diagnostics: {error}")
    })?;
    Ok(IntentionalBoundarySemanticIndexerCensus {
        indexer: indexer_kind(kind),
        tool_name: index.provenance.tool_name.clone(),
        tool_version: index.provenance.tool_version.clone(),
        semantic_facts_sha256: sha256(&facts),
        diagnostic_count: index.provenance.diagnostics.len(),
        diagnostics_sha256: sha256(&diagnostics),
        document_count: index.documents.len(),
        symbol_count: index.symbols.len(),
        relationship_count: index.relationships.len(),
        import_count: index.imports.len(),
        call_count: index.calls.len(),
        test_relationship_count: index.test_relationships.len(),
        unresolved_edge_count: index.unresolved_edges.len(),
    })
}

fn compute_semantic_census_sha256(
    census: &IntentionalBoundarySemanticCensus,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.semantic_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.indexers,
        &census.methods,
        census.resolved_method_count,
        census.compiler_excluded_method_count,
        census.unresolved_method_count,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary semantic census: {error}"))?;
    Ok(sha256(&bytes))
}

fn flatten_location(location: &SemanticLocation) -> IntentionalBoundarySemanticRange {
    flatten_range(&location.document.0, &location.range)
}

fn flatten_range(
    repository_path: &str,
    range: &crate::semantic_index::SemanticSourceRange,
) -> IntentionalBoundarySemanticRange {
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: range.start.line,
        start_character_zero_based: range.start.character,
        end_line_zero_based: range.end.line,
        end_character_zero_based: range.end.character,
    }
}

fn flatten_symbol_resolution(
    resolution: &SemanticResolution<SemanticSymbolId>,
) -> IntentionalBoundarySemanticResolution<String> {
    match resolution {
        SemanticResolution::Resolved { value } => IntentionalBoundarySemanticResolution::Resolved {
            value: value.0.clone(),
        },
        SemanticResolution::Unresolved {
            reason,
            raw_target,
            detail,
        } => IntentionalBoundarySemanticResolution::Unresolved {
            reason: unresolved_reason(*reason),
            raw_target: raw_target.clone(),
            detail: detail.clone(),
        },
    }
}

fn flatten_bool_resolution(
    resolution: &SemanticResolution<bool>,
) -> IntentionalBoundarySemanticResolution<bool> {
    match resolution {
        SemanticResolution::Resolved { value } => {
            IntentionalBoundarySemanticResolution::Resolved { value: *value }
        }
        SemanticResolution::Unresolved {
            reason,
            raw_target,
            detail,
        } => IntentionalBoundarySemanticResolution::Unresolved {
            reason: unresolved_reason(*reason),
            raw_target: raw_target.clone(),
            detail: detail.clone(),
        },
    }
}

fn indexer_for_language(language: &str) -> Result<SemanticIndexerKind, String> {
    match language {
        "typescript" | "javascript" => Ok(SemanticIndexerKind::TypeScriptJavaScript),
        "python" => Ok(SemanticIndexerKind::Python),
        "go" => Ok(SemanticIndexerKind::Go),
        "kotlin" => Ok(SemanticIndexerKind::Kotlin),
        "rust" => Ok(SemanticIndexerKind::Rust),
        other => Err(format!(
            "intentional-boundary source census contains unsupported language {other}"
        )),
    }
}

fn indexer_kind(kind: SemanticIndexerKind) -> IntentionalBoundaryIndexerKind {
    match kind {
        SemanticIndexerKind::TypeScriptJavaScript => {
            IntentionalBoundaryIndexerKind::TypeScriptJavaScript
        }
        SemanticIndexerKind::Python => IntentionalBoundaryIndexerKind::Python,
        SemanticIndexerKind::Go => IntentionalBoundaryIndexerKind::Go,
        SemanticIndexerKind::Kotlin => IntentionalBoundaryIndexerKind::Kotlin,
        SemanticIndexerKind::Rust => IntentionalBoundaryIndexerKind::Rust,
    }
}

fn unresolved_reason(
    reason: SemanticUnresolvedReason,
) -> IntentionalBoundarySemanticUnresolvedReason {
    match reason {
        SemanticUnresolvedReason::DynamicDispatch => {
            IntentionalBoundarySemanticUnresolvedReason::DynamicDispatch
        }
        SemanticUnresolvedReason::Ambiguous => {
            IntentionalBoundarySemanticUnresolvedReason::Ambiguous
        }
        SemanticUnresolvedReason::MissingDefinition => {
            IntentionalBoundarySemanticUnresolvedReason::MissingDefinition
        }
        SemanticUnresolvedReason::MissingIndexerFact => {
            IntentionalBoundarySemanticUnresolvedReason::MissingIndexerFact
        }
        SemanticUnresolvedReason::UnsupportedConstruct => {
            IntentionalBoundarySemanticUnresolvedReason::UnsupportedConstruct
        }
        SemanticUnresolvedReason::ExternalContractUnavailable => {
            IntentionalBoundarySemanticUnresolvedReason::ExternalContractUnavailable
        }
    }
}

fn symbol_category(category: SemanticSymbolCategory) -> IntentionalBoundarySemanticSymbolCategory {
    match category {
        SemanticSymbolCategory::Unknown => IntentionalBoundarySemanticSymbolCategory::Unknown,
        SemanticSymbolCategory::Callable => IntentionalBoundarySemanticSymbolCategory::Callable,
        SemanticSymbolCategory::Constructor => {
            IntentionalBoundarySemanticSymbolCategory::Constructor
        }
        SemanticSymbolCategory::Method => IntentionalBoundarySemanticSymbolCategory::Method,
        SemanticSymbolCategory::Type => IntentionalBoundarySemanticSymbolCategory::Type,
        SemanticSymbolCategory::TraitOrInterface => {
            IntentionalBoundarySemanticSymbolCategory::TraitOrInterface
        }
        SemanticSymbolCategory::Module => IntentionalBoundarySemanticSymbolCategory::Module,
        SemanticSymbolCategory::Namespace => IntentionalBoundarySemanticSymbolCategory::Namespace,
        SemanticSymbolCategory::Package => IntentionalBoundarySemanticSymbolCategory::Package,
        SemanticSymbolCategory::FieldOrProperty => {
            IntentionalBoundarySemanticSymbolCategory::FieldOrProperty
        }
        SemanticSymbolCategory::Parameter => IntentionalBoundarySemanticSymbolCategory::Parameter,
        SemanticSymbolCategory::Variable => IntentionalBoundarySemanticSymbolCategory::Variable,
        SemanticSymbolCategory::Constant => IntentionalBoundarySemanticSymbolCategory::Constant,
        SemanticSymbolCategory::Macro => IntentionalBoundarySemanticSymbolCategory::Macro,
        SemanticSymbolCategory::Other => IntentionalBoundarySemanticSymbolCategory::Other,
    }
}

fn visibility(value: SemanticVisibility) -> IntentionalBoundarySemanticVisibility {
    match value {
        SemanticVisibility::Unknown => IntentionalBoundarySemanticVisibility::Unknown,
        SemanticVisibility::Private => IntentionalBoundarySemanticVisibility::Private,
        SemanticVisibility::Package => IntentionalBoundarySemanticVisibility::Package,
        SemanticVisibility::Protected => IntentionalBoundarySemanticVisibility::Protected,
        SemanticVisibility::Public => IntentionalBoundarySemanticVisibility::Public,
    }
}

fn origin(value: SemanticSymbolOrigin) -> IntentionalBoundarySemanticOrigin {
    match value {
        SemanticSymbolOrigin::Unknown => IntentionalBoundarySemanticOrigin::Unknown,
        SemanticSymbolOrigin::Repository => IntentionalBoundarySemanticOrigin::Repository,
        SemanticSymbolOrigin::External => IntentionalBoundarySemanticOrigin::External,
    }
}

fn surface(value: SemanticSurface) -> IntentionalBoundarySemanticSurface {
    match value {
        SemanticSurface::PublicApi => IntentionalBoundarySemanticSurface::PublicApi,
        SemanticSurface::Entrypoint => IntentionalBoundarySemanticSurface::Entrypoint,
        SemanticSurface::Route => IntentionalBoundarySemanticSurface::Route,
        SemanticSurface::Command => IntentionalBoundarySemanticSurface::Command,
        SemanticSurface::Job => IntentionalBoundarySemanticSurface::Job,
        SemanticSurface::Callback => IntentionalBoundarySemanticSurface::Callback,
        SemanticSurface::Plugin => IntentionalBoundarySemanticSurface::Plugin,
        SemanticSurface::FrameworkRegistration => {
            IntentionalBoundarySemanticSurface::FrameworkRegistration
        }
        SemanticSurface::Configuration => IntentionalBoundarySemanticSurface::Configuration,
        SemanticSurface::Schema => IntentionalBoundarySemanticSurface::Schema,
    }
}

fn dispatch(value: SemanticDispatch) -> IntentionalBoundarySemanticDispatch {
    match value {
        SemanticDispatch::Static => IntentionalBoundarySemanticDispatch::Static,
        SemanticDispatch::Virtual => IntentionalBoundarySemanticDispatch::Virtual,
        SemanticDispatch::Dynamic => IntentionalBoundarySemanticDispatch::Dynamic,
        SemanticDispatch::Unknown => IntentionalBoundarySemanticDispatch::Unknown,
    }
}

fn relationship_kind(
    value: SemanticRelationshipKind,
) -> IntentionalBoundarySemanticRelationshipKind {
    match value {
        SemanticRelationshipKind::Reference => {
            IntentionalBoundarySemanticRelationshipKind::Reference
        }
        SemanticRelationshipKind::Implementation => {
            IntentionalBoundarySemanticRelationshipKind::Implementation
        }
        SemanticRelationshipKind::TypeDefinition => {
            IntentionalBoundarySemanticRelationshipKind::TypeDefinition
        }
        SemanticRelationshipKind::Definition => {
            IntentionalBoundarySemanticRelationshipKind::Definition
        }
        SemanticRelationshipKind::Override => IntentionalBoundarySemanticRelationshipKind::Override,
    }
}

fn occurrence_role(value: SemanticOccurrenceRole) -> IntentionalBoundarySemanticOccurrenceRole {
    match value {
        SemanticOccurrenceRole::Definition => IntentionalBoundarySemanticOccurrenceRole::Definition,
        SemanticOccurrenceRole::Import => IntentionalBoundarySemanticOccurrenceRole::Import,
        SemanticOccurrenceRole::Write => IntentionalBoundarySemanticOccurrenceRole::Write,
        SemanticOccurrenceRole::Read => IntentionalBoundarySemanticOccurrenceRole::Read,
        SemanticOccurrenceRole::Generated => IntentionalBoundarySemanticOccurrenceRole::Generated,
        SemanticOccurrenceRole::Test => IntentionalBoundarySemanticOccurrenceRole::Test,
        SemanticOccurrenceRole::ForwardDefinition => {
            IntentionalBoundarySemanticOccurrenceRole::ForwardDefinition
        }
    }
}

fn test_kind(value: SemanticTestRelationshipKind) -> IntentionalBoundarySemanticTestKind {
    match value {
        SemanticTestRelationshipKind::Exercises => IntentionalBoundarySemanticTestKind::Exercises,
        SemanticTestRelationshipKind::Mocks => IntentionalBoundarySemanticTestKind::Mocks,
        SemanticTestRelationshipKind::Replaces => IntentionalBoundarySemanticTestKind::Replaces,
        SemanticTestRelationshipKind::AssertsContract => {
            IntentionalBoundarySemanticTestKind::AssertsContract
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_index::{
        RepositoryPath, SemanticCallEdge, SemanticDocument, SemanticImportEdge,
        SemanticIndexProvenance, SemanticOccurrence, SemanticPosition, SemanticPositionEncoding,
        SemanticRelationship, SemanticSignature, SemanticSourceRange, SemanticSymbol,
        SemanticSymbolKind, SemanticTestRelationship, SemanticTextEncoding,
    };
    use crate::types::MethodRecord;

    fn range(line: u32, start: u32, end: u32) -> SemanticSourceRange {
        SemanticSourceRange {
            start: SemanticPosition {
                line,
                character: start,
            },
            end: SemanticPosition {
                line,
                character: end,
            },
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        IntentionalBoundarySourceCensus,
        Vec<FileRecord>,
        BTreeMap<SemanticIndexerKind, SemanticIndex>,
    ) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        let source = "pub fn process(value: i32) -> i32 { value }\n";
        let absolute_path = root.path().join("src/lib.rs");
        std::fs::write(&absolute_path, source).unwrap();
        let method = MethodRecord {
            name: "process".to_string(),
            file_path: absolute_path.to_string_lossy().into_owned(),
            source: source.to_string(),
            loc: 1,
            param_count: 1,
            start_line: 1,
            end_line: 1,
            is_exported: true,
            language: "rust".to_string(),
            nesting_depth: 0,
            references: Vec::new(),
            real_ref_count: 0,
        };
        let files = vec![FileRecord {
            file_path: absolute_path.to_string_lossy().into_owned(),
            source: source.to_string(),
            language: "rust".to_string(),
            methods: vec![method],
        }];
        let source_census = IntentionalBoundarySourceCensus {
            schema_version: 1,
            census_contract: "fixture".to_string(),
            repository: "github.com/example/semantic".to_string(),
            revision: "a".repeat(40),
            inventory_sha256: "b".repeat(64),
            tracked_entry_count: 1,
            source_files: vec![IntentionalBoundarySourceFile {
                repository_path: "src/lib.rs".to_string(),
                object_id: "c".repeat(40),
                byte_length: source.len() as u64,
                source_sha256: sha256(source.as_bytes()),
                language: "rust".to_string(),
                methods: vec![super::super::IntentionalBoundaryMethodCensusEntry {
                    parser_unit_id: "ibm-v1:fixture".to_string(),
                    symbol_name: "process".to_string(),
                    start_line: 1,
                    end_line: 1,
                    source_sha256: sha256(source.as_bytes()),
                    is_exported: true,
                }],
            }],
            source_file_count: 1,
            method_count: 1,
            census_sha256: "d".repeat(64),
        };
        let document = RepositoryPath("src/lib.rs".to_string());
        let symbol_id = SemanticSymbolId("rust fixture process".to_string());
        let caller_id = SemanticSymbolId("rust fixture caller".to_string());
        let test_id = SemanticSymbolId("rust fixture test".to_string());
        let trait_id = SemanticSymbolId("rust fixture trait".to_string());
        let definition = SemanticLocation {
            document: document.clone(),
            range: range(0, 7, 14),
        };
        let symbol = SemanticSymbol {
            id: symbol_id.clone(),
            provider_identity: symbol_id.0.clone(),
            display_name: Some("process".to_string()),
            kind: SemanticSymbolKind {
                category: SemanticSymbolCategory::Callable,
                provider_name: "function".to_string(),
            },
            documentation: vec!["Public processing contract.".to_string()],
            signature: Some(SemanticSignature {
                language: "rust".to_string(),
                text: "fn process(value: i32) -> i32".to_string(),
                referenced_symbols: BTreeSet::new(),
            }),
            owner: None,
            definitions: BTreeSet::from([definition]),
            visibility: SemanticVisibility::Public,
            surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
            origin: SemanticSymbolOrigin::Repository,
            ambiguity_notes: Vec::new(),
        };
        let index = SemanticIndex {
            format_version: 1,
            repository_root: root.path().to_string_lossy().replace('\\', "/"),
            provenance: SemanticIndexProvenance {
                format: "scip".to_string(),
                tool_name: "fixture-indexer".to_string(),
                tool_version: Some("1.0.0".to_string()),
                arguments: vec![root.path().to_string_lossy().into_owned()],
                source_text_encoding: Some(SemanticTextEncoding::Utf8),
                diagnostics: Vec::new(),
            },
            documents: BTreeMap::from([(
                document.clone(),
                SemanticDocument {
                    path: document.clone(),
                    language: "rust".to_string(),
                    position_encoding: SemanticPositionEncoding::Utf8,
                    embedded_text: None,
                    occurrences: vec![
                        SemanticOccurrence {
                            range: range(0, 7, 14),
                            symbol: Some(symbol_id.clone()),
                            roles: BTreeSet::from([SemanticOccurrenceRole::Definition]),
                            override_documentation: Vec::new(),
                        },
                        SemanticOccurrence {
                            range: range(0, 35, 40),
                            symbol: Some(symbol_id.clone()),
                            roles: BTreeSet::from([SemanticOccurrenceRole::Read]),
                            override_documentation: Vec::new(),
                        },
                    ],
                },
            )]),
            symbols: BTreeMap::from([(symbol_id.clone(), symbol)]),
            relationships: BTreeSet::from([SemanticRelationship {
                source: symbol_id.clone(),
                target: trait_id,
                kind: SemanticRelationshipKind::Implementation,
            }]),
            imports: BTreeSet::from([SemanticImportEdge {
                document: document.clone(),
                range: range(0, 0, 3),
                target: SemanticResolution::Resolved {
                    value: symbol_id.clone(),
                },
                reexport: SemanticResolution::Resolved { value: true },
            }]),
            calls: BTreeSet::from([SemanticCallEdge {
                caller: caller_id,
                callsite: SemanticLocation {
                    document,
                    range: range(0, 20, 27),
                },
                callee: SemanticResolution::Resolved {
                    value: symbol_id.clone(),
                },
                dispatch: SemanticDispatch::Static,
            }]),
            test_relationships: BTreeSet::from([SemanticTestRelationship {
                test: test_id,
                production: SemanticResolution::Resolved { value: symbol_id },
                kind: SemanticTestRelationshipKind::Exercises,
            }]),
            unresolved_edges: BTreeSet::new(),
        };
        (
            root,
            source_census,
            files,
            BTreeMap::from([(SemanticIndexerKind::Rust, index)]),
        )
    }

    #[test]
    fn commits_exact_compiler_facts_for_every_census_method() {
        let (root, source_census, files, indexes) = fixture();

        let census = build_semantic_census(root.path(), &source_census, &files, &indexes).unwrap();

        assert_eq!(census.resolved_method_count, 1);
        assert_eq!(census.unresolved_method_count, 0);
        assert_eq!(census.methods.len(), source_census.method_count);
        let method = &census.methods[0];
        assert_eq!(method.occurrences.len(), 2);
        assert_eq!(method.calls.len(), 1);
        assert_eq!(method.relationships.len(), 1);
        assert_eq!(method.imports.len(), 1);
        assert_eq!(method.test_relationships.len(), 1);
        assert!(matches!(
            method.status,
            IntentionalBoundarySemanticMethodStatus::Resolved { .. }
        ));
        assert_eq!(census.semantic_census_sha256.len(), 64);
        validate_intentional_boundary_semantic_census(&source_census, &census).unwrap();
    }

    #[test]
    fn preserves_missing_compiler_facts_as_unresolved_instead_of_falling_back() {
        let (root, source_census, files, mut indexes) = fixture();
        indexes
            .get_mut(&SemanticIndexerKind::Rust)
            .unwrap()
            .symbols
            .clear();

        let census = build_semantic_census(root.path(), &source_census, &files, &indexes).unwrap();

        assert_eq!(census.resolved_method_count, 0);
        assert_eq!(census.unresolved_method_count, 1);
        assert!(matches!(
            census.methods[0].status,
            IntentionalBoundarySemanticMethodStatus::Unresolved { .. }
        ));
        assert!(census.methods[0].calls.is_empty());
    }

    #[test]
    fn semantic_fact_commitment_ignores_operator_checkout_and_command_paths() {
        let (_, _, _, indexes) = fixture();
        let original = indexes.get(&SemanticIndexerKind::Rust).unwrap();
        let mut relocated = original.clone();
        relocated.repository_root = "/another/operator/checkout".to_string();
        relocated.provenance.arguments = vec!["/another/operator/tool".to_string()];

        let left = summarize_index(SemanticIndexerKind::Rust, original).unwrap();
        let right = summarize_index(SemanticIndexerKind::Rust, &relocated).unwrap();

        assert_eq!(left.semantic_facts_sha256, right.semantic_facts_sha256);
        assert_eq!(left.diagnostics_sha256, right.diagnostics_sha256);
    }

    #[test]
    fn offline_validation_rejects_semantic_checkpoint_tampering() {
        let (root, source_census, files, indexes) = fixture();
        let mut census =
            build_semantic_census(root.path(), &source_census, &files, &indexes).unwrap();
        census.methods[0].calls.clear();

        assert!(
            validate_intentional_boundary_semantic_census(&source_census, &census)
                .unwrap_err()
                .contains("commitment")
        );
    }
}
