use super::*;

pub(in crate::benchmark::release) fn flatten_method(
    indexer: IntentionalBoundaryIndexerKind,
    expected: &IntentionalBoundaryMethodCensusEntry,
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

pub(in crate::benchmark::release) fn summarize_index(
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
