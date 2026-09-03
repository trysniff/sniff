use super::*;

pub(super) fn assert_matches_reference(
    projection: &SemanticProjectionIndex<'_>,
    index: &SemanticIndex,
) {
    for symbol in referenced_symbols(index) {
        assert_eq!(
            projection.occurrences_for(&symbol),
            flatten_occurrences(index, &symbol),
            "occurrence projection changed for {}",
            symbol.0
        );
        assert_eq!(
            projection.calls_for(&symbol),
            flatten_calls(index, &symbol),
            "call projection changed for {}",
            symbol.0
        );
        assert_eq!(
            projection.relationships_for(&symbol),
            flatten_relationships(index, &symbol),
            "relationship projection changed for {}",
            symbol.0
        );
        assert_eq!(
            projection.imports_for(&symbol),
            flatten_imports(index, &symbol),
            "import projection changed for {}",
            symbol.0
        );
        assert_eq!(
            projection.test_relationships_for(&symbol),
            flatten_test_relationships(index, &symbol),
            "test relationship projection changed for {}",
            symbol.0
        );
    }
}

fn referenced_symbols(index: &SemanticIndex) -> BTreeSet<SemanticSymbolId> {
    let mut symbols = index.symbols.keys().cloned().collect::<BTreeSet<_>>();
    for document in index.documents.values() {
        symbols.extend(
            document
                .occurrences
                .iter()
                .filter_map(|occurrence| occurrence.symbol.clone()),
        );
    }
    for call in &index.calls {
        symbols.insert(call.caller.clone());
        if let SemanticResolution::Resolved { value } = &call.callee {
            symbols.insert(value.clone());
        }
    }
    for relationship in &index.relationships {
        symbols.insert(relationship.source.clone());
        symbols.insert(relationship.target.clone());
    }
    for import in &index.imports {
        if let SemanticResolution::Resolved { value } = &import.target {
            symbols.insert(value.clone());
        }
    }
    for relationship in &index.test_relationships {
        symbols.insert(relationship.test.clone());
        if let SemanticResolution::Resolved { value } = &relationship.production {
            symbols.insert(value.clone());
        }
    }
    symbols
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
