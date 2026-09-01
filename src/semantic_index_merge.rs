use crate::semantic_index::{
    SEMANTIC_INDEX_FORMAT_VERSION, SemanticIndex, SemanticIndexerContribution,
    SemanticOccurrenceRole, SemanticRelationshipKind, SemanticResolution, SemanticSymbol,
    SemanticSymbolCategory, SemanticSymbolId, SemanticSymbolKind, SemanticSymbolOrigin,
    SemanticUnresolvedEdgeKind,
};

const CONFLICTING_KINDS: &str = "ConflictingKinds";

pub(crate) fn merge_document_shards(
    shards: impl IntoIterator<Item = SemanticIndex>,
) -> Result<SemanticIndex, String> {
    let mut shards = shards.into_iter();
    let mut merged = shards
        .next()
        .ok_or_else(|| "semantic document-shard merge requires at least one index".to_string())?;
    validate_index(&merged)?;
    mark_invocations(&mut merged, SemanticIndexerContribution::DocumentShard);
    merged.provenance.arguments.clear();

    for mut shard in shards {
        validate_compatible_provenance(&merged, &shard)?;
        mark_invocations(&mut shard, SemanticIndexerContribution::DocumentShard);
        merge_diagnostics(&mut merged, &shard);
        merged
            .provenance
            .invocations
            .extend(shard.provenance.invocations);

        for (path, document) in shard.documents {
            if merged.documents.insert(path.clone(), document).is_some() {
                return Err(format!(
                    "semantic document {path:?} appeared in more than one document shard"
                ));
            }
        }
        for (_, symbol) in shard.symbols {
            merge_symbol(&mut merged, symbol)?;
        }
        merged.relationships.extend(shard.relationships);
        merged.imports.extend(shard.imports);
        merged.calls.extend(shard.calls);
        merged.test_relationships.extend(shard.test_relationships);
        merged.unresolved_edges.extend(shard.unresolved_edges);
    }
    Ok(merged)
}

pub(crate) fn merge_implementation_pair(
    merged: &mut SemanticIndex,
    mut pair: SemanticIndex,
) -> Result<(), String> {
    validate_compatible_provenance(merged, &pair)?;
    for (path, document) in &pair.documents {
        let existing = merged.documents.get(path).ok_or_else(|| {
            format!(
                "implementation-pair index emitted document {} outside the document shards",
                path.0
            )
        })?;
        if existing != document {
            return Err(format!(
                "implementation-pair index disagrees with document shard {}",
                path.0
            ));
        }
    }
    let implementations = pair
        .relationships
        .iter()
        .filter(|relationship| relationship.kind == SemanticRelationshipKind::Implementation)
        .cloned()
        .collect::<Vec<_>>();
    for relationship in &implementations {
        for endpoint in [&relationship.source, &relationship.target] {
            merge_missing_implementation_endpoint(merged, &pair, endpoint)?;
        }
    }
    let unresolved = pair
        .unresolved_edges
        .iter()
        .filter(|edge| edge.edge_kind == SemanticUnresolvedEdgeKind::Implementation)
        .cloned()
        .collect::<Vec<_>>();

    mark_invocations(&mut pair, SemanticIndexerContribution::ImplementationPair);
    merge_diagnostics(merged, &pair);
    merged
        .provenance
        .invocations
        .extend(pair.provenance.invocations);
    merged.relationships.extend(implementations);
    merged.unresolved_edges.extend(unresolved);
    Ok(())
}

fn merge_missing_implementation_endpoint(
    merged: &mut SemanticIndex,
    pair: &SemanticIndex,
    endpoint: &SemanticSymbolId,
) -> Result<(), String> {
    if merged.symbols.contains_key(endpoint) {
        return Ok(());
    }
    let symbol = pair.symbols.get(endpoint).ok_or_else(|| {
        format!(
            "implementation-pair relationship references symbol {} absent from document shards and pair symbol evidence",
            endpoint.0
        )
    })?;
    if symbol.origin == SemanticSymbolOrigin::Repository && symbol.definitions.is_empty() {
        return Err(format!(
            "implementation-pair relationship references symbol {} absent from document shards without an exact repository definition",
            endpoint.0
        ));
    }
    if symbol.origin != SemanticSymbolOrigin::Repository && !symbol.definitions.is_empty() {
        return Err(format!(
            "implementation-pair relationship references non-repository symbol {} with repository definitions",
            endpoint.0
        ));
    }
    for definition in &symbol.definitions {
        let pair_document = pair.documents.get(&definition.document).ok_or_else(|| {
            format!(
                "implementation-pair symbol {} has a definition outside its emitted documents",
                endpoint.0
            )
        })?;
        let merged_document = merged.documents.get(&definition.document).ok_or_else(|| {
            format!(
                "implementation-pair symbol {} has a definition outside the accepted document shards",
                endpoint.0
            )
        })?;
        if pair_document != merged_document {
            return Err(format!(
                "implementation-pair symbol {} has a definition in a document that disagrees with its accepted shard",
                endpoint.0
            ));
        }
        let exact_definition = pair_document.occurrences.iter().any(|occurrence| {
            occurrence.symbol.as_ref() == Some(endpoint)
                && occurrence.range == definition.range
                && occurrence
                    .roles
                    .contains(&SemanticOccurrenceRole::Definition)
        });
        if !exact_definition {
            return Err(format!(
                "implementation-pair symbol {} lacks an exact compiler definition occurrence",
                endpoint.0
            ));
        }
    }
    if let Some(SemanticResolution::Resolved { value: owner }) = &symbol.owner
        && !merged.symbols.contains_key(owner)
    {
        return Err(format!(
            "implementation-pair symbol {} has owner {} absent from document shards",
            endpoint.0, owner.0
        ));
    }
    if let Some(signature) = &symbol.signature
        && let Some(missing) = signature
            .referenced_symbols
            .iter()
            .find(|referenced| !merged.symbols.contains_key(*referenced))
    {
        return Err(format!(
            "implementation-pair symbol {} has signature dependency {} absent from document shards",
            endpoint.0, missing.0
        ));
    }
    merge_symbol(merged, symbol.clone())
}

fn validate_compatible_provenance(
    merged: &SemanticIndex,
    incoming: &SemanticIndex,
) -> Result<(), String> {
    validate_index(merged)?;
    validate_index(incoming)?;
    let left = &merged.provenance;
    let right = &incoming.provenance;
    if merged.repository_root != incoming.repository_root {
        return Err("semantic indexes have different repository roots".to_string());
    }
    if left.format != right.format
        || left.tool_name != right.tool_name
        || left.tool_version != right.tool_version
        || left.source_text_encoding != right.source_text_encoding
    {
        return Err("semantic indexes have incompatible compiler provenance".to_string());
    }
    Ok(())
}

fn validate_index(index: &SemanticIndex) -> Result<(), String> {
    if index.format_version != SEMANTIC_INDEX_FORMAT_VERSION {
        return Err(format!(
            "semantic index format version {} is unsupported; expected {}",
            index.format_version, SEMANTIC_INDEX_FORMAT_VERSION
        ));
    }
    if index.provenance.invocations.is_empty() {
        return Err("semantic index provenance omitted compiler invocations".to_string());
    }
    for invocation in &index.provenance.invocations {
        if invocation.output_sha256.len() != 64
            || !invocation
                .output_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("semantic compiler invocation has an invalid output SHA-256".to_string());
        }
    }
    Ok(())
}

fn mark_invocations(index: &mut SemanticIndex, contribution: SemanticIndexerContribution) {
    for invocation in &mut index.provenance.invocations {
        invocation.contribution = contribution;
    }
}

fn merge_diagnostics(merged: &mut SemanticIndex, incoming: &SemanticIndex) {
    for diagnostic in &incoming.provenance.diagnostics {
        if !merged.provenance.diagnostics.contains(diagnostic) {
            merged.provenance.diagnostics.push(diagnostic.clone());
        }
    }
}

pub(crate) fn merge_symbol(
    index: &mut SemanticIndex,
    incoming: SemanticSymbol,
) -> Result<(), String> {
    let Some(existing) = index.symbols.get_mut(&incoming.id) else {
        index.symbols.insert(incoming.id.clone(), incoming);
        return Ok(());
    };
    if !existing.provider_identity.is_empty()
        && existing.provider_identity != incoming.provider_identity
    {
        return Err(format!(
            "semantic symbol identity collision for {}",
            incoming.id.0
        ));
    }
    if existing.provider_identity.is_empty() {
        existing.provider_identity = incoming.provider_identity;
    }
    merge_optional(
        &mut existing.display_name,
        incoming.display_name,
        &incoming.id,
        "display name",
    )?;
    if existing.kind.category == SemanticSymbolCategory::Unknown {
        if existing.kind.provider_name == CONFLICTING_KINDS {
            if incoming.kind.category != SemanticSymbolCategory::Unknown {
                let detail = format!(
                    "additional conflicting SCIP symbol kind for {}: {}",
                    incoming.id.0, incoming.kind.provider_name
                );
                if !existing.ambiguity_notes.contains(&detail) {
                    existing.ambiguity_notes.push(detail);
                }
            }
        } else {
            existing.kind = incoming.kind;
        }
    } else if incoming.kind.category != SemanticSymbolCategory::Unknown
        && existing.kind != incoming.kind
    {
        let mut provider_names = [
            existing.kind.provider_name.as_str(),
            incoming.kind.provider_name.as_str(),
        ];
        provider_names.sort_unstable();
        let detail = format!(
            "conflicting SCIP symbol kinds for {}: {} and {}",
            incoming.id.0, provider_names[0], provider_names[1]
        );
        existing.kind = SemanticSymbolKind {
            category: SemanticSymbolCategory::Unknown,
            provider_name: CONFLICTING_KINDS.to_string(),
        };
        existing.ambiguity_notes.push(detail);
    }
    if let Err(detail) = merge_optional(
        &mut existing.signature,
        incoming.signature,
        &incoming.id,
        "signature",
    ) {
        existing.signature = None;
        existing.ambiguity_notes.push(detail);
    }
    merge_optional(&mut existing.owner, incoming.owner, &incoming.id, "owner")?;
    for documentation in incoming.documentation {
        if !existing.documentation.contains(&documentation) {
            existing.documentation.push(documentation);
        }
    }
    existing.origin = match (existing.origin, incoming.origin) {
        (SemanticSymbolOrigin::Repository, _) | (_, SemanticSymbolOrigin::Repository) => {
            SemanticSymbolOrigin::Repository
        }
        (SemanticSymbolOrigin::External, _) | (_, SemanticSymbolOrigin::External) => {
            SemanticSymbolOrigin::External
        }
        _ => SemanticSymbolOrigin::Unknown,
    };
    if existing.visibility == crate::semantic_index::SemanticVisibility::Unknown {
        existing.visibility = incoming.visibility;
    } else if incoming.visibility != crate::semantic_index::SemanticVisibility::Unknown
        && existing.visibility != incoming.visibility
    {
        return Err(format!(
            "conflicting SCIP symbol visibility for {}",
            incoming.id.0
        ));
    }
    existing.definitions.extend(incoming.definitions);
    existing.surfaces.extend(incoming.surfaces);
    for note in incoming.ambiguity_notes {
        if !existing.ambiguity_notes.contains(&note) {
            existing.ambiguity_notes.push(note);
        }
    }
    Ok(())
}

fn merge_optional<T: PartialEq + std::fmt::Debug>(
    existing: &mut Option<T>,
    incoming: Option<T>,
    id: &SemanticSymbolId,
    field: &str,
) -> Result<(), String> {
    match (&existing, incoming) {
        (None, Some(value)) => *existing = Some(value),
        (Some(left), Some(right)) if left != &right => {
            return Err(format!(
                "conflicting SCIP symbol {field} values for {}: existing={left:?}, incoming={right:?}",
                id.0,
            ));
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_index::{
        RepositoryPath, SemanticCallEdge, SemanticDispatch, SemanticDocument,
        SemanticIndexProvenance, SemanticIndexerInvocation, SemanticLocation, SemanticOccurrence,
        SemanticPosition, SemanticPositionEncoding, SemanticRelationship, SemanticResolution,
        SemanticSourceRange, SemanticSymbolCategory, SemanticSymbolKind, SemanticTextEncoding,
        SemanticVisibility,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn invocation(argument: &str, digest: char) -> SemanticIndexerInvocation {
        SemanticIndexerInvocation {
            arguments: vec![argument.to_string()],
            context: BTreeMap::from([("GOOS".to_string(), "linux".to_string())]),
            contribution: SemanticIndexerContribution::CompleteIndex,
            output_sha256: digest.to_string().repeat(64),
        }
    }

    fn document(path: &str) -> SemanticDocument {
        SemanticDocument {
            path: RepositoryPath(path.to_string()),
            language: "go".to_string(),
            position_encoding: SemanticPositionEncoding::Utf8,
            embedded_text: None,
            occurrences: Vec::new(),
        }
    }

    fn definition(path: &str) -> SemanticLocation {
        SemanticLocation {
            document: RepositoryPath(path.to_string()),
            range: SemanticSourceRange {
                start: SemanticPosition {
                    line: 1,
                    character: 0,
                },
                end: SemanticPosition {
                    line: 1,
                    character: 5,
                },
            },
        }
    }

    fn add_definition(
        index: &mut SemanticIndex,
        path: &str,
        symbol: &SemanticSymbolId,
    ) -> SemanticLocation {
        let definition = definition(path);
        index
            .documents
            .get_mut(&definition.document)
            .unwrap()
            .occurrences
            .push(SemanticOccurrence {
                range: definition.range,
                symbol: Some(symbol.clone()),
                roles: BTreeSet::from([SemanticOccurrenceRole::Definition]),
                override_documentation: Vec::new(),
            });
        definition
    }

    fn symbol(
        id: &str,
        category: SemanticSymbolCategory,
        origin: SemanticSymbolOrigin,
    ) -> SemanticSymbol {
        SemanticSymbol {
            id: SemanticSymbolId(id.to_string()),
            provider_identity: id.to_string(),
            display_name: Some(id.to_string()),
            kind: SemanticSymbolKind {
                category,
                provider_name: format!("{category:?}"),
            },
            documentation: Vec::new(),
            signature: None,
            owner: None,
            definitions: BTreeSet::new(),
            visibility: if origin == SemanticSymbolOrigin::Repository {
                SemanticVisibility::Public
            } else {
                SemanticVisibility::Unknown
            },
            surfaces: BTreeSet::new(),
            origin,
            ambiguity_notes: Vec::new(),
        }
    }

    fn index(path: &str, argument: &str, digest: char) -> SemanticIndex {
        let document = document(path);
        SemanticIndex {
            format_version: SEMANTIC_INDEX_FORMAT_VERSION,
            repository_root: "C:/repo".to_string(),
            provenance: SemanticIndexProvenance {
                format: "scip".to_string(),
                tool_name: "scip-go".to_string(),
                tool_version: Some("0.2.7".to_string()),
                arguments: vec![argument.to_string()],
                source_text_encoding: Some(SemanticTextEncoding::Utf8),
                invocations: vec![invocation(argument, digest)],
                diagnostics: Vec::new(),
            },
            documents: BTreeMap::from([(document.path.clone(), document)]),
            symbols: BTreeMap::new(),
            relationships: BTreeSet::new(),
            imports: BTreeSet::new(),
            calls: BTreeSet::new(),
            test_relationships: BTreeSet::new(),
            unresolved_edges: BTreeSet::new(),
        }
    }

    #[test]
    fn document_shards_merge_symbols_and_preserve_every_invocation() {
        let mut first = index("a.go", "./a", 'a');
        let mut second = index("b.go", "./b", 'b');
        let shared = SemanticSymbolId("scip-global:shared".to_string());
        let caller = SemanticSymbolId("scip-global:caller".to_string());
        first.symbols.insert(
            caller.clone(),
            symbol(
                &caller.0,
                SemanticSymbolCategory::Callable,
                SemanticSymbolOrigin::Repository,
            ),
        );
        first.symbols.insert(
            shared.clone(),
            symbol(
                &shared.0,
                SemanticSymbolCategory::Unknown,
                SemanticSymbolOrigin::External,
            ),
        );
        second.symbols.insert(
            shared.clone(),
            symbol(
                &shared.0,
                SemanticSymbolCategory::Type,
                SemanticSymbolOrigin::Repository,
            ),
        );
        first.calls.insert(SemanticCallEdge {
            caller,
            callsite: SemanticLocation {
                document: RepositoryPath("a.go".to_string()),
                range: SemanticSourceRange {
                    start: SemanticPosition {
                        line: 1,
                        character: 0,
                    },
                    end: SemanticPosition {
                        line: 1,
                        character: 6,
                    },
                },
            },
            callee: SemanticResolution::Resolved {
                value: shared.clone(),
            },
            dispatch: SemanticDispatch::Static,
        });

        let merged = merge_document_shards([first, second]).unwrap();

        assert_eq!(merged.documents.len(), 2);
        assert!(merged.provenance.arguments.is_empty());
        assert_eq!(merged.provenance.invocations.len(), 2);
        assert!(merged.provenance.invocations.iter().all(|invocation| {
            invocation.contribution == SemanticIndexerContribution::DocumentShard
        }));
        assert_eq!(
            merged.symbols[&shared].origin,
            SemanticSymbolOrigin::Repository
        );
        assert_eq!(
            merged.symbols[&shared].kind.category,
            SemanticSymbolCategory::Type
        );
        assert_eq!(
            merged.symbols[&shared].visibility,
            SemanticVisibility::Public
        );
        assert_eq!(merged.calls.len(), 1);
        assert_eq!(
            &merged.calls.iter().next().unwrap().callee,
            &SemanticResolution::Resolved { value: shared }
        );
    }

    #[test]
    fn implementation_pair_adds_only_implementation_evidence() {
        let source = SemanticSymbolId("scip-global:source".to_string());
        let target = SemanticSymbolId("scip-global:target".to_string());
        let mut first = index("a.go", "./a", 'a');
        first.symbols.insert(
            source.clone(),
            symbol(
                &source.0,
                SemanticSymbolCategory::Type,
                SemanticSymbolOrigin::Repository,
            ),
        );
        let mut second = index("b.go", "./b", 'b');
        second.symbols.insert(
            target.clone(),
            symbol(
                &target.0,
                SemanticSymbolCategory::TraitOrInterface,
                SemanticSymbolOrigin::Repository,
            ),
        );
        let mut merged = merge_document_shards([first, second]).unwrap();
        let mut pair = index("a.go", "./a+./b", 'c');
        pair.documents
            .insert(RepositoryPath("b.go".to_string()), document("b.go"));
        pair.relationships.insert(SemanticRelationship {
            source: source.clone(),
            target: target.clone(),
            kind: SemanticRelationshipKind::Implementation,
        });
        pair.relationships.insert(SemanticRelationship {
            source: source.clone(),
            target: target.clone(),
            kind: SemanticRelationshipKind::Reference,
        });

        merge_implementation_pair(&mut merged, pair).unwrap();

        assert_eq!(merged.relationships.len(), 1);
        assert_eq!(
            merged.relationships.iter().next().unwrap().kind,
            SemanticRelationshipKind::Implementation
        );
        assert_eq!(merged.provenance.invocations.len(), 3);
        assert_eq!(
            merged.provenance.invocations.last().unwrap().contribution,
            SemanticIndexerContribution::ImplementationPair
        );
    }

    #[test]
    fn duplicate_document_shards_fail_closed() {
        let error =
            merge_document_shards([index("same.go", "./a", 'a'), index("same.go", "./b", 'b')])
                .unwrap_err();

        assert!(error.contains("more than one document shard"));
    }

    #[test]
    fn implementation_pair_cannot_invent_an_endpoint() {
        let mut merged = merge_document_shards([index("a.go", "./a", 'a')]).unwrap();
        let mut pair = index("a.go", "./a+./missing", 'b');
        pair.relationships.insert(SemanticRelationship {
            source: SemanticSymbolId("missing-source".to_string()),
            target: SemanticSymbolId("missing-target".to_string()),
            kind: SemanticRelationshipKind::Implementation,
        });

        let error = merge_implementation_pair(&mut merged, pair).unwrap_err();

        assert!(error.contains("absent from document shards"));
        assert_eq!(merged.provenance.invocations.len(), 1);
    }

    #[test]
    fn implementation_pair_can_supply_exact_missing_endpoint_definition() {
        let source = SemanticSymbolId("scip-global:source".to_string());
        let target = SemanticSymbolId("scip-global:target-method".to_string());
        let owner = SemanticSymbolId("scip-global:target-owner".to_string());
        let mut diagonal = index("a.go", "./a", 'a');
        add_definition(&mut diagonal, "a.go", &target);
        diagonal.symbols.insert(
            source.clone(),
            symbol(
                &source.0,
                SemanticSymbolCategory::Method,
                SemanticSymbolOrigin::Repository,
            ),
        );
        diagonal.symbols.insert(
            owner.clone(),
            symbol(
                &owner.0,
                SemanticSymbolCategory::TraitOrInterface,
                SemanticSymbolOrigin::Repository,
            ),
        );
        let mut merged = merge_document_shards([diagonal]).unwrap();

        let mut pair = index("a.go", "./a+./b", 'b');
        let definition = add_definition(&mut pair, "a.go", &target);
        let mut target_symbol = symbol(
            &target.0,
            SemanticSymbolCategory::Method,
            SemanticSymbolOrigin::Repository,
        );
        target_symbol.owner = Some(SemanticResolution::Resolved {
            value: owner.clone(),
        });
        target_symbol.definitions.insert(definition);
        pair.symbols.insert(target.clone(), target_symbol);
        pair.relationships.insert(SemanticRelationship {
            source: source.clone(),
            target: target.clone(),
            kind: SemanticRelationshipKind::Implementation,
        });

        merge_implementation_pair(&mut merged, pair).unwrap();

        assert!(merged.symbols.contains_key(&target));
        assert!(merged.relationships.contains(&SemanticRelationship {
            source,
            target,
            kind: SemanticRelationshipKind::Implementation,
        }));
    }

    #[test]
    fn implementation_pair_can_supply_exact_compiler_placeholder_endpoint() {
        let source = SemanticSymbolId("scip-global:source".to_string());
        let target = SemanticSymbolId("scip-global:compiler-only-target".to_string());
        let mut diagonal = index("a.go", "./a", 'a');
        diagonal.symbols.insert(
            source.clone(),
            symbol(
                &source.0,
                SemanticSymbolCategory::Method,
                SemanticSymbolOrigin::Repository,
            ),
        );
        let mut merged = merge_document_shards([diagonal]).unwrap();

        let mut pair = index("a.go", "./a+./b", 'b');
        pair.symbols.insert(
            target.clone(),
            symbol(
                &target.0,
                SemanticSymbolCategory::Unknown,
                SemanticSymbolOrigin::Unknown,
            ),
        );
        pair.relationships.insert(SemanticRelationship {
            source: source.clone(),
            target: target.clone(),
            kind: SemanticRelationshipKind::Implementation,
        });

        merge_implementation_pair(&mut merged, pair).unwrap();

        assert_eq!(
            merged.symbols[&target].origin,
            SemanticSymbolOrigin::Unknown
        );
        assert!(merged.relationships.contains(&SemanticRelationship {
            source,
            target,
            kind: SemanticRelationshipKind::Implementation,
        }));
    }

    #[test]
    fn incompatible_compiler_provenance_fails_closed() {
        let first = index("a.go", "./a", 'a');
        let mut second = index("b.go", "./b", 'b');
        second.provenance.tool_version = Some("different".to_string());

        let error = merge_document_shards([first, second]).unwrap_err();

        assert!(error.contains("incompatible compiler provenance"));
    }

    #[test]
    fn malformed_invocation_digest_fails_closed() {
        let mut malformed = index("a.go", "./a", 'a');
        malformed.provenance.invocations[0].output_sha256 = "not-a-digest".to_string();

        let error = merge_document_shards([malformed]).unwrap_err();

        assert!(error.contains("invalid output SHA-256"));
    }
}
