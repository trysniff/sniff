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
    let mut census = build_semantic_census(root.path(), &source_census, &files, &indexes).unwrap();
    census.methods[0].calls.clear();

    assert!(
        validate_intentional_boundary_semantic_census(&source_census, &census)
            .unwrap_err()
            .contains("commitment")
    );
}

#[test]
fn offline_validation_rejects_unrelated_compiler_facts() {
    let (root, source_census, files, indexes) = fixture();
    let mut census = build_semantic_census(root.path(), &source_census, &files, &indexes).unwrap();
    census.methods[0].calls[0].callee = IntentionalBoundarySemanticResolution::Resolved {
        value: "rust unrelated symbol".to_string(),
    };
    census.semantic_census_sha256 = compute_semantic_census_sha256(&census).unwrap();

    assert!(
        validate_intentional_boundary_semantic_census(&source_census, &census)
            .unwrap_err()
            .contains("unrelated compiler facts")
    );
}
