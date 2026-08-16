use super::*;
use crate::semantic_index::{
    RepositoryPath, SemanticDocument, SemanticIndexProvenance, SemanticLocation,
    SemanticOccurrence, SemanticOccurrenceRole, SemanticPosition, SemanticPositionEncoding,
    SemanticSourceRange, SemanticSurface, SemanticSymbol, SemanticSymbolCategory, SemanticSymbolId,
    SemanticSymbolKind, SemanticSymbolOrigin, SemanticTextEncoding, SemanticVisibility,
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn commits_exact_compiler_facts_for_every_historical_method() {
    let fixture = fixture();
    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.resolved_method_count, 1);
    assert_eq!(snapshot.compiler_excluded_method_count, 0);
    assert_eq!(snapshot.unresolved_method_count, 0);
    assert_eq!(snapshot.methods[0].parser_unit_id, "h2m-v1:fixture");
    assert_eq!(snapshot.indexers[0].tool_name, "fixture-indexer");
    validation::validate_snapshot("github.com/example/repo", &fixture.source, &snapshot).unwrap();
}

#[test]
fn semantic_validation_rejects_recommitted_invented_method() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture.indexes,
    )
    .unwrap();
    snapshot.methods[0].parser_unit_id = "invented".to_string();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    assert!(
        validation::validate_snapshot("github.com/example/repo", &fixture.source, &snapshot)
            .unwrap_err()
            .contains("invented")
    );
}

#[test]
fn semantic_census_requires_the_exact_language_indexer_set() {
    let fixture = fixture();
    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeMap::new(),
    )
    .unwrap_err();

    assert!(error.contains("indexer set is incomplete"));
}

struct Fixture {
    root: tempfile::TempDir,
    source: HistoricalV2SourceSnapshotCensus,
    files: Vec<FileRecord>,
    indexes: BTreeMap<SemanticIndexerKind, SemanticIndex>,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("src")).unwrap();
    let source_text = "pub fn process(value: i32) -> i32 { value }\n";
    let absolute = root.path().join("src/lib.rs");
    std::fs::write(&absolute, source_text).unwrap();
    let files = vec![
        crate::parser::parse_source_checked(&absolute.to_string_lossy(), source_text.as_bytes())
            .unwrap(),
    ];
    let method = &files[0].methods[0];
    let source = HistoricalV2SourceSnapshotCensus {
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        parser_census_sha256: "c".repeat(64),
        tracked_entry_count: 1,
        source_files: vec![super::super::HistoricalV2SourceFile {
            repository_path: "src/lib.rs".to_string(),
            object_id: "d".repeat(40),
            byte_length: source_text.len() as u64,
            source_sha256: sha256(source_text.as_bytes()),
            non_whitespace_lines: 1,
            language: "rust".to_string(),
            methods: vec![super::super::HistoricalV2SourceMethod {
                parser_unit_id: "h2m-v1:fixture".to_string(),
                symbol_name: method.name.clone(),
                start_line: method.start_line,
                end_line: method.end_line,
                source_sha256: sha256(method.source.as_bytes()),
                is_exported: method.is_exported,
            }],
        }],
        source_file_count: 1,
        method_counts_by_language: BTreeMap::from([("rust".to_string(), 1)]),
        method_count: 1,
        snapshot_census_sha256: "e".repeat(64),
    };
    let document = RepositoryPath("src/lib.rs".to_string());
    let symbol_id = SemanticSymbolId("rust fixture process".to_string());
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
        documentation: Vec::new(),
        signature: None,
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
            arguments: Vec::new(),
            source_text_encoding: Some(SemanticTextEncoding::Utf8),
            diagnostics: Vec::new(),
        },
        documents: BTreeMap::from([(
            document.clone(),
            SemanticDocument {
                path: document,
                language: "rust".to_string(),
                position_encoding: SemanticPositionEncoding::Utf8,
                embedded_text: None,
                occurrences: vec![SemanticOccurrence {
                    range: range(0, 7, 14),
                    symbol: Some(symbol_id.clone()),
                    roles: BTreeSet::from([SemanticOccurrenceRole::Definition]),
                    override_documentation: Vec::new(),
                }],
            },
        )]),
        symbols: BTreeMap::from([(symbol_id, symbol)]),
        relationships: BTreeSet::new(),
        imports: BTreeSet::new(),
        calls: BTreeSet::new(),
        test_relationships: BTreeSet::new(),
        unresolved_edges: BTreeSet::new(),
    };
    Fixture {
        root,
        source,
        files,
        indexes: BTreeMap::from([(SemanticIndexerKind::Rust, index)]),
    }
}

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
