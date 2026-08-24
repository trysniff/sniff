use super::*;
use crate::benchmark::{
    census_intentional_boundary_repository, inventory_intentional_boundary_repository,
};
use crate::semantic_index::{
    RepositoryPath, SemanticCallEdge, SemanticDocument, SemanticImportEdge,
    SemanticIndexProvenance, SemanticOccurrence, SemanticPosition, SemanticPositionEncoding,
    SemanticRelationship, SemanticSignature, SemanticSourceRange, SemanticSymbol,
    SemanticSymbolKind, SemanticTestRelationship, SemanticTextEncoding,
};
use crate::types::MethodRecord;
use std::path::Path;
use std::process::Command;

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
    let external_id = SemanticSymbolId("rust std core/fmt/Debug#fmt().".to_string());
    let external_type_id = SemanticSymbolId("rust std core/fmt/Debug#fmt().(type)".to_string());
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
    let external_symbol = SemanticSymbol {
        id: external_id.clone(),
        provider_identity: external_id.0.clone(),
        display_name: Some("fmt".to_string()),
        kind: SemanticSymbolKind {
            category: SemanticSymbolCategory::Method,
            provider_name: "method".to_string(),
        },
        documentation: Vec::new(),
        signature: None,
        owner: None,
        definitions: BTreeSet::new(),
        visibility: SemanticVisibility::Public,
        surfaces: BTreeSet::new(),
        origin: SemanticSymbolOrigin::External,
        ambiguity_notes: Vec::new(),
    };
    let mut external_type_symbol = external_symbol.clone();
    external_type_symbol.id = external_type_id.clone();
    external_type_symbol.provider_identity = external_type_id.0.clone();
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
                    SemanticOccurrence {
                        range: range(0, 15, 18),
                        symbol: Some(external_id.clone()),
                        roles: BTreeSet::from([SemanticOccurrenceRole::Write]),
                        override_documentation: Vec::new(),
                    },
                    SemanticOccurrence {
                        range: range(0, 15, 18),
                        symbol: Some(external_id.clone()),
                        roles: BTreeSet::from([SemanticOccurrenceRole::Read]),
                        override_documentation: Vec::new(),
                    },
                    SemanticOccurrence {
                        range: range(0, 15, 18),
                        symbol: Some(external_id.clone()),
                        roles: BTreeSet::from([SemanticOccurrenceRole::Read]),
                        override_documentation: Vec::new(),
                    },
                    SemanticOccurrence {
                        range: range(0, 15, 18),
                        symbol: Some(external_type_id.clone()),
                        roles: BTreeSet::from([SemanticOccurrenceRole::Read]),
                        override_documentation: Vec::new(),
                    },
                ],
            },
        )]),
        symbols: BTreeMap::from([
            (symbol_id.clone(), symbol),
            (external_id, external_symbol),
            (external_type_id, external_type_symbol),
        ]),
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

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn semantic_indexer_mutations_are_confined_to_disposable_snapshot() {
    let source = tempfile::tempdir().unwrap();
    git(source.path(), &["init", "--quiet"]);
    git(source.path(), &["config", "user.name", "SniffBench"]);
    git(
        source.path(),
        &["config", "user.email", "bench@example.invalid"],
    );
    git(
        source.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/semantic-snapshot.git",
        ],
    );
    std::fs::write(
        source.path().join("go.mod"),
        "module github.com/example/semantic-snapshot\n\ngo 1.24\n",
    )
    .unwrap();
    std::fs::write(source.path().join("go.sum"), "committed checksum\n").unwrap();
    std::fs::write(
        source.path().join("main.go"),
        "package main\n\nfunc main() {}\n",
    )
    .unwrap();
    git(source.path(), &["add", "go.mod", "go.sum", "main.go"]);
    git(source.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(source.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/semantic-snapshot";
    let inventory =
        inventory_intentional_boundary_repository(repository, &revision, source.path()).unwrap();
    let source_census =
        census_intentional_boundary_repository(repository, &revision, source.path(), &inventory)
            .unwrap();

    let runtime =
        prepare_semantic_runtime_snapshot(&revision, source.path(), &inventory, &source_census)
            .unwrap();
    std::fs::write(runtime.root().join("go.sum"), "indexer-updated checksum\n").unwrap();

    assert!(!git(runtime.root(), &["status", "--porcelain=v1"]).is_empty());
    validate_intentional_boundary_source_census(
        repository,
        &revision,
        source.path(),
        &inventory,
        &source_census,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(source.path().join("go.sum")).unwrap(),
        "committed checksum\n"
    );
    assert!(git(source.path(), &["status", "--porcelain=v1"]).is_empty());
    assert!(
        runtime
            .files()
            .iter()
            .all(|file| Path::new(&file.file_path).starts_with(runtime.root()))
    );
}

#[test]
fn commits_exact_compiler_facts_for_every_census_method() {
    let (root, source_census, files, indexes) = fixture();

    let census = build_semantic_census(root.path(), &source_census, &files, &indexes).unwrap();

    assert_eq!(census.resolved_method_count, 1);
    assert_eq!(census.unresolved_method_count, 0);
    assert_eq!(census.methods.len(), source_census.method_count);
    assert_eq!(census.source_references.len(), 4);
    let same_range_identities = census
        .source_references
        .iter()
        .filter(|reference| {
            reference.location
                == IntentionalBoundarySemanticRange {
                    repository_path: "src/lib.rs".to_string(),
                    start_line_zero_based: 0,
                    start_character_zero_based: 15,
                    end_line_zero_based: 0,
                    end_character_zero_based: 18,
                }
        })
        .filter_map(|reference| match &reference.target {
            IntentionalBoundarySemanticResolution::Resolved { value } => {
                Some(value.provider_identity.as_str())
            }
            IntentionalBoundarySemanticResolution::Unresolved { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        same_range_identities,
        BTreeSet::from([
            "rust std core/fmt/Debug#fmt().",
            "rust std core/fmt/Debug#fmt().(type)",
        ])
    );
    let merged_reference = census
        .source_references
        .iter()
        .find(|reference| {
            matches!(
                &reference.target,
                IntentionalBoundarySemanticResolution::Resolved { value }
                    if value.provider_identity == "rust std core/fmt/Debug#fmt()."
            )
        })
        .unwrap();
    assert_eq!(
        merged_reference.roles,
        [
            IntentionalBoundarySemanticOccurrenceRole::Write,
            IntentionalBoundarySemanticOccurrenceRole::Read,
        ]
    );
    assert!(census.source_references.iter().any(|reference| matches!(
        &reference.target,
        IntentionalBoundarySemanticResolution::Resolved { value }
            if value.provider_identity == "rust std core/fmt/Debug#fmt()."
                && value.origin == IntentionalBoundarySemanticOrigin::External
    )));
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
    assert!(census.source_references.iter().all(|reference| matches!(
        reference.target,
        IntentionalBoundarySemanticResolution::Unresolved { .. }
    )));
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
fn offline_validation_rejects_source_reference_tampering() {
    let (root, source_census, files, indexes) = fixture();
    let mut census = build_semantic_census(root.path(), &source_census, &files, &indexes).unwrap();
    census.source_references[0].location.repository_path = "outside.rs".to_string();
    census.semantic_census_sha256 = compute_semantic_census_sha256(&census).unwrap();

    assert!(
        validate_intentional_boundary_semantic_census(&source_census, &census)
            .unwrap_err()
            .contains("source reference")
    );
}

#[test]
fn offline_validation_rejects_duplicate_source_references() {
    let (root, source_census, files, indexes) = fixture();
    let mut census = build_semantic_census(root.path(), &source_census, &files, &indexes).unwrap();
    census
        .source_references
        .push(census.source_references[0].clone());
    census.semantic_census_sha256 = compute_semantic_census_sha256(&census).unwrap();

    assert!(
        validate_intentional_boundary_semantic_census(&source_census, &census)
            .unwrap_err()
            .contains("source reference")
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
