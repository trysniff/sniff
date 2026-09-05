use super::super::HistoricalV2SemanticPublicBindingKind;
use super::*;
use crate::semantic_index::{
    RepositoryPath, SemanticCallEdge, SemanticDispatch, SemanticDocument, SemanticIndexProvenance,
    SemanticLocation, SemanticOccurrence, SemanticOccurrenceRole, SemanticPosition,
    SemanticPositionEncoding, SemanticResolution, SemanticSourceRange, SemanticSurface,
    SemanticSymbol, SemanticSymbolCategory, SemanticSymbolId, SemanticSymbolKind,
    SemanticSymbolOrigin, SemanticTextEncoding, SemanticVisibility,
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn commits_exact_compiler_facts_for_every_historical_method() {
    let fixture = fixture();
    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.resolved_method_count, 1);
    assert_eq!(snapshot.compiler_excluded_method_count, 0);
    assert_eq!(snapshot.unresolved_method_count, 0);
    assert_eq!(snapshot.methods[0].parser_unit_id, "h2m-v1:fixture");
    assert_eq!(snapshot.indexers[0].tool_name, "fixture-indexer");
    assert_eq!(snapshot.symbol_count, 1);
    assert_eq!(snapshot.public_symbol_count, 1);
    assert_eq!(snapshot.symbols[0].symbol.symbol_id, "rust fixture process");
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
    )
    .unwrap();
}

#[test]
fn high_degree_graph_is_hash_committed_without_per_method_edge_copies() {
    let mut fixture = fixture();
    let index = fixture.indexes.get_mut(&SemanticIndexerKind::Rust).unwrap();
    let symbol = index.symbols.keys().next().unwrap().clone();
    for character in 0..10_000_u32 {
        index.calls.insert(SemanticCallEdge {
            caller: symbol.clone(),
            callsite: SemanticLocation {
                document: RepositoryPath("src/lib.rs".to_string()),
                range: SemanticSourceRange {
                    start: SemanticPosition { line: 1, character },
                    end: SemanticPosition {
                        line: 1,
                        character: character + 1,
                    },
                },
            },
            callee: SemanticResolution::Resolved {
                value: symbol.clone(),
            },
            dispatch: SemanticDispatch::Static,
        });
    }

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.methods.len(), 1);
    assert_eq!(snapshot.symbol_count, 1);
    assert_eq!(snapshot.indexers[0].call_count, 10_000);
    assert!(serde_json::to_vec(&snapshot).unwrap().len() < 16 * 1024);
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
    )
    .unwrap();
}

#[tokio::test]
async fn completed_snapshot_is_loaded_before_source_reconstruction() {
    let fixture = fixture();
    let changed_indexers = fixture_changed_indexers();
    let required_paths = fixture_required_paths(&fixture.source);
    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();
    let materialization = HistoricalV2Materialization {
        schema_version: 1,
        materialization_contract: "fixture".to_string(),
        canonical_repository: "example/repo".to_string(),
        base_revision: fixture.source.revision.clone(),
        object_format: "sha1".to_string(),
        base_tree_oid: "1".repeat(40),
        historical_patch_sha256: "2".repeat(64),
        patched_tree_oid: "3".repeat(40),
        patched_commit_oid: "4".repeat(40),
        materialization_sha256: "5".repeat(64),
    };
    let source_census = HistoricalV2SourceCensus {
        schema_version: 2,
        source_census_contract: "fixture".to_string(),
        canonical_repository: "example/repo".to_string(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        base: fixture.source.clone(),
        patched: fixture.source.clone(),
        source_census_sha256: "6".repeat(64),
    };
    let state = tempfile::tempdir().unwrap();
    let progress =
        progress::HistoricalV2SemanticProgress::open(&state.path().join("progress")).unwrap();
    progress
        .publish_snapshot(
            &materialization,
            &source_census,
            HistoricalV2SemanticSnapshotSide::Base,
            &source_census.base,
            &changed_indexers,
            &required_paths,
            &snapshot,
        )
        .unwrap();
    let unavailable_root = state.path().join("source-does-not-exist");
    let mut failures = Vec::new();
    let mut stage_errors = Vec::new();

    let resumed = execution::census_semantic_snapshot(
        HistoricalV2SemanticSnapshotInputs {
            side: HistoricalV2SemanticSnapshotSide::Base,
            root: &unavailable_root,
            source: &source_census.base,
            required_paths: &required_paths,
        },
        &materialization,
        &source_census,
        &changed_indexers,
        Some(&progress),
        &mut failures,
        &mut stage_errors,
    )
    .await
    .unwrap();

    assert_eq!(resumed, Some(snapshot));
    assert!(failures.is_empty());
    assert!(stage_errors.is_empty());
}

#[test]
fn generated_files_are_committed_but_not_required_from_the_compiler_index() {
    let mut fixture = fixture();
    let mut generated = fixture.source.source_files[0].clone();
    generated.repository_path = "public/angular.min.js".to_string();
    generated.language = "javascript".to_string();
    generated.semantic_coverage = HistoricalV2SourceSemanticCoverage::GeneratedPath;
    generated.public_surface_coverage =
        super::super::HistoricalV2PublicSurfaceCoverage::UnsupportedLanguage;
    generated.public_declarations.clear();
    generated.methods[0].parser_unit_id = "h2m-v1:generated".to_string();
    fixture.source.source_files.push(generated);
    fixture.source.source_file_count += 1;
    fixture.source.method_count += 1;
    *fixture
        .source
        .method_counts_by_language
        .entry("javascript".to_string())
        .or_default() += 1;

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.methods.len(), 1);
    assert_eq!(snapshot.methods[0].parser_unit_id, "h2m-v1:fixture");
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
    )
    .unwrap();
}

#[test]
fn semantic_validation_rejects_recommitted_invented_method() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    snapshot.methods[0].parser_unit_id = "invented".to_string();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    assert!(
        validation::validate_snapshot(
            &fixture.source,
            &snapshot,
            &fixture_changed_indexers(),
            &fixture_required_paths(&fixture.source),
        )
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
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &BTreeMap::new(),
    )
    .unwrap_err();

    assert!(error.contains("indexer set is incomplete"));
}

#[test]
fn semantic_validation_rejects_recommitted_fake_public_surface() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    snapshot.symbols[0].symbol.origin = super::super::IntentionalBoundarySemanticOrigin::External;
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    assert!(
        validation::validate_snapshot(
            &fixture.source,
            &snapshot,
            &fixture_changed_indexers(),
            &fixture_required_paths(&fixture.source),
        )
        .unwrap_err()
        .contains("changed compiler identity")
    );
}

#[test]
fn changed_public_declaration_without_an_exact_compiler_symbol_fails_closed() {
    let mut fixture = fixture();
    fixture.source.source_files[0].public_declarations.push(
        super::super::HistoricalV2SourcePublicDeclaration {
            surface_unit_id: "invented-value-surface".to_string(),
            declaration_unit_id: "invented-value-declaration".to_string(),
            name: "value".to_string(),
            target_name: "value".to_string(),
            owner: None,
            namespace: super::super::HistoricalV2SourcePublicNamespace::Module,
            kind: super::super::HistoricalV2SourcePublicSymbolKind::Variable,
            binding: super::super::HistoricalV2SourcePublicBindingKind::Definition,
            source_module: None,
            exposed_identifier: super::super::HistoricalV2SourceByteRange { start: 15, end: 20 },
            exposed_identifier_positions: source_identifier_positions(0, 15, 20),
            identifier: super::super::HistoricalV2SourceByteRange { start: 15, end: 20 },
            identifier_positions: source_identifier_positions(0, 15, 20),
        },
    );
    fixture.source.public_declaration_count += 1;

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("resolved 0 public symbol(s)"), "{error}");
}

#[test]
fn ambiguous_exact_public_compiler_identity_fails_closed() {
    let mut fixture = fixture();
    let index = fixture.indexes.get_mut(&SemanticIndexerKind::Rust).unwrap();
    let mut duplicate = index.symbols.values().next().unwrap().clone();
    duplicate.id = SemanticSymbolId("rust fixture duplicate process".to_string());
    duplicate.provider_identity = duplicate.id.0.clone();
    index.symbols.insert(duplicate.id.clone(), duplicate);

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("resolved 2 public symbol(s)"), "{error}");
}

#[test]
fn public_reference_binds_the_exact_compiler_occurrence() {
    let fixture = reference_fixture();

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.public_bindings.len(), 1);
    assert_eq!(
        snapshot.public_bindings[0].binding,
        HistoricalV2SemanticPublicBindingKind::Reference
    );
    assert_eq!(
        snapshot.public_bindings[0]
            .compiler_anchor
            .start_character_zero_based,
        41
    );
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
    )
    .unwrap();
}

#[test]
fn public_reference_does_not_fall_back_to_a_matching_symbol_name() {
    let mut fixture = reference_fixture();
    fixture
        .indexes
        .get_mut(&SemanticIndexerKind::TypeScriptJavaScript)
        .unwrap()
        .documents
        .values_mut()
        .next()
        .unwrap()
        .occurrences
        .clear();

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("emitted 0 occurrence(s)"), "{error}");
}

#[test]
fn semantic_validation_rejects_a_retyped_public_reference() {
    let fixture = reference_fixture();
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]);
    let required_paths = fixture_required_paths(&fixture.source);
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();
    snapshot.public_bindings[0].binding = HistoricalV2SemanticPublicBindingKind::Definition;
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap_err();

    assert!(error.contains("changed compiler identity"), "{error}");
}

#[test]
fn compiler_reexports_expand_wildcards_chains_and_namespaces_exhaustively() {
    let fixture = reexport_fixture();
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]);
    let required_paths = fixture_required_paths(&fixture.source);

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();

    let expansions = snapshot
        .public_bindings
        .iter()
        .filter(|binding| {
            binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
        })
        .collect::<Vec<_>>();
    assert_eq!(expansions.len(), 4);
    assert!(
        expansions
            .iter()
            .any(|binding| binding.reexport_path.len() == 2)
    );
    let default_declaration = fixture.source.source_files[2]
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "default")
        .unwrap();
    let default_expansions = expansions
        .iter()
        .filter(|binding| {
            binding.origin_declaration_unit_id == default_declaration.declaration_unit_id
        })
        .collect::<Vec<_>>();
    assert_eq!(default_expansions.len(), 1);
    assert_eq!(default_expansions[0].repository_path, "src/root.ts");
    let namespace_bindings = expansions
        .iter()
        .filter(|binding| {
            binding.repository_path == "src/root.ts" && binding.reexport_path.len() == 1
        })
        .collect::<Vec<_>>();
    assert_eq!(namespace_bindings.len(), 2);
    assert_eq!(
        namespace_bindings[0].surface_unit_id,
        namespace_bindings[1].surface_unit_id
    );
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
#[ignore = "requires the installed checksum-pinned scip-typescript runtime and Node.js"]
fn pinned_typescript_provider_drives_recursive_public_reexports() {
    let mut fixture = reexport_fixture();
    std::fs::write(
        fixture.root.path().join("package.json"),
        r#"{"name":"sniff-reexport-probe","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        fixture.root.path().join("tsconfig.json"),
        r#"{"compilerOptions":{"strict":true,"noEmit":true},"include":["src/**/*.ts"]}"#,
    )
    .unwrap();
    let spec =
        crate::semantic_indexer_manifest::pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript)
            .unwrap();
    let installed = crate::semantic_indexer_installation::SemanticIndexerStore::for_user()
        .unwrap()
        .verify(spec)
        .unwrap();
    let output = fixture.root.path().join("index.scip");
    let status = std::process::Command::new(if cfg!(windows) { "node.exe" } else { "node" })
        .arg(&installed.entrypoint)
        .arg("index")
        .arg("--cwd")
        .arg(fixture.root.path())
        .arg("--output")
        .arg(&output)
        .arg("--no-progress-bar")
        .status()
        .unwrap();
    assert!(status.success());
    let expected_languages = fixture
        .source
        .source_files
        .iter()
        .map(|file| {
            (
                RepositoryPath(file.repository_path.clone()),
                file.language.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    fixture.indexes.insert(
        SemanticIndexerKind::TypeScriptJavaScript,
        crate::semantic_index_scip::ingest_scip_file_with_expected_languages(
            fixture.root.path(),
            &output,
            Some(&expected_languages),
            Some(SemanticPositionEncoding::Utf16),
        )
        .unwrap(),
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]);
    let required_paths = fixture_required_paths(&fixture.source);

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.public_reexport_hop_count, 3);
    assert_eq!(
        snapshot
            .public_bindings
            .iter()
            .filter(|binding| {
                binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
            })
            .count(),
        4
    );
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
#[ignore = "requires the installed checksum-pinned scip-python runtime and Node.js"]
fn pinned_python_provider_drives_signatures_and_recursive_public_surfaces() {
    let mut fixture = python_surface_fixture(
        &[
            (
                "pkg/core.py",
                r#"from typing import overload

PUBLIC_CONSTANT: int = 7
_PRIVATE_CONSTANT: int = 8

@overload
def parse(value: str) -> str: ...

@overload
def parse(value: int) -> int: ...

def parse(value: str | int) -> str | int:
    return value

class Widget:
    category: str = "public"

    def __init__(self, name: str) -> None:
        self.label: str = name

    def render(self, prefix: str = "") -> str:
        return prefix

    @staticmethod
    def build(name: str) -> "Widget":
        return Widget()
"#,
            ),
            ("pkg/extra.py", "class Extra:\n    pass\n"),
            (
                "pkg/reexports.py",
                r#"from .core import Widget as PublicWidget
from .extra import *
from . import core as namespace

__all__ = ["PublicWidget", "Extra", "namespace"]
"#,
            ),
            (
                "pkg/__init__.py",
                r#"from .reexports import *

__all__ = ["PublicWidget", "Extra", "namespace"]
"#,
            ),
        ],
        &[
            ("pkg/reexports.py", ".extra", "pkg/extra.py"),
            ("pkg/reexports.py", ".core", "pkg/core.py"),
            ("pkg/__init__.py", ".reexports", "pkg/reexports.py"),
        ],
    );
    let spec =
        crate::semantic_indexer_manifest::pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let entrypoint = std::env::var_os("SNIFF_TEST_SCIP_PYTHON_ENTRYPOINT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            crate::semantic_indexer_installation::SemanticIndexerStore::for_user()
                .unwrap()
                .verify(spec)
                .unwrap()
                .entrypoint
        });
    let output = fixture.root.path().join("index.scip");
    let mut command = std::process::Command::new(if cfg!(windows) { "node.exe" } else { "node" });
    if cfg!(windows) {
        command
            .arg("--preserve-symlinks")
            .arg("--preserve-symlinks-main")
            .arg("-e")
            .arg(crate::semantic_indexer_runner::WINDOWS_SCIP_PYTHON_BOOTSTRAP)
            .arg(&entrypoint);
    } else {
        command.arg(&entrypoint);
    }
    command
        .arg("index")
        .arg(".")
        .arg("--project-name")
        .arg("sniff-python-public-surface")
        .arg("--project-version")
        .arg("_")
        .arg("--output")
        .arg(&output)
        .arg("--quiet");
    if cfg!(windows) {
        let environment = fixture.root.path().join("python-environment.json");
        std::fs::write(&environment, "[]").unwrap();
        command.arg("--environment").arg(environment);
    }
    let status = command.current_dir(fixture.root.path()).status().unwrap();
    assert!(status.success());
    assert!(output.is_file());
    let expected_languages = fixture
        .source
        .source_files
        .iter()
        .map(|file| {
            (
                RepositoryPath(file.repository_path.clone()),
                file.language.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let live_index = crate::semantic_index_scip::ingest_scip_file_with_expected_languages(
        fixture.root.path(),
        &output,
        Some(&expected_languages),
        Some(SemanticPositionEncoding::Utf32),
    )
    .unwrap();
    fixture
        .indexes
        .insert(SemanticIndexerKind::Python, live_index);
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Python]);
    let required_paths = fixture_required_paths(&fixture.source);

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();

    let parse_signatures = snapshot
        .symbols
        .iter()
        .flat_map(|symbol| &symbol.symbol.signatures)
        .filter(|signature| signature.text.contains("def parse("))
        .map(|signature| signature.text.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(parse_signatures.len(), 2, "{parse_signatures:#?}");
    assert!(
        parse_signatures
            .iter()
            .all(|signature| signature.contains("@overload"))
    );
    assert_eq!(snapshot.public_reexport_hop_count, 5);
    assert!(snapshot.public_bindings.iter().any(|binding| {
        binding.repository_path == "pkg/__init__.py"
            && binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
            && binding.reexport_path.len() == 2
    }));
    assert!(snapshot.symbols.iter().all(|symbol| {
        symbol.symbol.display_name.as_deref() != Some("_PRIVATE_CONSTANT")
            || !symbol.is_public_surface
    }));
    let label_declaration = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "pkg/core.py")
        .and_then(|file| {
            file.public_declarations.iter().find(|declaration| {
                declaration.owner.as_deref() == Some("Widget") && declaration.name == "label"
            })
        })
        .expect("instance field source declaration");
    let label_binding = snapshot
        .public_bindings
        .iter()
        .find(|binding| binding.declaration_unit_id == label_declaration.declaration_unit_id)
        .expect("instance field compiler binding");
    assert!(snapshot.symbols.iter().any(|symbol| {
        symbol.symbol.symbol_id == label_binding.symbol_id && symbol.is_public_surface
    }));
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
fn semantic_validation_rejects_a_recommitted_omitted_reexport_expansion() {
    let fixture = reexport_fixture();
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]);
    let required_paths = fixture_required_paths(&fixture.source);
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();
    let index = snapshot
        .public_bindings
        .iter()
        .position(|binding| {
            binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
        })
        .unwrap();
    snapshot.public_bindings.remove(index);
    snapshot.public_binding_count = snapshot.public_bindings.len();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap_err();

    assert!(error.contains("expansion set is incomplete"), "{error}");
}

#[test]
fn semantic_validation_rejects_a_recommitted_omitted_reexport_hop() {
    let fixture = reexport_fixture();
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]);
    let required_paths = fixture_required_paths(&fixture.source);
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();
    snapshot.public_reexport_hops.pop();
    snapshot.public_reexport_hop_count = snapshot.public_reexport_hops.len();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap_err();

    assert!(error.contains("omitted a public re-export hop"), "{error}");
}

#[test]
fn compiler_reexport_cycles_fail_closed() {
    let fixture = typescript_surface_fixture(
        &[
            ("src/a.ts", "export * from \"./b\";\n"),
            ("src/b.ts", "export * from \"./a\";\n"),
        ],
        &[
            ("src/a.ts", "./b", "src/b.ts"),
            ("src/b.ts", "./a", "src/a.ts"),
        ],
    );

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("cyclic public re-export path"), "{error}");
}

#[test]
fn compiler_reexport_missing_target_document_fails_closed() {
    let mut fixture = reexport_fixture();
    fixture
        .indexes
        .get_mut(&SemanticIndexerKind::TypeScriptJavaScript)
        .unwrap()
        .documents
        .remove(&RepositoryPath("src/target.ts".to_string()));

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("omitted changed source document"), "{error}");
}

#[test]
fn compiler_reexport_external_module_identity_fails_closed() {
    let mut fixture = reexport_fixture();
    let index = fixture
        .indexes
        .get_mut(&SemanticIndexerKind::TypeScriptJavaScript)
        .unwrap();
    index
        .symbols
        .get_mut(&SemanticSymbolId(
            "typescript module src/target.ts".to_string(),
        ))
        .unwrap()
        .origin = SemanticSymbolOrigin::External;

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("unambiguous repository module"), "{error}");
}

#[test]
fn compiler_reexport_ambiguous_module_target_fails_closed() {
    let mut fixture = reexport_fixture();
    let index = fixture
        .indexes
        .get_mut(&SemanticIndexerKind::TypeScriptJavaScript)
        .unwrap();
    index
        .symbols
        .get_mut(&SemanticSymbolId(
            "typescript module src/target.ts".to_string(),
        ))
        .unwrap()
        .definitions
        .insert(SemanticLocation {
            document: RepositoryPath("src/barrel.ts".to_string()),
            range: range(0, 0, 1),
        });

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("2 module document(s)"), "{error}");
}

#[test]
fn compiler_namespace_reexport_empty_target_fails_closed() {
    let fixture = typescript_surface_fixture(
        &[
            (
                "src/root.ts",
                "export * as emptyNamespace from \"./empty\";\n",
            ),
            ("src/empty.ts", "export {};\n"),
        ],
        &[("src/root.ts", "./empty", "src/empty.ts")],
    );

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("no enumerable bindings"), "{error}");
}

#[test]
fn compiler_reexport_distinct_wildcard_symbols_fail_closed() {
    let fixture = typescript_surface_fixture(
        &[
            (
                "src/root.ts",
                "export * from \"./left\"; export * from \"./right\";\n",
            ),
            ("src/left.ts", "export const duplicate = 1;\n"),
            ("src/right.ts", "export const duplicate = 2;\n"),
        ],
        &[
            ("src/root.ts", "./left", "src/left.ts"),
            ("src/root.ts", "./right", "src/right.ts"),
        ],
    );

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("ambiguous wildcard export"), "{error}");
}

#[test]
fn direct_export_overrides_same_named_wildcard_slot() {
    let fixture = typescript_surface_fixture(
        &[
            (
                "src/root.ts",
                "export const duplicate = 3; export * from \"./target\";\n",
            ),
            ("src/target.ts", "export const duplicate = 1;\n"),
        ],
        &[("src/root.ts", "./target", "src/target.ts")],
    );

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();

    assert!(snapshot.public_bindings.iter().all(|binding| {
        binding.repository_path != "src/root.ts"
            || binding.binding != HistoricalV2SemanticPublicBindingKind::ReexportExpansion
    }));
}

#[test]
fn semantic_validation_rejects_recommitted_missing_public_binding() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    snapshot.public_bindings.clear();
    snapshot.public_binding_count = 0;
    snapshot.symbols[0].is_public_surface = false;
    snapshot.public_symbol_count = 0;
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
    )
    .unwrap_err();

    assert!(error.contains("has no compiler binding"), "{error}");
}

#[test]
fn semantic_validation_rejects_recommitted_binding_to_another_symbol() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    snapshot.public_bindings[0].symbol_id = "invented compiler symbol".to_string();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
    )
    .unwrap_err();

    assert!(error.contains("missing symbol"), "{error}");
}

#[test]
fn semantic_validation_rejects_another_real_symbol_at_the_wrong_source_range() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    let mut other = snapshot.symbols[0].clone();
    other.symbol.symbol_id = "rust fixture secondary".to_string();
    other.symbol.provider_identity = "rust fixture secondary".to_string();
    other.symbol.display_name = Some("secondary".to_string());
    other.symbol.definitions = vec![super::super::IntentionalBoundarySemanticRange {
        repository_path: "src/lib.rs".to_string(),
        start_line_zero_based: 0,
        start_character_zero_based: 0,
        end_line_zero_based: 0,
        end_character_zero_based: 3,
    }];
    snapshot.symbols[0].is_public_surface = false;
    snapshot.symbols.push(other.clone());
    snapshot.symbol_count = snapshot.symbols.len();
    snapshot.public_bindings[0].symbol_id = other.symbol.symbol_id;
    snapshot.public_bindings[0].compiler_anchor = other.symbol.definitions[0].clone();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
    )
    .unwrap_err();

    assert!(error.contains("changed compiler identity"), "{error}");
}

#[test]
fn source_byte_positions_respect_each_compiler_encoding() {
    let source = "éPublic";
    assert_eq!(
        semantic_position_at_byte(source, 2, SemanticPositionEncoding::Utf8).unwrap(),
        SemanticPosition {
            line: 0,
            character: 2
        }
    );
    assert_eq!(
        semantic_position_at_byte(source, 2, SemanticPositionEncoding::Utf16).unwrap(),
        SemanticPosition {
            line: 0,
            character: 1
        }
    );
    assert_eq!(
        semantic_position_at_byte(source, 2, SemanticPositionEncoding::Utf32).unwrap(),
        SemanticPosition {
            line: 0,
            character: 1
        }
    );
}

#[test]
fn semantic_validation_rejects_a_recommitted_missing_method_symbol() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    snapshot.symbols.clear();
    snapshot.symbol_count = 0;
    snapshot.public_symbol_count = 0;
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    assert!(
        validation::validate_snapshot(
            &fixture.source,
            &snapshot,
            &fixture_changed_indexers(),
            &fixture_required_paths(&fixture.source),
        )
        .unwrap_err()
        .contains("references a missing symbol")
    );
}

#[test]
fn repository_rejection_becomes_hash_bound_terminal_evidence() {
    let detail = "rust-analyzer rejected the repository";
    let stdout = "compiler output";
    let stderr = "invalid manifest";
    let evidence = indexer_failure_evidence(
        HistoricalV2SemanticSnapshotSide::Base,
        &"a".repeat(40),
        SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::RepositoryRejected,
            phase: SemanticIndexerRunPhase::Execution,
            indexer: Some(SemanticIndexerKind::Rust),
            detail: detail.to_string(),
            process: Some(Box::new(SemanticIndexerProcessEvidence {
                status_code: Some(1),
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
                stdout_sha256: sha256(stdout.as_bytes()),
                stderr_sha256: sha256(stderr.as_bytes()),
                timed_out: false,
                memory_limit_exceeded: false,
                process_limit_exceeded: false,
            })),
        },
    )
    .unwrap();
    let exclusion =
        seal_semantic_census_exclusion(&"b".repeat(64), &"c".repeat(64), vec![evidence]).unwrap();

    assert_eq!(
        exclusion.reasons,
        vec![HistoricalV2SemanticCensusExclusionReason::CompilerIndexerRejectedRepository]
    );
    assert_eq!(
        exclusion.failures[0].indexer,
        Some(IntentionalBoundaryIndexerKind::Rust)
    );
    assert_eq!(
        exclusion.failures[0]
            .process
            .as_ref()
            .unwrap()
            .stderr_sha256,
        sha256(stderr.as_bytes())
    );
    super::super::validate_historical_v2_semantic_census_exclusion(&exclusion).unwrap();
}

#[test]
fn preparation_repository_rejection_becomes_hash_bound_terminal_evidence() {
    let detail = "no Gradle build project exists at the repository root";
    let evidence = indexer_failure_evidence(
        HistoricalV2SemanticSnapshotSide::Patched,
        &"a".repeat(40),
        SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::RepositoryRejected,
            phase: SemanticIndexerRunPhase::Preparation,
            indexer: Some(SemanticIndexerKind::Kotlin),
            detail: detail.to_string(),
            process: None,
        },
    )
    .unwrap();
    let exclusion =
        seal_semantic_census_exclusion(&"b".repeat(64), &"c".repeat(64), vec![evidence]).unwrap();

    assert_eq!(
        exclusion.reasons,
        vec![HistoricalV2SemanticCensusExclusionReason::CompilerIndexerRejectedRepository]
    );
    assert_eq!(
        exclusion.failures[0].indexer,
        Some(IntentionalBoundaryIndexerKind::Kotlin)
    );
    assert_eq!(
        exclusion.failures[0].phase,
        HistoricalV2SemanticCensusFailurePhase::Preparation
    );
    assert!(exclusion.failures[0].process.is_none());
    super::super::validate_historical_v2_semantic_census_exclusion(&exclusion).unwrap();
}

#[test]
fn processless_execution_rejection_cannot_be_sealed() {
    let evidence = indexer_failure_evidence(
        HistoricalV2SemanticSnapshotSide::Base,
        &"a".repeat(40),
        SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::RepositoryRejected,
            phase: SemanticIndexerRunPhase::Execution,
            indexer: Some(SemanticIndexerKind::Rust),
            detail: "indexer execution did not provide process evidence".to_string(),
            process: None,
        },
    )
    .unwrap();

    let error = seal_semantic_census_exclusion(&"b".repeat(64), &"c".repeat(64), vec![evidence])
        .unwrap_err();
    assert!(error.detail.contains("indexer rejection evidence"));
}

#[test]
fn processless_output_validation_failure_cannot_be_sealed() {
    let evidence = indexer_failure_evidence(
        HistoricalV2SemanticSnapshotSide::Base,
        &"a".repeat(40),
        SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::IncompleteOutput,
            phase: SemanticIndexerRunPhase::OutputValidation,
            indexer: Some(SemanticIndexerKind::Go),
            detail: "successful compiler output was not retained".to_string(),
            process: None,
        },
    )
    .unwrap();

    let error = seal_semantic_census_exclusion(&"b".repeat(64), &"c".repeat(64), vec![evidence])
        .unwrap_err();
    assert!(error.detail.contains("incomplete output process status"));
}

#[test]
fn processless_snapshot_assembly_failure_is_terminal_evidence() {
    let evidence = indexer_failure_evidence(
        HistoricalV2SemanticSnapshotSide::Patched,
        &"a".repeat(40),
        SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::IncompleteOutput,
            phase: SemanticIndexerRunPhase::SnapshotAssembly,
            indexer: Some(SemanticIndexerKind::Go),
            detail: "bounded Go shard merge omitted a required document".to_string(),
            process: None,
        },
    )
    .unwrap();

    let exclusion =
        seal_semantic_census_exclusion(&"b".repeat(64), &"c".repeat(64), vec![evidence]).unwrap();
    assert_eq!(
        exclusion.failures[0].phase,
        HistoricalV2SemanticCensusFailurePhase::SnapshotAssembly
    );
    assert!(exclusion.failures[0].process.is_none());
}

#[test]
fn infrastructure_failure_cannot_be_sealed_as_candidate_exclusion() {
    let error = indexer_failure_evidence(
        HistoricalV2SemanticSnapshotSide::Patched,
        &"a".repeat(40),
        SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            phase: SemanticIndexerRunPhase::InstallationVerification,
            indexer: Some(SemanticIndexerKind::Python),
            detail: "pinned scip-python installation is unavailable".to_string(),
            process: None,
        },
    )
    .unwrap_err();

    assert_eq!(error.stage, HistoricalV2SlotStage::SemanticCensus);
    assert_eq!(
        error.kind,
        HistoricalV2SlotStageErrorKind::InfrastructureUnavailable
    );
}

#[test]
fn semantic_exclusion_commits_all_sides_and_rejects_tampering() {
    let mut failures = Vec::new();
    let base = resolve_snapshot_build(
        HistoricalV2SemanticSnapshotSide::Base,
        &"a".repeat(40),
        Err("base compiler census omitted a method".to_string()),
        &mut failures,
    );
    let patched = resolve_snapshot_build(
        HistoricalV2SemanticSnapshotSide::Patched,
        &"b".repeat(40),
        Err("patched compiler census invented a symbol".to_string()),
        &mut failures,
    );
    assert!(base.is_none() && patched.is_none());
    let mut exclusion =
        seal_semantic_census_exclusion(&"c".repeat(64), &"d".repeat(64), failures).unwrap();
    assert_eq!(exclusion.failures.len(), 2);
    assert_eq!(
        exclusion.reasons,
        vec![HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete]
    );

    exclusion.failures[0].revision = "e".repeat(40);
    assert!(super::super::validate_historical_v2_semantic_census_exclusion(&exclusion).is_err());
}

#[test]
fn mixed_language_snapshot_retains_every_indexer_failure() {
    let mut failures = Vec::new();
    let mut stage_errors = Vec::new();
    let indexes = resolve_indexer_run(
        HistoricalV2SemanticSnapshotSide::Base,
        &"a".repeat(40),
        Ok(SemanticIndexerBatchOutcome {
            indexes: BTreeMap::new(),
            failures: vec![
                SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                    phase: SemanticIndexerRunPhase::RepositoryValidation,
                    indexer: Some(SemanticIndexerKind::Kotlin),
                    detail: "Android Gradle module is unsupported".to_string(),
                    process: None,
                },
                SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::IncompleteOutput,
                    phase: SemanticIndexerRunPhase::OutputValidation,
                    indexer: Some(SemanticIndexerKind::Rust),
                    detail: "rust-analyzer omitted a source document".to_string(),
                    process: Some(Box::new(SemanticIndexerProcessEvidence {
                        status_code: Some(0),
                        stdout: String::new(),
                        stderr: String::new(),
                        stdout_sha256: sha256(b""),
                        stderr_sha256: sha256(b""),
                        timed_out: false,
                        memory_limit_exceeded: false,
                        process_limit_exceeded: false,
                    })),
                },
            ],
        }),
        &mut failures,
        &mut stage_errors,
    );

    assert!(indexes.is_none());
    assert!(stage_errors.is_empty());
    assert_eq!(failures.len(), 2);
    let exclusion =
        seal_semantic_census_exclusion(&"b".repeat(64), &"c".repeat(64), failures).unwrap();
    assert_eq!(
        exclusion.reasons,
        vec![
            HistoricalV2SemanticCensusExclusionReason::UnsupportedProjectShape,
            HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete,
        ]
    );
}

#[test]
fn one_infrastructure_failure_prevents_mixed_batch_exclusion() {
    let mut failures = Vec::new();
    let mut stage_errors = Vec::new();
    let indexes = resolve_indexer_run(
        HistoricalV2SemanticSnapshotSide::Patched,
        &"a".repeat(40),
        Ok(SemanticIndexerBatchOutcome {
            indexes: BTreeMap::new(),
            failures: vec![
                SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                    phase: SemanticIndexerRunPhase::RepositoryValidation,
                    indexer: Some(SemanticIndexerKind::Kotlin),
                    detail: "unsupported project".to_string(),
                    process: None,
                },
                SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::InfrastructureFailed,
                    phase: SemanticIndexerRunPhase::Cleanup,
                    indexer: Some(SemanticIndexerKind::Rust),
                    detail: "sandbox cleanup failed".to_string(),
                    process: None,
                },
            ],
        }),
        &mut failures,
        &mut stage_errors,
    );

    assert!(indexes.is_none());
    assert_eq!(failures.len(), 1);
    assert_eq!(stage_errors.len(), 1);
    assert_eq!(
        combine_stage_errors(stage_errors).kind,
        HistoricalV2SlotStageErrorKind::InfrastructureFailed
    );
}

fn fixture_changed_indexers() -> BTreeSet<SemanticIndexerKind> {
    BTreeSet::from([SemanticIndexerKind::Rust])
}

#[test]
fn unchanged_compiler_invisible_document_is_explicitly_excluded() {
    let mut fixture = fixture();
    let index = fixture.indexes.get_mut(&SemanticIndexerKind::Rust).unwrap();
    index.documents.clear();
    index.symbols.clear();

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &BTreeSet::new(),
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.resolved_method_count, 0);
    assert_eq!(snapshot.compiler_excluded_method_count, 1);
    assert!(matches!(
        &snapshot.methods[0].status,
        HistoricalV2SemanticMethodStatus::CompilerExcluded { reason }
            if reason == UNCHANGED_DOCUMENT_EXCLUSION
    ));
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &fixture_changed_indexers(),
        &BTreeSet::new(),
    )
    .unwrap();
}

#[test]
fn changed_compiler_invisible_document_still_fails_closed() {
    let mut fixture = fixture();
    let index = fixture.indexes.get_mut(&SemanticIndexerKind::Rust).unwrap();
    index.documents.clear();
    index.symbols.clear();

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("omitted changed source document src/lib.rs"));
}

#[test]
fn untouched_language_methods_are_explicitly_excluded_without_an_indexer() {
    let fixture = fixture();
    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    )
    .unwrap();

    assert!(snapshot.indexers.is_empty());
    assert_eq!(snapshot.compiler_excluded_method_count, 1);
    assert!(matches!(
        &snapshot.methods[0].status,
        HistoricalV2SemanticMethodStatus::CompilerExcluded { reason }
            if reason == UNTOUCHED_LANGUAGE_EXCLUSION
    ));
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &BTreeSet::new(),
        &BTreeSet::new(),
    )
    .unwrap();
}

#[test]
fn renamed_source_requires_the_exact_old_and_new_documents() {
    let fixture = fixture();
    let mut patched = fixture.source.clone();
    patched.source_files[0].repository_path = "src/renamed.rs".to_string();
    let scope = derive_semantic_scope(
        &[super::super::HistoricalChangedPath {
            status: "R100".to_string(),
            previous_path: Some("src/lib.rs".to_string()),
            path: "src/renamed.rs".to_string(),
        }],
        &fixture.source,
        &patched,
    )
    .unwrap();

    assert_eq!(scope.changed_indexers, fixture_changed_indexers());
    assert_eq!(
        scope.base_required_paths,
        BTreeSet::from(["src/lib.rs".to_string()])
    );
    assert_eq!(
        scope.patched_required_paths,
        BTreeSet::from(["src/renamed.rs".to_string()])
    );
}

#[test]
fn empty_revision_does_not_require_an_indexer_for_a_changed_language() {
    let fixture = fixture();
    let mut source = fixture.source.clone();
    source.source_files.clear();
    source.source_file_count = 0;
    source.method_counts_by_language.clear();
    source.method_count = 0;
    source.public_declaration_count = 0;

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &source,
        &[],
        &fixture_changed_indexers(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    )
    .unwrap();

    assert!(snapshot.indexers.is_empty());
    assert!(snapshot.methods.is_empty());
    validation::validate_snapshot(
        &source,
        &snapshot,
        &fixture_changed_indexers(),
        &BTreeSet::new(),
    )
    .unwrap();
}

#[test]
fn cross_language_rename_scopes_each_revision_to_its_own_document() {
    let fixture = fixture();
    let mut patched = fixture.source.clone();
    patched.source_files[0].repository_path = "src/process.py".to_string();
    patched.source_files[0].language = "python".to_string();
    let scope = derive_semantic_scope(
        &[super::super::HistoricalChangedPath {
            status: "R100".to_string(),
            previous_path: Some("src/lib.rs".to_string()),
            path: "src/process.py".to_string(),
        }],
        &fixture.source,
        &patched,
    )
    .unwrap();

    assert_eq!(
        scope.changed_indexers,
        BTreeSet::from([SemanticIndexerKind::Python, SemanticIndexerKind::Rust])
    );
    assert_eq!(
        scope.base_required_paths,
        BTreeSet::from(["src/lib.rs".to_string()])
    );
    assert_eq!(
        scope.patched_required_paths,
        BTreeSet::from(["src/process.py".to_string()])
    );
}

#[test]
fn semantic_validation_rejects_recommitted_required_document_scope_tampering() {
    let fixture = fixture();
    let required_paths = fixture_required_paths(&fixture.source);
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();
    let original_hash = snapshot.semantic_snapshot_sha256.clone();
    snapshot.required_document_paths.clear();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();
    assert_ne!(snapshot.semantic_snapshot_sha256, original_hash);

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &fixture_changed_indexers(),
        &required_paths,
    )
    .unwrap_err();

    assert!(error.contains("semantic snapshot identity changed"));
}

#[test]
fn semantic_census_hash_binds_the_changed_indexer_scope() {
    let fixture = fixture();
    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture_changed_indexers(),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    let mut census = HistoricalV2SemanticCensus {
        schema_version: HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_census_contract: SEMANTIC_CENSUS_CONTRACT.to_string(),
        canonical_repository: "example/repo".to_string(),
        materialization_sha256: "a".repeat(64),
        source_census_sha256: "b".repeat(64),
        changed_indexers: vec![IntentionalBoundaryIndexerKind::Rust],
        base: snapshot.clone(),
        patched: snapshot,
        semantic_census_sha256: String::new(),
    };
    let original_hash = semantic_census_sha256(&census).unwrap();

    census.changed_indexers = vec![IntentionalBoundaryIndexerKind::Python];

    assert_ne!(semantic_census_sha256(&census).unwrap(), original_hash);
}

fn fixture_required_paths(source: &HistoricalV2SourceSnapshotCensus) -> BTreeSet<String> {
    source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
        .map(|file| file.repository_path.clone())
        .collect()
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
            semantic_coverage: HistoricalV2SourceSemanticCoverage::Required,
            methods: vec![super::super::HistoricalV2SourceMethod {
                parser_unit_id: "h2m-v1:fixture".to_string(),
                symbol_name: method.name.clone(),
                start_line: method.start_line,
                end_line: method.end_line,
                source_sha256: sha256(method.source.as_bytes()),
                is_exported: method.is_exported,
            }],
            public_surface_coverage: super::super::HistoricalV2PublicSurfaceCoverage::Complete,
            public_declarations: vec![super::super::HistoricalV2SourcePublicDeclaration {
                surface_unit_id: "public-process-surface".to_string(),
                declaration_unit_id: "public-process-declaration".to_string(),
                name: "process".to_string(),
                target_name: "process".to_string(),
                owner: None,
                namespace: super::super::HistoricalV2SourcePublicNamespace::Module,
                kind: super::super::HistoricalV2SourcePublicSymbolKind::Callable,
                binding: super::super::HistoricalV2SourcePublicBindingKind::Definition,
                source_module: None,
                exposed_identifier: super::super::HistoricalV2SourceByteRange { start: 7, end: 14 },
                exposed_identifier_positions: source_identifier_positions(0, 7, 14),
                identifier: super::super::HistoricalV2SourceByteRange { start: 7, end: 14 },
                identifier_positions: source_identifier_positions(0, 7, 14),
            }],
            public_reexports: Vec::new(),
        }],
        source_file_count: 1,
        method_counts_by_language: BTreeMap::from([("rust".to_string(), 1)]),
        method_count: 1,
        public_declaration_count: 1,
        public_reexport_count: 0,
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
        signatures: BTreeSet::new(),
        owner: None,
        definitions: BTreeSet::from([definition]),
        visibility: SemanticVisibility::Public,
        surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
        origin: SemanticSymbolOrigin::Repository,
        ambiguity_notes: Vec::new(),
    };
    let index = SemanticIndex {
        format_version: crate::semantic_index::SEMANTIC_INDEX_FORMAT_VERSION,
        repository_root: root.path().to_string_lossy().replace('\\', "/"),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            arguments: Vec::new(),
            source_text_encoding: Some(SemanticTextEncoding::Utf8),
            invocations: vec![crate::semantic_index::SemanticIndexerInvocation {
                arguments: Vec::new(),
                context: Default::default(),
                contribution: crate::semantic_index::SemanticIndexerContribution::CompleteIndex,
                output_sha256: "0".repeat(64),
            }],
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

fn reference_fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("src")).unwrap();
    let source_text = "const internal = 1; export { internal as publicName };\n";
    let absolute = root.path().join("src/index.ts");
    std::fs::write(&absolute, source_text).unwrap();
    let files = vec![
        crate::parser::parse_source_checked(&absolute.to_string_lossy(), source_text.as_bytes())
            .unwrap(),
    ];
    let (_, public_declarations, public_reexports) =
        super::super::history_v2_source_census::source_public_declarations(
            "src/index.ts",
            "typescript",
            source_text.as_bytes(),
        )
        .unwrap();
    let source = HistoricalV2SourceSnapshotCensus {
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        parser_census_sha256: "c".repeat(64),
        tracked_entry_count: 1,
        source_files: vec![super::super::HistoricalV2SourceFile {
            repository_path: "src/index.ts".to_string(),
            object_id: "d".repeat(40),
            byte_length: source_text.len() as u64,
            source_sha256: sha256(source_text.as_bytes()),
            non_whitespace_lines: 1,
            language: "typescript".to_string(),
            semantic_coverage: HistoricalV2SourceSemanticCoverage::Required,
            methods: Vec::new(),
            public_surface_coverage: super::super::HistoricalV2PublicSurfaceCoverage::Complete,
            public_declarations,
            public_reexports,
        }],
        source_file_count: 1,
        method_counts_by_language: BTreeMap::from([("typescript".to_string(), 0)]),
        method_count: 0,
        public_declaration_count: 1,
        public_reexport_count: 0,
        snapshot_census_sha256: "e".repeat(64),
    };
    let document_path = RepositoryPath("src/index.ts".to_string());
    let symbol_id = SemanticSymbolId("typescript fixture internal".to_string());
    let definition = SemanticLocation {
        document: document_path.clone(),
        range: range(0, 6, 14),
    };
    let symbol = SemanticSymbol {
        id: symbol_id.clone(),
        provider_identity: symbol_id.0.clone(),
        display_name: Some("publicName".to_string()),
        kind: SemanticSymbolKind {
            category: SemanticSymbolCategory::Variable,
            provider_name: "variable".to_string(),
        },
        documentation: Vec::new(),
        signatures: BTreeSet::new(),
        owner: None,
        definitions: BTreeSet::from([definition]),
        visibility: SemanticVisibility::Public,
        surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
        origin: SemanticSymbolOrigin::Repository,
        ambiguity_notes: Vec::new(),
    };
    let compiler_anchor = range(0, 41, 51);
    let index = SemanticIndex {
        format_version: crate::semantic_index::SEMANTIC_INDEX_FORMAT_VERSION,
        repository_root: root.path().to_string_lossy().replace('\\', "/"),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            arguments: Vec::new(),
            source_text_encoding: Some(SemanticTextEncoding::Utf8),
            invocations: vec![crate::semantic_index::SemanticIndexerInvocation {
                arguments: Vec::new(),
                context: Default::default(),
                contribution: crate::semantic_index::SemanticIndexerContribution::CompleteIndex,
                output_sha256: "0".repeat(64),
            }],
            diagnostics: Vec::new(),
        },
        documents: BTreeMap::from([(
            document_path.clone(),
            SemanticDocument {
                path: document_path,
                language: "typescript".to_string(),
                position_encoding: SemanticPositionEncoding::Utf16,
                embedded_text: None,
                occurrences: vec![SemanticOccurrence {
                    range: compiler_anchor,
                    symbol: Some(symbol_id.clone()),
                    roles: BTreeSet::from([SemanticOccurrenceRole::Read]),
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
        indexes: BTreeMap::from([(SemanticIndexerKind::TypeScriptJavaScript, index)]),
    }
}

fn reexport_fixture() -> Fixture {
    typescript_surface_fixture(
        &[
            (
                "src/root.ts",
                "export * from \"./barrel\"; export * as api from \"./target\";\n",
            ),
            ("src/barrel.ts", "export * from \"./target\";\n"),
            (
                "src/target.ts",
                "export const kept = 1; export default interface Hidden {}\n",
            ),
        ],
        &[
            ("src/root.ts", "./barrel", "src/barrel.ts"),
            ("src/root.ts", "./target", "src/target.ts"),
            ("src/barrel.ts", "./target", "src/target.ts"),
        ],
    )
}

fn typescript_surface_fixture(
    sources: &[(&str, &str)],
    module_targets: &[(&str, &str, &str)],
) -> Fixture {
    compiler_surface_fixture(
        "typescript",
        SemanticIndexerKind::TypeScriptJavaScript,
        SemanticPositionEncoding::Utf16,
        sources,
        module_targets,
    )
}

#[test]
fn python_all_selects_only_the_named_wildcard_binding() {
    let fixture = python_surface_fixture(
        &[
            (
                "pkg/__init__.py",
                "from .target import *\n__all__ = ['kept']\n",
            ),
            ("pkg/target.py", "kept: int = 1\nskipped: int = 2\n"),
        ],
        &[("pkg/__init__.py", ".target", "pkg/target.py")],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Python]);
    let required_paths = fixture_required_paths(&fixture.source);

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();

    let root_expansions = snapshot
        .public_bindings
        .iter()
        .filter(|binding| {
            binding.repository_path == "pkg/__init__.py"
                && binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
        })
        .collect::<Vec<_>>();
    assert_eq!(root_expansions.len(), 1);
    let kept = fixture.source.source_files[1]
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "kept")
        .unwrap();
    assert_eq!(
        root_expansions[0].origin_declaration_unit_id,
        kept.declaration_unit_id
    );
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
fn python_all_name_absent_from_wildcard_target_fails_closed() {
    let fixture = python_surface_fixture(
        &[
            (
                "pkg/__init__.py",
                "from .target import *\n__all__ = ['missing']\n",
            ),
            ("pkg/target.py", "kept: int = 1\n"),
        ],
        &[("pkg/__init__.py", ".target", "pkg/target.py")],
    );

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::Python]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("absent from wildcard target"), "{error}");
}

#[test]
fn python_namespace_import_expands_the_repository_module() {
    let fixture = python_surface_fixture(
        &[
            (
                "pkg/__init__.py",
                "from . import target as api\n__all__ = ['api']\n",
            ),
            ("pkg/target.py", "kept: int = 1\n"),
        ],
        &[("pkg/__init__.py", ".target", "pkg/target.py")],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Python]);
    let required_paths = fixture_required_paths(&fixture.source);

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.public_reexport_hop_count, 1);
    assert_eq!(
        snapshot
            .public_bindings
            .iter()
            .filter(|binding| {
                binding.repository_path == "pkg/__init__.py"
                    && binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
            })
            .count(),
        1
    );
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
fn python_recursive_wildcard_preserves_one_namespace_surface() {
    let fixture = python_surface_fixture(
        &[
            (
                "pkg/__init__.py",
                "from .reexports import *\n__all__ = ['api']\n",
            ),
            (
                "pkg/reexports.py",
                "from . import target as api\n__all__ = ['api']\n",
            ),
            ("pkg/target.py", "first: int = 1\nsecond: str = 'two'\n"),
        ],
        &[
            ("pkg/__init__.py", ".reexports", "pkg/reexports.py"),
            ("pkg/reexports.py", ".target", "pkg/target.py"),
        ],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Python]);
    let required_paths = fixture_required_paths(&fixture.source);

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();

    let root_namespace = snapshot
        .public_bindings
        .iter()
        .filter(|binding| {
            binding.repository_path == "pkg/__init__.py"
                && binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
        })
        .collect::<Vec<_>>();
    assert_eq!(root_namespace.len(), 2);
    assert_eq!(
        root_namespace
            .iter()
            .map(|binding| binding.surface_unit_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        1
    );
    assert_eq!(
        root_namespace
            .iter()
            .map(|binding| binding.symbol_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
fn python_wildcard_after_a_colliding_direct_binding_fails_closed() {
    let fixture = python_surface_fixture(
        &[
            ("pkg/__init__.py", "kept: int = 1\nfrom .target import *\n"),
            ("pkg/target.py", "kept: int = 2\n"),
        ],
        &[("pkg/__init__.py", ".target", "pkg/target.py")],
    );

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::Python]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .expect_err("source-order wildcard overwrite must not produce an inexact public surface");

    assert!(
        error.contains("wildcard overwrites an earlier direct public binding"),
        "{error}"
    );
}

#[test]
fn python_direct_binding_after_a_wildcard_remains_authoritative() {
    let fixture = python_surface_fixture(
        &[
            ("pkg/__init__.py", "from .target import *\nkept: int = 1\n"),
            ("pkg/target.py", "kept: int = 2\n"),
        ],
        &[("pkg/__init__.py", ".target", "pkg/target.py")],
    );

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::Python]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .expect("later direct binding should shadow the wildcard");

    assert!(!snapshot.public_bindings.iter().any(|binding| {
        binding.repository_path == "pkg/__init__.py"
            && binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
    }));
}

#[test]
fn semantic_validation_rejects_a_recommitted_omitted_python_expansion() {
    let fixture = python_surface_fixture(
        &[
            (
                "pkg/__init__.py",
                "from .target import *\n__all__ = ['kept']\n",
            ),
            ("pkg/target.py", "kept: int = 1\n"),
        ],
        &[("pkg/__init__.py", ".target", "pkg/target.py")],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Python]);
    let required_paths = fixture_required_paths(&fixture.source);
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &required_paths,
        &fixture.indexes,
    )
    .unwrap();
    let index = snapshot
        .public_bindings
        .iter()
        .position(|binding| {
            binding.repository_path == "pkg/__init__.py"
                && binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
        })
        .unwrap();
    snapshot.public_bindings.remove(index);
    snapshot.public_binding_count = snapshot.public_bindings.len();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap_err();

    assert!(error.contains("expansion set is incomplete"), "{error}");
}

fn python_surface_fixture(
    sources: &[(&str, &str)],
    module_targets: &[(&str, &str, &str)],
) -> Fixture {
    compiler_surface_fixture(
        "python",
        SemanticIndexerKind::Python,
        SemanticPositionEncoding::Utf32,
        sources,
        module_targets,
    )
}

fn compiler_surface_fixture(
    language: &str,
    indexer: SemanticIndexerKind,
    position_encoding: SemanticPositionEncoding,
    sources: &[(&str, &str)],
    module_targets: &[(&str, &str, &str)],
) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    let mut source_files = Vec::new();
    let mut documents = BTreeMap::new();
    let mut symbols = BTreeMap::new();

    for (ordinal, (repository_path, source_text)) in sources.iter().enumerate() {
        let absolute = root.path().join(repository_path);
        std::fs::create_dir_all(absolute.parent().unwrap()).unwrap();
        std::fs::write(&absolute, source_text).unwrap();
        let record = crate::parser::parse_source_checked(
            &absolute.to_string_lossy(),
            source_text.as_bytes(),
        )
        .unwrap();
        let methods = record
            .methods
            .iter()
            .enumerate()
            .map(
                |(method_ordinal, method)| super::super::HistoricalV2SourceMethod {
                    parser_unit_id: format!("h2m-v1:fixture-{ordinal}-{method_ordinal}"),
                    symbol_name: method.name.clone(),
                    start_line: method.start_line,
                    end_line: method.end_line,
                    source_sha256: sha256(method.source.as_bytes()),
                    is_exported: method.is_exported,
                },
            )
            .collect::<Vec<_>>();
        let (coverage, public_declarations, public_reexports) =
            super::super::history_v2_source_census::source_public_declarations(
                repository_path,
                language,
                source_text.as_bytes(),
            )
            .unwrap();
        let document_path = RepositoryPath((*repository_path).to_string());
        let mut occurrences = Vec::new();
        for declaration in &public_declarations {
            let symbol_id = SemanticSymbolId(format!(
                "{language} declaration {}",
                declaration.declaration_unit_id
            ));
            let definition = SemanticLocation {
                document: document_path.clone(),
                range: semantic_range(identifier_range(declaration, position_encoding)),
            };
            symbols.insert(
                symbol_id.clone(),
                SemanticSymbol {
                    id: symbol_id.clone(),
                    provider_identity: symbol_id.0.clone(),
                    display_name: Some(declaration.name.clone()),
                    kind: SemanticSymbolKind {
                        category: semantic_category(declaration.kind),
                        provider_name: "fixture-declaration".to_string(),
                    },
                    documentation: Vec::new(),
                    signatures: BTreeSet::new(),
                    owner: None,
                    definitions: BTreeSet::from([definition]),
                    visibility: SemanticVisibility::Public,
                    surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
                    origin: SemanticSymbolOrigin::Repository,
                    ambiguity_notes: Vec::new(),
                },
            );
            occurrences.push(SemanticOccurrence {
                range: semantic_range(identifier_range(declaration, position_encoding)),
                symbol: Some(symbol_id),
                roles: BTreeSet::from([match declaration.binding {
                    super::super::HistoricalV2SourcePublicBindingKind::Definition => {
                        SemanticOccurrenceRole::Definition
                    }
                    super::super::HistoricalV2SourcePublicBindingKind::Reference => {
                        SemanticOccurrenceRole::Read
                    }
                }]),
                override_documentation: Vec::new(),
            });
        }
        files.push(record);
        source_files.push(super::super::HistoricalV2SourceFile {
            repository_path: (*repository_path).to_string(),
            object_id: format!("{ordinal:040x}"),
            byte_length: source_text.len() as u64,
            source_sha256: sha256(source_text.as_bytes()),
            non_whitespace_lines: source_text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count(),
            language: language.to_string(),
            semantic_coverage: HistoricalV2SourceSemanticCoverage::Required,
            methods,
            public_surface_coverage: coverage,
            public_declarations,
            public_reexports,
        });
        documents.insert(
            document_path.clone(),
            SemanticDocument {
                path: document_path,
                language: language.to_string(),
                position_encoding,
                embedded_text: None,
                occurrences,
            },
        );
    }

    for (_, _, target_path) in module_targets {
        let symbol_id = SemanticSymbolId(format!("{language} module {target_path}"));
        symbols
            .entry(symbol_id.clone())
            .or_insert_with(|| SemanticSymbol {
                id: symbol_id.clone(),
                provider_identity: symbol_id.0.clone(),
                display_name: Some((*target_path).to_string()),
                kind: SemanticSymbolKind {
                    category: SemanticSymbolCategory::Module,
                    provider_name: "module".to_string(),
                },
                documentation: Vec::new(),
                signatures: BTreeSet::new(),
                owner: None,
                definitions: BTreeSet::from([SemanticLocation {
                    document: RepositoryPath((*target_path).to_string()),
                    range: range(0, 0, 1),
                }]),
                visibility: SemanticVisibility::Public,
                surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
                origin: SemanticSymbolOrigin::Repository,
                ambiguity_notes: Vec::new(),
            });
    }
    for (source_path, source_module, target_path) in module_targets {
        let source_file = source_files
            .iter()
            .find(|file| file.repository_path == *source_path)
            .unwrap();
        let reexport = source_file
            .public_reexports
            .iter()
            .find(|reexport| reexport.source_module == *source_module)
            .unwrap();
        documents
            .get_mut(&RepositoryPath((*source_path).to_string()))
            .unwrap()
            .occurrences
            .push(SemanticOccurrence {
                range: semantic_range(reexport_identifier_range(reexport, position_encoding)),
                symbol: Some(SemanticSymbolId(format!("{language} module {target_path}"))),
                roles: BTreeSet::from([SemanticOccurrenceRole::Read]),
                override_documentation: Vec::new(),
            });
    }

    source_files.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    files.sort_by(|left, right| left.file_path.cmp(&right.file_path));
    let public_declaration_count = source_files
        .iter()
        .map(|file| file.public_declarations.len())
        .sum();
    let public_reexport_count = source_files
        .iter()
        .map(|file| file.public_reexports.len())
        .sum();
    let method_count = source_files.iter().map(|file| file.methods.len()).sum();
    let source = HistoricalV2SourceSnapshotCensus {
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        parser_census_sha256: "c".repeat(64),
        tracked_entry_count: source_files.len(),
        source_file_count: source_files.len(),
        source_files,
        method_counts_by_language: BTreeMap::from([(language.to_string(), method_count)]),
        method_count,
        public_declaration_count,
        public_reexport_count,
        snapshot_census_sha256: "e".repeat(64),
    };
    let index = SemanticIndex {
        format_version: crate::semantic_index::SEMANTIC_INDEX_FORMAT_VERSION,
        repository_root: root.path().to_string_lossy().replace('\\', "/"),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            arguments: Vec::new(),
            source_text_encoding: Some(SemanticTextEncoding::Utf8),
            invocations: vec![crate::semantic_index::SemanticIndexerInvocation {
                arguments: Vec::new(),
                context: Default::default(),
                contribution: crate::semantic_index::SemanticIndexerContribution::CompleteIndex,
                output_sha256: "0".repeat(64),
            }],
            diagnostics: Vec::new(),
        },
        documents,
        symbols,
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
        indexes: BTreeMap::from([(indexer, index)]),
    }
}

fn identifier_range(
    declaration: &super::super::HistoricalV2SourcePublicDeclaration,
    encoding: SemanticPositionEncoding,
) -> super::super::HistoricalV2SourcePositionRange {
    match encoding {
        SemanticPositionEncoding::Utf8 => declaration.identifier_positions.utf8,
        SemanticPositionEncoding::Utf16 => declaration.identifier_positions.utf16,
        SemanticPositionEncoding::Utf32 => declaration.identifier_positions.utf32,
    }
}

fn reexport_identifier_range(
    reexport: &super::super::HistoricalV2SourcePublicReexport,
    encoding: SemanticPositionEncoding,
) -> super::super::HistoricalV2SourcePositionRange {
    match encoding {
        SemanticPositionEncoding::Utf8 => reexport.identifier_positions.utf8,
        SemanticPositionEncoding::Utf16 => reexport.identifier_positions.utf16,
        SemanticPositionEncoding::Utf32 => reexport.identifier_positions.utf32,
    }
}

fn semantic_category(
    kind: super::super::HistoricalV2SourcePublicSymbolKind,
) -> SemanticSymbolCategory {
    match kind {
        super::super::HistoricalV2SourcePublicSymbolKind::CompilerDefined
        | super::super::HistoricalV2SourcePublicSymbolKind::Variable => {
            SemanticSymbolCategory::Variable
        }
        super::super::HistoricalV2SourcePublicSymbolKind::Callable => {
            SemanticSymbolCategory::Callable
        }
        super::super::HistoricalV2SourcePublicSymbolKind::Method => SemanticSymbolCategory::Method,
        super::super::HistoricalV2SourcePublicSymbolKind::Type => SemanticSymbolCategory::Type,
        super::super::HistoricalV2SourcePublicSymbolKind::Module => SemanticSymbolCategory::Module,
        super::super::HistoricalV2SourcePublicSymbolKind::Field => {
            SemanticSymbolCategory::FieldOrProperty
        }
        super::super::HistoricalV2SourcePublicSymbolKind::Constant => {
            SemanticSymbolCategory::Constant
        }
    }
}

fn semantic_range(range: super::super::HistoricalV2SourcePositionRange) -> SemanticSourceRange {
    SemanticSourceRange {
        start: SemanticPosition {
            line: range.start.line_zero_based,
            character: range.start.character_zero_based,
        },
        end: SemanticPosition {
            line: range.end.line_zero_based,
            character: range.end.character_zero_based,
        },
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

fn source_identifier_positions(
    line: u32,
    start: u32,
    end: u32,
) -> super::super::HistoricalV2SourceIdentifierPositions {
    let range = super::super::HistoricalV2SourcePositionRange {
        start: super::super::HistoricalV2SourcePosition {
            line_zero_based: line,
            character_zero_based: start,
        },
        end: super::super::HistoricalV2SourcePosition {
            line_zero_based: line,
            character_zero_based: end,
        },
    };
    super::super::HistoricalV2SourceIdentifierPositions {
        utf8: range,
        utf16: range,
        utf32: range,
    }
}
