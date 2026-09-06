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

fn fixture_cargo_project_model(
    revision: &str,
    inventory_sha256: &str,
    rust_library_root: Option<&str>,
) -> super::super::IntentionalBoundaryProjectModelCensus {
    use super::super::{
        IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestTarget,
        IntentionalBoundaryProjectModelProvider, IntentionalBoundaryProjectModelTarget,
        IntentionalBoundaryProjectModelTargetStatus,
    };

    let targets = rust_library_root
        .map(|repository_path| {
            vec![IntentionalBoundaryProjectModelTarget {
                target_id: "fixture-target".to_string(),
                execution_id: "fixture-execution".to_string(),
                provider: IntentionalBoundaryProjectModelProvider::CargoMetadata,
                manifest_repository_path: "Cargo.toml".to_string(),
                manifest_object_id: "0".repeat(40),
                package_name: "fixture".to_string(),
                package_version: "0.1.0".to_string(),
                target_name: "fixture".to_string(),
                provider_kinds: vec!["lib".to_string()],
                provider_output_types: vec!["lib".to_string()],
                source_repository_paths: vec![repository_path.to_string()],
                producer_tasks: Vec::new(),
                required_features: Vec::new(),
                target_status: IntentionalBoundaryProjectModelTargetStatus::Boundary {
                    declaration_kind: IntentionalBoundaryManifestDeclarationKind::PublishedModule,
                    target: IntentionalBoundaryManifestTarget::RepositoryPath {
                        repository_path: repository_path.to_string(),
                    },
                },
            }]
        })
        .unwrap_or_default();
    super::super::IntentionalBoundaryProjectModelCensus {
        schema_version: super::super::INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
        project_model_contract: "fixture".to_string(),
        repository: "example/repo".to_string(),
        revision: revision.to_string(),
        inventory_sha256: inventory_sha256.to_string(),
        executions: Vec::new(),
        targets,
        execution_count_by_provider: BTreeMap::new(),
        target_count_by_status: BTreeMap::new(),
        project_model_census_sha256: "f".repeat(64),
    }
}

fn fixture_node_package_surfaces(
    revision: &str,
    inventory_sha256: &str,
    compiler_root: Option<(&str, &str)>,
) -> super::super::HistoricalV2NodePackageSurfaceCensus {
    let (documents, exposures, exposure_count_by_entry_kind) = compiler_root
        .map(|(target_repository_path, target_object_id)| {
            let range = super::super::IntentionalBoundarySemanticRange {
                repository_path: "package.json".to_string(),
                start_line_zero_based: 0,
                start_character_zero_based: 0,
                end_line_zero_based: 0,
                end_character_zero_based: 1,
            };
            let entry_kind = super::super::HistoricalV2NodePackageEntryKind::Exports;
            (
                vec![super::super::HistoricalV2NodePackageDocument {
                    manifest_repository_path: "package.json".to_string(),
                    manifest_object_id: "8".repeat(40),
                    source_sha256: "7".repeat(64),
                    package_name: Some("fixture".to_string()),
                    private: false,
                    has_exports: true,
                    exposure_count: 1,
                }],
                vec![super::super::HistoricalV2NodePackageExposure {
                    exposure_id: "fixture-node-package-exposure".to_string(),
                    surface_slot_id: "fixture-node-package-surface-slot".to_string(),
                    manifest_repository_path: "package.json".to_string(),
                    manifest_object_id: "8".repeat(40),
                    package_name: Some("fixture".to_string()),
                    entry_kind,
                    public_subpath: ".".to_string(),
                    public_subpath_location: range.clone(),
                    conditions: Vec::new(),
                    fallback_indices: Vec::new(),
                    target_repository_path: target_repository_path.to_string(),
                    target_location: range,
                    target_status:
                        super::super::HistoricalV2NodePackageTargetStatus::TrackedRegularFile,
                    target_object_id: Some(target_object_id.to_string()),
                }],
                BTreeMap::from([(entry_kind, 1)]),
            )
        })
        .unwrap_or_default();
    super::super::HistoricalV2NodePackageSurfaceCensus {
        schema_version: super::super::HISTORICAL_V2_NODE_PACKAGE_SURFACE_CENSUS_SCHEMA_VERSION,
        contract: "fixture".to_string(),
        repository: "example/repo".to_string(),
        revision: revision.to_string(),
        inventory_sha256: inventory_sha256.to_string(),
        documents,
        exposures,
        exposure_count_by_entry_kind,
        census_sha256: "9".repeat(64),
    }
}

fn fixture_python_distribution_surfaces(
    revision: &str,
    inventory_sha256: &str,
    sources: Option<&[(&str, &str)]>,
) -> super::super::HistoricalV2PythonDistributionSurfaceCensus {
    let (distributions, modules, module_count_by_kind) = sources
        .map(|sources| {
            let distribution_id = "fixture-python-distribution".to_string();
            let modules = sources
                .iter()
                .map(|(repository_path, source)| {
                    let (import_name, kind) = python_fixture_module_identity(repository_path);
                    super::super::HistoricalV2PythonDistributionModule {
                        module_exposure_id: format!("fixture-python-module-{import_name}-{kind:?}"),
                        surface_slot_id: format!("fixture-python-slot-{import_name}-{kind:?}"),
                        distribution_id: distribution_id.clone(),
                        normalized_distribution_name: "fixture".to_string(),
                        is_distribution_root: !import_name.contains('.'),
                        import_name,
                        kind,
                        archive_member_path: Some((*repository_path).to_string()),
                        installed_path: Some((*repository_path).to_string()),
                        member_sha256: Some(sha256(source.as_bytes())),
                        member_byte_length: Some(source.len() as u64),
                    }
                })
                .collect::<Vec<_>>();
            let module_count_by_kind =
                modules.iter().fold(BTreeMap::new(), |mut counts, module| {
                    *counts.entry(module.kind).or_insert(0) += 1;
                    counts
                });
            let distributions = vec![super::super::HistoricalV2PythonDistribution {
                distribution_id,
                manifest_repository_path: "pyproject.toml".to_string(),
                manifest_object_id: "5".repeat(40),
                manifest_source_sha256: "4".repeat(64),
                build_backend: "fixture.build".to_string(),
                backend_path: Vec::new(),
                build_requirements: vec![super::super::HistoricalV2PythonBuildRequirement {
                    ordinal: 0,
                    requirement: "fixture-build==1.0.0".to_string(),
                }],
                toolchain_identity_sha256: "3".repeat(64),
                command_contract: "fixture".to_string(),
                wheel_filename: "fixture-1.0.0-py3-none-any.whl".to_string(),
                wheel_sha256: "2".repeat(64),
                wheel_byte_length: 1,
                distribution_name: "fixture".to_string(),
                normalized_distribution_name: "fixture".to_string(),
                distribution_version: "1.0.0".to_string(),
                wheel_root: super::super::HistoricalV2PythonWheelRoot::Purelib,
                metadata_member_path: "fixture-1.0.0.dist-info/METADATA".to_string(),
                wheel_metadata_member_path: "fixture-1.0.0.dist-info/WHEEL".to_string(),
                record_member_path: "fixture-1.0.0.dist-info/RECORD".to_string(),
                module_count: modules.len(),
            }];
            (distributions, modules, module_count_by_kind)
        })
        .unwrap_or_default();
    super::super::HistoricalV2PythonDistributionSurfaceCensus {
        schema_version:
            super::super::HISTORICAL_V2_PYTHON_DISTRIBUTION_SURFACE_CENSUS_SCHEMA_VERSION,
        contract: "fixture".to_string(),
        repository: "example/repo".to_string(),
        revision: revision.to_string(),
        inventory_sha256: inventory_sha256.to_string(),
        distributions,
        modules,
        module_count_by_kind,
        census_sha256: "6".repeat(64),
    }
}

fn python_fixture_module_identity(
    repository_path: &str,
) -> (String, super::super::HistoricalV2PythonModuleKind) {
    let module = repository_path.strip_suffix(".py").unwrap();
    let is_init = module.ends_with("/__init__") || module == "__init__";
    let module = module.strip_suffix("/__init__").unwrap_or(module);
    let import_name = module.replace('/', ".");
    let kind = if is_init {
        super::super::HistoricalV2PythonModuleKind::SourcePackageInit
    } else {
        super::super::HistoricalV2PythonModuleKind::SourceModule
    };
    (import_name, kind)
}

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
    assert_eq!(snapshot.symbol_count, 2);
    assert_eq!(snapshot.public_symbol_count, 1);
    assert_eq!(snapshot.public_root_count, 1);
    assert!(snapshot.symbols.iter().any(|entry| {
        entry.symbol.symbol_id == "rust fixture process" && entry.is_public_surface
    }));
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
    assert_eq!(snapshot.symbol_count, 2);
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
            owner_identifier: None,
            owner_identifier_positions: None,
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
    let mut duplicate = index
        .symbols
        .values()
        .find(|symbol| symbol.kind.category == SemanticSymbolCategory::Callable)
        .unwrap()
        .clone();
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

    assert_eq!(snapshot.public_bindings.len(), 2);
    let direct = snapshot
        .public_bindings
        .iter()
        .find(|binding| binding.binding == HistoricalV2SemanticPublicBindingKind::Reference)
        .expect("latent direct compiler reference");
    let exposure = snapshot
        .public_bindings
        .iter()
        .find(|binding| binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure)
        .expect("externally reachable package exposure");
    assert!(!direct.externally_reachable);
    assert!(exposure.externally_reachable);
    assert_eq!(exposure.symbol_id, direct.symbol_id);
    assert_eq!(
        exposure.package_exposure_id.as_deref(),
        Some("fixture-node-package-exposure")
    );
    assert_eq!(direct.compiler_anchor.start_character_zero_based, 41);
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
fn typescript_source_export_outside_the_package_graph_remains_latent() {
    let fixture = typescript_surface_fixture(
        &[
            ("src/index.ts", "export const publicValue = 1;\n"),
            ("src/internal.ts", "export const internalValue = 2;\n"),
        ],
        &[],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]);
    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    let internal_declaration = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "src/internal.ts")
        .and_then(|file| file.public_declarations.first())
        .unwrap();
    let internal_binding = snapshot
        .public_bindings
        .iter()
        .find(|binding| {
            binding.origin_declaration_unit_id == internal_declaration.declaration_unit_id
        })
        .unwrap();

    assert!(!internal_binding.externally_reachable);
    assert_eq!(internal_binding.package_exposure_id, None);
    assert!(snapshot.public_bindings.iter().all(|binding| {
        binding.binding != HistoricalV2SemanticPublicBindingKind::PackageExposure
            || binding.origin_declaration_unit_id != internal_declaration.declaration_unit_id
    }));
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &fixture_required_paths(&fixture.source),
    )
    .unwrap();
}

#[test]
fn two_node_package_slots_for_one_module_remain_distinct() {
    let mut fixture =
        typescript_surface_fixture(&[("src/index.ts", "export const value = 1;\n")], &[]);
    let mut second = fixture.source.node_package_surfaces.exposures[0].clone();
    second.exposure_id = "fixture-node-package-exposure-feature".to_string();
    second.surface_slot_id = "fixture-node-package-surface-slot-feature".to_string();
    second.public_subpath = "./feature".to_string();
    second.conditions = vec![super::super::HistoricalV2NodePackageCondition {
        name: "import".to_string(),
        ordinal: 0,
        location: second.public_subpath_location.clone(),
    }];
    fixture.source.node_package_surfaces.exposures.push(second);
    fixture.source.node_package_surfaces.documents[0].exposure_count = 2;
    fixture
        .source
        .node_package_surfaces
        .exposure_count_by_entry_kind
        .insert(super::super::HistoricalV2NodePackageEntryKind::Exports, 2);
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]);
    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &changed_indexers,
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap();
    let package_bindings = snapshot
        .public_bindings
        .iter()
        .filter(|binding| binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure)
        .collect::<Vec<_>>();

    assert_eq!(snapshot.public_roots.len(), 2);
    assert_eq!(package_bindings.len(), 2);
    assert_eq!(
        package_bindings
            .iter()
            .map(|binding| binding.surface_unit_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &fixture_required_paths(&fixture.source),
    )
    .unwrap();
}

#[test]
fn unresolved_node_package_target_fails_closed() {
    let mut fixture =
        typescript_surface_fixture(&[("src/index.ts", "export const value = 1;\n")], &[]);
    let exposure = &mut fixture.source.node_package_surfaces.exposures[0];
    exposure.target_status =
        super::super::HistoricalV2NodePackageTargetStatus::MissingFromInventory;
    exposure.target_object_id = None;

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("has no tracked compiler root"), "{error}");
}

#[test]
fn missing_node_package_compiler_root_fails_closed() {
    let mut fixture =
        typescript_surface_fixture(&[("src/index.ts", "export const value = 1;\n")], &[]);
    fixture
        .indexes
        .get_mut(&SemanticIndexerKind::TypeScriptJavaScript)
        .unwrap()
        .symbols
        .remove(&SemanticSymbolId(
            "typescript module src/index.ts".to_string(),
        ));

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("to 0 root module definitions"), "{error}");
}

#[test]
fn ambiguous_node_package_compiler_root_fails_closed() {
    let mut fixture =
        typescript_surface_fixture(&[("src/index.ts", "export const value = 1;\n")], &[]);
    let index = fixture
        .indexes
        .get_mut(&SemanticIndexerKind::TypeScriptJavaScript)
        .unwrap();
    let mut duplicate = index
        .symbols
        .get(&SemanticSymbolId(
            "typescript module src/index.ts".to_string(),
        ))
        .unwrap()
        .clone();
    duplicate.id = SemanticSymbolId("typescript duplicate module src/index.ts".to_string());
    index.symbols.insert(duplicate.id.clone(), duplicate);

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::TypeScriptJavaScript]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("to 2 root module definitions"), "{error}");
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
    snapshot
        .public_bindings
        .iter_mut()
        .find(|binding| binding.binding == HistoricalV2SemanticPublicBindingKind::Reference)
        .unwrap()
        .binding = HistoricalV2SemanticPublicBindingKind::Definition;
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
        .filter(|binding| binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure)
        .collect::<Vec<_>>();
    // The barrel's intermediate wildcard expansion stays latent; consumers see
    // one wildcard slot and two namespace-backed slots at the package root.
    assert_eq!(expansions.len(), 3);
    assert!(expansions.iter().all(|binding| {
        binding.externally_reachable
            && binding.package_exposure_id.as_deref() == Some("fixture-node-package-exposure")
    }));
    assert!(snapshot.public_bindings.iter().all(|binding| {
        binding.binding != HistoricalV2SemanticPublicBindingKind::ReexportExpansion
    }));
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
        r#"{"name":"sniff-reexport-probe","version":"1.0.0","exports":"./src/root.ts"}"#,
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
                binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
            })
            .count(),
        3
    );
    assert!(snapshot.public_bindings.iter().all(|binding| {
        binding.binding != HistoricalV2SemanticPublicBindingKind::ReexportExpansion
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
            && binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
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
fn semantic_validation_rejects_a_recommitted_omitted_package_expansion() {
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
            binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
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

    assert!(
        error.contains("package exposure set is incomplete"),
        "{error}"
    );
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

    assert!(
        error.contains("references an omitted public re-export hop"),
        "{error}"
    );
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
    snapshot
        .symbols
        .iter_mut()
        .find(|entry| entry.symbol.symbol_id == "rust fixture process")
        .unwrap()
        .is_public_surface = false;
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
        cargo_project_model: fixture_cargo_project_model(
            &"a".repeat(40),
            &"b".repeat(64),
            Some("src/lib.rs"),
        ),
        node_package_surfaces: fixture_node_package_surfaces(
            &"a".repeat(40),
            &"b".repeat(64),
            None,
        ),
        python_distribution_surfaces: fixture_python_distribution_surfaces(
            &"a".repeat(40),
            &"b".repeat(64),
            None,
        ),
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
                owner_identifier: None,
                owner_identifier_positions: None,
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
    let root_symbol_id = SemanticSymbolId("rust fixture crate".to_string());
    let root_symbol = SemanticSymbol {
        id: root_symbol_id.clone(),
        provider_identity: "rust-analyzer cargo fixture 0.1.0 crate/".to_string(),
        display_name: Some("crate".to_string()),
        kind: SemanticSymbolKind {
            category: SemanticSymbolCategory::Module,
            provider_name: "module".to_string(),
        },
        documentation: Vec::new(),
        signatures: BTreeSet::new(),
        owner: None,
        definitions: BTreeSet::from([SemanticLocation {
            document: document.clone(),
            range: range(0, 0, 0),
        }]),
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
        symbols: BTreeMap::from([(symbol_id, symbol), (root_symbol_id, root_symbol)]),
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
        cargo_project_model: fixture_cargo_project_model(&"a".repeat(40), &"b".repeat(64), None),
        node_package_surfaces: fixture_node_package_surfaces(
            &"a".repeat(40),
            &"b".repeat(64),
            Some(("src/index.ts", &"d".repeat(40))),
        ),
        python_distribution_surfaces: fixture_python_distribution_surfaces(
            &"a".repeat(40),
            &"b".repeat(64),
            None,
        ),
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
    let root_symbol_id = SemanticSymbolId("typescript module src/index.ts".to_string());
    let root_symbol = SemanticSymbol {
        id: root_symbol_id.clone(),
        provider_identity: "scip-typescript npm fixture 1.0.0 `src/index.ts`/".to_string(),
        display_name: Some("src/index.ts".to_string()),
        kind: SemanticSymbolKind {
            category: SemanticSymbolCategory::Module,
            provider_name: "module".to_string(),
        },
        documentation: Vec::new(),
        signatures: BTreeSet::new(),
        owner: None,
        definitions: BTreeSet::from([SemanticLocation {
            document: document_path.clone(),
            range: range(0, 0, 0),
        }]),
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
        symbols: BTreeMap::from([(symbol_id, symbol), (root_symbol_id, root_symbol)]),
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
                && binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
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
                    && binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
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
                && binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
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

    let package_bindings = snapshot
        .public_bindings
        .iter()
        .filter(|binding| {
            binding.repository_path == "pkg/__init__.py"
                && binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
        })
        .collect::<Vec<_>>();
    assert_eq!(package_bindings.len(), 1);
    assert!(package_bindings[0].reexport_path.is_empty());
}

#[test]
fn python_distribution_root_keeps_unreexported_module_bindings_latent() {
    let fixture = python_surface_fixture(
        &[
            ("pkg/__init__.py", "\n"),
            ("pkg/internal.py", "def helper() -> int:\n    return 1\n"),
        ],
        &[],
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

    assert_eq!(snapshot.public_root_count, 1);
    assert_eq!(snapshot.public_roots[0].repository_path, "pkg/__init__.py");
    let helper = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "pkg/internal.py")
        .and_then(|file| {
            file.public_declarations
                .iter()
                .find(|declaration| declaration.name == "helper")
        })
        .unwrap();
    assert!(snapshot.public_bindings.iter().any(|binding| {
        binding.declaration_unit_id == helper.declaration_unit_id && !binding.externally_reachable
    }));
    assert!(!snapshot.public_bindings.iter().any(|binding| {
        binding.origin_declaration_unit_id == helper.declaration_unit_id
            && binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
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
fn python_distribution_reexport_to_unshipped_module_fails_closed() {
    let mut fixture = python_surface_fixture(
        &[
            ("pkg/__init__.py", "from .internal import *\n"),
            ("pkg/internal.py", "value: int = 1\n"),
        ],
        &[("pkg/__init__.py", ".internal", "pkg/internal.py")],
    );
    fixture
        .source
        .python_distribution_surfaces
        .modules
        .retain(|module| module.import_name != "pkg.internal");
    fixture.source.python_distribution_surfaces.distributions[0].module_count = 1;
    fixture
        .source
        .python_distribution_surfaces
        .module_count_by_kind
        .insert(super::super::HistoricalV2PythonModuleKind::SourceModule, 0);

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::Python]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(error.contains("unshipped module"), "{error}");
}

#[test]
fn python_distribution_missing_or_ambiguous_compiler_root_fails_closed() {
    let fixture = python_surface_fixture(&[("pkg/__init__.py", "value: int = 1\n")], &[]);
    let root_symbol = SemanticSymbolId("python module pkg/__init__.py".to_string());
    let mut missing = fixture.indexes.clone();
    missing
        .get_mut(&SemanticIndexerKind::Python)
        .unwrap()
        .symbols
        .remove(&root_symbol);
    let missing_error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::Python]),
        &fixture_required_paths(&fixture.source),
        &missing,
    )
    .unwrap_err();
    assert!(
        missing_error.contains("0 exact source definitions"),
        "{missing_error}"
    );

    let mut ambiguous = fixture.indexes.clone();
    let mut duplicate = ambiguous[&SemanticIndexerKind::Python].symbols[&root_symbol].clone();
    duplicate.id = SemanticSymbolId("python duplicate module pkg".to_string());
    ambiguous
        .get_mut(&SemanticIndexerKind::Python)
        .unwrap()
        .symbols
        .insert(duplicate.id.clone(), duplicate);
    let ambiguous_error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::Python]),
        &fixture_required_paths(&fixture.source),
        &ambiguous,
    )
    .unwrap_err();
    assert!(
        ambiguous_error.contains("2 exact source definitions"),
        "{ambiguous_error}"
    );
}

#[test]
fn python_distribution_uncovered_public_variants_fail_closed() {
    for (kind, expected) in [
        (
            super::super::HistoricalV2PythonModuleKind::StubPackageInit,
            "stub module",
        ),
        (
            super::super::HistoricalV2PythonModuleKind::ExtensionModule,
            "extension module",
        ),
        (
            super::super::HistoricalV2PythonModuleKind::NamespacePackage,
            "namespace distribution root",
        ),
    ] {
        let mut fixture = python_surface_fixture(&[("pkg/__init__.py", "value: int = 1\n")], &[]);
        fixture.source.python_distribution_surfaces.modules[0].kind = kind;
        let error = build_semantic_snapshot(
            fixture.root.path(),
            &fixture.source,
            &fixture.files,
            &BTreeSet::from([SemanticIndexerKind::Python]),
            &fixture_required_paths(&fixture.source),
            &fixture.indexes,
        )
        .unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
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
                && binding.binding == HistoricalV2SemanticPublicBindingKind::PackageExposure
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

    assert!(
        error.contains("package exposure set is incomplete"),
        "{error}"
    );
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

#[test]
fn rust_public_surface_starts_at_the_compiler_crate_root() {
    let fixture = rust_surface_fixture(
        &[
            ("src/lib.rs", "mod hidden;\npub mod public;\n"),
            ("src/hidden.rs", "pub fn hidden_api() {}\n"),
            ("src/public.rs", "pub fn visible_api() {}\n"),
        ],
        &[
            ("src/lib.rs", "hidden", "src/hidden.rs"),
            ("src/lib.rs", "public", "src/public.rs"),
        ],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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

    assert_eq!(snapshot.public_root_count, 1);
    assert_eq!(snapshot.public_roots[0].repository_path, "src/lib.rs");
    let hidden = fixture.source.source_files[0..]
        .iter()
        .find(|file| file.repository_path == "src/hidden.rs")
        .unwrap()
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "hidden_api")
        .unwrap();
    let visible = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "src/public.rs")
        .unwrap()
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "visible_api")
        .unwrap();
    assert!(snapshot.public_bindings.iter().any(|binding| {
        binding.declaration_unit_id == hidden.declaration_unit_id && !binding.externally_reachable
    }));
    assert!(snapshot.public_bindings.iter().any(|binding| {
        binding.origin_declaration_unit_id == visible.declaration_unit_id
            && binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
            && binding.repository_path == "src/lib.rs"
            && binding.externally_reachable
    }));
    assert!(!snapshot.public_bindings.iter().any(|binding| {
        binding.origin_declaration_unit_id == hidden.declaration_unit_id
            && binding.binding == HistoricalV2SemanticPublicBindingKind::ReexportExpansion
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
fn rust_binary_target_is_not_an_external_public_surface() {
    let mut fixture = compiler_surface_fixture(
        "rust",
        SemanticIndexerKind::Rust,
        SemanticPositionEncoding::Utf8,
        &[("src/main.rs", "pub fn command() {}\n")],
        &[],
    );
    fixture.source.cargo_project_model.targets[0].target_status =
        super::super::IntentionalBoundaryProjectModelTargetStatus::Boundary {
            declaration_kind:
                super::super::IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint,
            target: super::super::IntentionalBoundaryManifestTarget::RepositoryPath {
                repository_path: "src/main.rs".to_string(),
            },
        };
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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

    assert_eq!(snapshot.public_root_count, 0);
    assert!(
        snapshot
            .public_bindings
            .iter()
            .all(|binding| !binding.externally_reachable)
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
fn rust_mixed_library_and_binary_targets_select_only_the_cargo_library_root() {
    let mut fixture = rust_surface_fixture(
        &[
            ("src/lib.rs", "pub fn library_api() {}\n"),
            ("src/main.rs", "pub fn command() {}\n"),
        ],
        &[],
    );
    let index = fixture.indexes.get_mut(&SemanticIndexerKind::Rust).unwrap();
    let crate_root = index
        .symbols
        .values_mut()
        .find(|symbol| symbol.provider_identity.ends_with(" crate/"))
        .unwrap();
    crate_root.definitions.insert(SemanticLocation {
        document: RepositoryPath("src/main.rs".to_string()),
        range: range(0, 0, 0),
    });
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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

    assert_eq!(snapshot.public_root_count, 1);
    assert_eq!(snapshot.public_roots[0].repository_path, "src/lib.rs");
    assert!(snapshot.public_bindings.iter().any(|binding| {
        binding.repository_path == "src/lib.rs" && binding.externally_reachable
    }));
    assert!(snapshot.public_bindings.iter().any(|binding| {
        binding.repository_path == "src/main.rs" && !binding.externally_reachable
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
fn rust_named_alias_exposes_the_exact_compiler_target_without_the_module() {
    let fixture = rust_surface_fixture(
        &[
            (
                "src/lib.rs",
                "mod hidden;\npub use hidden::Hidden as Alias;\n",
            ),
            ("src/hidden.rs", "pub struct Hidden;\n"),
        ],
        &[("src/lib.rs", "hidden", "src/hidden.rs")],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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

    let alias = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "src/lib.rs")
        .unwrap()
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "Alias")
        .unwrap();
    let hidden = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "src/hidden.rs")
        .unwrap()
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "Hidden")
        .unwrap();
    let alias_binding = snapshot
        .public_bindings
        .iter()
        .find(|binding| binding.declaration_unit_id == alias.declaration_unit_id)
        .unwrap();
    let hidden_binding = snapshot
        .public_bindings
        .iter()
        .find(|binding| binding.declaration_unit_id == hidden.declaration_unit_id)
        .unwrap();
    assert!(alias_binding.externally_reachable);
    assert!(!hidden_binding.externally_reachable);
    assert_eq!(alias_binding.symbol_id, hidden_binding.symbol_id);
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
fn rust_cross_file_inherent_method_follows_its_compiler_resolved_public_owner() {
    let fixture = rust_surface_fixture(
        &[
            ("src/lib.rs", "pub struct Root;\nmod extensions;\n"),
            (
                "src/extensions.rs",
                "impl crate::Root { pub fn cross_file(&self) {} }\n",
            ),
        ],
        &[("src/lib.rs", "extensions", "src/extensions.rs")],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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

    let method = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "src/extensions.rs")
        .unwrap()
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "cross_file")
        .unwrap();
    let direct = snapshot
        .public_bindings
        .iter()
        .find(|binding| binding.declaration_unit_id == method.declaration_unit_id)
        .unwrap();
    let expansion = snapshot
        .public_bindings
        .iter()
        .find(|binding| {
            binding.origin_declaration_unit_id == method.declaration_unit_id
                && binding.binding == HistoricalV2SemanticPublicBindingKind::OwnerExpansion
        })
        .unwrap();
    assert!(!direct.externally_reachable);
    assert!(direct.owner_symbol_id.is_some());
    assert!(direct.owner_compiler_anchor.is_some());
    assert!(expansion.externally_reachable);
    assert!(expansion.exposing_owner_declaration_unit_id.is_some());
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
fn rust_public_type_alias_exposes_inherent_methods_of_the_exact_target_type() {
    let fixture = rust_surface_fixture(
        &[
            (
                "src/lib.rs",
                "mod hidden;\npub use hidden::Hidden as Alias;\npub use hidden::Hidden as SecondAlias;\n",
            ),
            (
                "src/hidden.rs",
                "pub struct Hidden;\nimpl Hidden { pub fn aliased_method(&self) {} }\n",
            ),
        ],
        &[("src/lib.rs", "hidden", "src/hidden.rs")],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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

    let method = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "src/hidden.rs")
        .unwrap()
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "aliased_method")
        .unwrap();
    let direct = snapshot
        .public_bindings
        .iter()
        .find(|binding| binding.declaration_unit_id == method.declaration_unit_id)
        .unwrap();
    let expansions = snapshot
        .public_bindings
        .iter()
        .filter(|binding| {
            binding.origin_declaration_unit_id == method.declaration_unit_id
                && binding.binding == HistoricalV2SemanticPublicBindingKind::OwnerExpansion
        })
        .collect::<Vec<_>>();
    assert!(!direct.externally_reachable);
    assert_eq!(expansions.len(), 2);
    assert!(
        expansions
            .iter()
            .all(|binding| binding.externally_reachable)
    );
    assert_ne!(expansions[0].surface_unit_id, expansions[1].surface_unit_id);
    assert_ne!(
        expansions[0].exposing_owner_declaration_unit_id,
        expansions[1].exposing_owner_declaration_unit_id
    );
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();

    let mut omitted = snapshot.clone();
    omitted
        .public_bindings
        .retain(|binding| binding.binding != HistoricalV2SemanticPublicBindingKind::OwnerExpansion);
    omitted.public_binding_count = omitted.public_bindings.len();
    omitted.semantic_snapshot_sha256 = semantic_snapshot_sha256(&omitted).unwrap();
    let error = validation::validate_snapshot(
        &fixture.source,
        &omitted,
        &changed_indexers,
        &required_paths,
    )
    .unwrap_err();
    assert!(error.contains("owner expansion set is incomplete or invented"));
}

#[test]
fn rust_public_type_alias_exposes_exact_compiler_owned_fields() {
    let fixture = rust_surface_fixture(
        &[
            (
                "src/lib.rs",
                "mod hidden;\npub use hidden::Hidden as Alias;\n",
            ),
            ("src/hidden.rs", "pub struct Hidden { pub value: u32 }\n"),
        ],
        &[("src/lib.rs", "hidden", "src/hidden.rs")],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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

    let field = fixture
        .source
        .source_files
        .iter()
        .find(|file| file.repository_path == "src/hidden.rs")
        .unwrap()
        .public_declarations
        .iter()
        .find(|declaration| declaration.name == "value")
        .unwrap();
    let direct = snapshot
        .public_bindings
        .iter()
        .find(|binding| binding.declaration_unit_id == field.declaration_unit_id)
        .unwrap();
    let expansion = snapshot
        .public_bindings
        .iter()
        .find(|binding| {
            binding.origin_declaration_unit_id == field.declaration_unit_id
                && binding.binding == HistoricalV2SemanticPublicBindingKind::OwnerExpansion
        })
        .unwrap();
    assert!(!direct.externally_reachable);
    assert!(direct.owner_symbol_id.is_some());
    assert!(expansion.externally_reachable);
    validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap();
}

#[test]
fn semantic_validation_rejects_a_recommitted_rust_private_module_as_public() {
    let fixture = rust_surface_fixture(
        &[
            ("src/lib.rs", "mod hidden;\n"),
            ("src/hidden.rs", "pub fn hidden_api() {}\n"),
        ],
        &[("src/lib.rs", "hidden", "src/hidden.rs")],
    );
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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
    let hidden = snapshot
        .public_bindings
        .iter_mut()
        .find(|binding| binding.repository_path == "src/hidden.rs")
        .unwrap();
    hidden.externally_reachable = true;
    let hidden_symbol_id = hidden.symbol_id.clone();
    snapshot
        .symbols
        .iter_mut()
        .find(|entry| entry.symbol.symbol_id == hidden_symbol_id)
        .unwrap()
        .is_public_surface = true;
    snapshot.public_symbol_count += 1;
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
fn semantic_validation_rejects_a_recommitted_missing_rust_public_root() {
    let fixture = rust_surface_fixture(&[("src/lib.rs", "pub fn api() {}\n")], &[]);
    let changed_indexers = BTreeSet::from([SemanticIndexerKind::Rust]);
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
    snapshot.public_roots.clear();
    snapshot.public_root_count = 0;
    snapshot
        .symbols
        .iter_mut()
        .find(|entry| entry.is_public_root_evidence)
        .unwrap()
        .is_public_root_evidence = false;
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    let error = validation::validate_snapshot(
        &fixture.source,
        &snapshot,
        &changed_indexers,
        &required_paths,
    )
    .unwrap_err();

    assert!(
        error.contains("disagree with Cargo library targets"),
        "{error}"
    );
}

#[test]
fn rust_module_reference_without_a_namespace_surface_fails_closed() {
    let mut fixture = compiler_surface_fixture(
        "rust",
        SemanticIndexerKind::Rust,
        SemanticPositionEncoding::Utf8,
        &[("src/lib.rs", "pub use nested::module as api;\n")],
        &[],
    );
    let declaration = fixture.source.source_files[0].public_declarations[0].clone();
    let module_id = SemanticSymbolId("rust fixture nested module".to_string());
    let index = fixture.indexes.get_mut(&SemanticIndexerKind::Rust).unwrap();
    index.symbols.insert(
        module_id.clone(),
        SemanticSymbol {
            id: module_id.clone(),
            provider_identity: "rust-analyzer cargo fixture 0.1.0 nested/module/".to_string(),
            display_name: Some("module".to_string()),
            kind: SemanticSymbolKind {
                category: SemanticSymbolCategory::Module,
                provider_name: "module".to_string(),
            },
            documentation: Vec::new(),
            signatures: BTreeSet::new(),
            owner: None,
            definitions: BTreeSet::from([SemanticLocation {
                document: RepositoryPath("src/lib.rs".to_string()),
                range: range(0, 16, 22),
            }]),
            visibility: SemanticVisibility::Public,
            surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
            origin: SemanticSymbolOrigin::Repository,
            ambiguity_notes: Vec::new(),
        },
    );
    let anchor = semantic_range(identifier_range(
        &declaration,
        SemanticPositionEncoding::Utf8,
    ));
    index
        .documents
        .get_mut(&RepositoryPath("src/lib.rs".to_string()))
        .unwrap()
        .occurrences
        .iter_mut()
        .find(|occurrence| occurrence.range == anchor)
        .unwrap()
        .symbol = Some(module_id);

    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeSet::from([SemanticIndexerKind::Rust]),
        &fixture_required_paths(&fixture.source),
        &fixture.indexes,
    )
    .unwrap_err();

    assert!(
        error.contains("was not represented as a namespace re-export"),
        "{error}"
    );
}

fn rust_surface_fixture(
    sources: &[(&str, &str)],
    module_targets: &[(&str, &str, &str)],
) -> Fixture {
    let mut fixture = compiler_surface_fixture(
        "rust",
        SemanticIndexerKind::Rust,
        SemanticPositionEncoding::Utf8,
        sources,
        module_targets,
    );
    let index = fixture.indexes.get_mut(&SemanticIndexerKind::Rust).unwrap();
    for file in &fixture.source.source_files {
        for declaration in file.public_declarations.iter().filter(|declaration| {
            declaration.binding == super::super::HistoricalV2SourcePublicBindingKind::Reference
        }) {
            let source_module = declaration.source_module.as_deref().unwrap_or_default();
            let target_path = module_targets
                .iter()
                .find(|(source_path, module, _)| {
                    *source_path == file.repository_path && *module == source_module
                })
                .map(|(_, _, target_path)| *target_path)
                .unwrap();
            let target = fixture
                .source
                .source_files
                .iter()
                .find(|target| target.repository_path == target_path)
                .unwrap()
                .public_declarations
                .iter()
                .find(|target| {
                    target.binding == super::super::HistoricalV2SourcePublicBindingKind::Definition
                        && target.name == declaration.target_name
                })
                .unwrap();
            let target_symbol =
                SemanticSymbolId(format!("rust declaration {}", target.declaration_unit_id));
            let expected_range = semantic_range(identifier_range(
                declaration,
                SemanticPositionEncoding::Utf8,
            ));
            let occurrence = index
                .documents
                .get_mut(&RepositoryPath(file.repository_path.clone()))
                .unwrap()
                .occurrences
                .iter_mut()
                .find(|occurrence| occurrence.range == expected_range)
                .unwrap();
            occurrence.symbol = Some(target_symbol);
        }
    }
    fixture
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

    if language == "python" {
        for (repository_path, _) in sources {
            let (import_name, _) = python_fixture_module_identity(repository_path);
            let symbol_id = SemanticSymbolId(format!("python module {repository_path}"));
            symbols.insert(
                symbol_id.clone(),
                SemanticSymbol {
                    id: symbol_id,
                    provider_identity: format!(
                        "scip-python python fixture _ `{import_name}`/__init__:"
                    ),
                    display_name: Some(import_name),
                    kind: SemanticSymbolKind {
                        category: SemanticSymbolCategory::Module,
                        provider_name: "module".to_string(),
                    },
                    documentation: Vec::new(),
                    signatures: BTreeSet::new(),
                    owner: None,
                    definitions: BTreeSet::from([SemanticLocation {
                        document: RepositoryPath((*repository_path).to_string()),
                        range: range(0, 0, 1),
                    }]),
                    visibility: SemanticVisibility::Public,
                    surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
                    origin: SemanticSymbolOrigin::Repository,
                    ambiguity_notes: Vec::new(),
                },
            );
        }
    }

    for (_, _, target_path) in module_targets {
        let symbol_id = SemanticSymbolId(format!("{language} module {target_path}"));
        let provider_identity = match language {
            "rust" => {
                let module = std::path::Path::new(target_path)
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .unwrap();
                format!("rust-analyzer cargo fixture 0.1.0 {module}/")
            }
            "typescript" | "javascript" => {
                format!("scip-typescript npm fixture 1.0.0 `{target_path}`/")
            }
            "python" => {
                let (import_name, _) = python_fixture_module_identity(target_path);
                format!("scip-python python fixture _ `{import_name}`/__init__:")
            }
            _ => symbol_id.0.clone(),
        };
        symbols
            .entry(symbol_id.clone())
            .or_insert_with(|| SemanticSymbol {
                id: symbol_id.clone(),
                provider_identity,
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
    let node_package_root = if matches!(language, "typescript" | "javascript") {
        let root_path = sources
            .first()
            .map(|(path, _)| *path)
            .expect("Node public-surface fixture needs one source root");
        let root_id = SemanticSymbolId(format!("{language} module {root_path}"));
        symbols
            .entry(root_id.clone())
            .or_insert_with(|| SemanticSymbol {
                id: root_id,
                provider_identity: format!("scip-typescript npm fixture 1.0.0 `{root_path}`/"),
                display_name: Some(root_path.to_string()),
                kind: SemanticSymbolKind {
                    category: SemanticSymbolCategory::Module,
                    provider_name: "module".to_string(),
                },
                documentation: Vec::new(),
                signatures: BTreeSet::new(),
                owner: None,
                definitions: BTreeSet::from([SemanticLocation {
                    document: RepositoryPath(root_path.to_string()),
                    range: range(0, 0, 1),
                }]),
                visibility: SemanticVisibility::Public,
                surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
                origin: SemanticSymbolOrigin::Repository,
                ambiguity_notes: Vec::new(),
            });
        Some((root_path, format!("{:040x}", 0)))
    } else {
        None
    };
    let owner_references = source_files
        .iter()
        .flat_map(|file| {
            file.public_declarations.iter().filter_map(|declaration| {
                let range = owner_identifier_range(declaration, position_encoding)?;
                Some((
                    file.repository_path.clone(),
                    declaration.owner.clone()?,
                    semantic_range(range),
                ))
            })
        })
        .collect::<Vec<_>>();
    for (repository_path, owner_name, range) in owner_references {
        let owners = source_files
            .iter()
            .flat_map(|file| &file.public_declarations)
            .filter(|declaration| {
                declaration.name == owner_name
                    && declaration.kind == super::super::HistoricalV2SourcePublicSymbolKind::Type
                    && declaration.binding
                        == super::super::HistoricalV2SourcePublicBindingKind::Definition
            })
            .collect::<Vec<_>>();
        let [owner] = owners.as_slice() else {
            panic!("fixture owner {owner_name} must resolve to one compiler type");
        };
        documents
            .get_mut(&RepositoryPath(repository_path))
            .unwrap()
            .occurrences
            .push(SemanticOccurrence {
                range,
                symbol: Some(SemanticSymbolId(format!(
                    "{language} declaration {}",
                    owner.declaration_unit_id
                ))),
                roles: BTreeSet::from([SemanticOccurrenceRole::Read]),
                override_documentation: Vec::new(),
            });
    }
    let rust_library_root = if language == "rust" {
        let root_path = sources
            .iter()
            .map(|(path, _)| *path)
            .find(|path| path.ends_with("/lib.rs") || *path == "lib.rs")
            .or_else(|| sources.first().map(|(path, _)| *path))
            .expect("Rust public-surface fixture needs one source root");
        let root_id = SemanticSymbolId("rust fixture crate root".to_string());
        symbols.insert(
            root_id.clone(),
            SemanticSymbol {
                id: root_id,
                provider_identity: "rust-analyzer cargo fixture 0.1.0 crate/".to_string(),
                display_name: Some("crate".to_string()),
                kind: SemanticSymbolKind {
                    category: SemanticSymbolCategory::Module,
                    provider_name: "module".to_string(),
                },
                documentation: Vec::new(),
                signatures: BTreeSet::new(),
                owner: None,
                definitions: BTreeSet::from([SemanticLocation {
                    document: RepositoryPath(root_path.to_string()),
                    range: range(0, 0, 0),
                }]),
                visibility: SemanticVisibility::Public,
                surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
                origin: SemanticSymbolOrigin::Repository,
                ambiguity_notes: Vec::new(),
            },
        );
        Some(root_path)
    } else {
        None
    };
    for (source_path, source_module, target_path) in module_targets {
        let source_file = source_files
            .iter()
            .find(|file| file.repository_path == *source_path)
            .unwrap();
        let Some(reexport) = source_file
            .public_reexports
            .iter()
            .find(|reexport| reexport.source_module == *source_module)
        else {
            continue;
        };
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
        cargo_project_model: fixture_cargo_project_model(
            &"a".repeat(40),
            &"b".repeat(64),
            rust_library_root,
        ),
        node_package_surfaces: fixture_node_package_surfaces(
            &"a".repeat(40),
            &"b".repeat(64),
            node_package_root
                .as_ref()
                .map(|(repository_path, object_id)| (*repository_path, object_id.as_str())),
        ),
        python_distribution_surfaces: fixture_python_distribution_surfaces(
            &"a".repeat(40),
            &"b".repeat(64),
            (language == "python").then_some(sources),
        ),
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

fn owner_identifier_range(
    declaration: &super::super::HistoricalV2SourcePublicDeclaration,
    encoding: SemanticPositionEncoding,
) -> Option<super::super::HistoricalV2SourcePositionRange> {
    declaration
        .owner_identifier_positions
        .as_ref()
        .map(|positions| match encoding {
            SemanticPositionEncoding::Utf8 => positions.utf8,
            SemanticPositionEncoding::Utf16 => positions.utf16,
            SemanticPositionEncoding::Utf32 => positions.utf32,
        })
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
