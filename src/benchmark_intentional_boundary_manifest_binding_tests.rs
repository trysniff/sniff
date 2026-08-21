use super::*;
use crate::benchmark::release::{
    BoundaryEvidenceKind, IntentionalBoundaryEvidenceProof, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryManifestDeclarationKind as DeclarationKind,
    IntentionalBoundaryManifestDocument, IntentionalBoundaryManifestProofKind,
    IntentionalBoundaryManifestProvider as Provider, IntentionalBoundaryManifestTarget as Target,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticUnresolvedReason, IntentionalBoundarySemanticVisibility,
    IntentionalBoundarySourceFile,
};
use std::collections::BTreeMap;

fn range(path: &str) -> IntentionalBoundarySemanticRange {
    IntentionalBoundarySemanticRange {
        repository_path: path.to_string(),
        start_line_zero_based: 0,
        start_character_zero_based: 0,
        end_line_zero_based: 0,
        end_character_zero_based: 1,
    }
}

fn source_file(
    path: &str,
    source: &str,
    object: char,
) -> (IntentionalBoundarySourceFile, crate::types::MethodRecord) {
    let record = crate::parser::parse_source_checked(path, source.as_bytes()).unwrap();
    let method = record.methods.into_iter().next().expect("fixture method");
    let parser_unit_id = format!("ibm-v1:{}", path.replace(['/', '.'], "-"));
    (
        IntentionalBoundarySourceFile {
            repository_path: path.to_string(),
            object_id: object.to_string().repeat(40),
            byte_length: source.len() as u64,
            source_sha256: object.to_string().repeat(64),
            language: method.language.clone(),
            methods: vec![IntentionalBoundaryMethodCensusEntry {
                parser_unit_id,
                symbol_name: method.name.clone(),
                start_line: method.start_line,
                end_line: method.end_line,
                source_sha256: object.to_ascii_uppercase().to_string().repeat(64),
                is_exported: method.is_exported,
            }],
        },
        method,
    )
}

fn indexer(
    indexer: IntentionalBoundaryIndexerKind,
    marker: char,
) -> IntentionalBoundarySemanticIndexerCensus {
    IntentionalBoundarySemanticIndexerCensus {
        indexer,
        tool_name: "fixture-indexer".to_string(),
        tool_version: Some("1.0.0".to_string()),
        semantic_facts_sha256: marker.to_string().repeat(64),
        diagnostic_count: 0,
        diagnostics_sha256: marker.to_ascii_uppercase().to_string().repeat(64),
        document_count: 1,
        symbol_count: 1,
        relationship_count: 0,
        import_count: 0,
        call_count: 0,
        test_relationship_count: 0,
        unresolved_edge_count: 0,
    }
}

fn declaration(
    provider: Provider,
    manifest_path: &str,
    object: char,
    declaration_kind: DeclarationKind,
    target: Target,
    character: u32,
) -> IntentionalBoundaryManifestDeclaration {
    let mut declaration = IntentionalBoundaryManifestDeclaration {
        declaration_id: String::new(),
        provider,
        manifest_repository_path: manifest_path.to_string(),
        manifest_object_id: object.to_string().repeat(40),
        declaration_kind,
        declaration_location: IntentionalBoundarySemanticRange {
            repository_path: manifest_path.to_string(),
            start_line_zero_based: 0,
            start_character_zero_based: character,
            end_line_zero_based: 0,
            end_character_zero_based: character + 1,
        },
        target,
    };
    declaration.declaration_id =
        super::super::intentional_boundary_manifest::compute_manifest_declaration_id(&declaration)
            .unwrap();
    declaration
}

fn fixture() -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
    IntentionalBoundaryManifestCensus,
) {
    let (javascript, _) = source_file(
        "js/index.js",
        "export function publicApi() { return 1; }",
        'a',
    );
    let (rust, _) = source_file("rust/main.rs", "fn main() {}", 'b');
    let (python, _) = source_file("demo/cli.py", "def main():\n    return 0\n", 'c');
    let source_files = vec![javascript, rust, python];
    let method_count = source_files.iter().map(|file| file.methods.len()).sum();
    let source_census = IntentionalBoundarySourceCensus {
        schema_version: 1,
        census_contract: "fixture".to_string(),
        repository: "github.com/example/bindings".to_string(),
        revision: "d".repeat(40),
        inventory_sha256: "e".repeat(64),
        tracked_entry_count: 6,
        source_files,
        source_file_count: 3,
        method_count,
        census_sha256: "f".repeat(64),
    };
    let methods = source_census
        .source_files
        .iter()
        .flat_map(|file| {
            file.methods.iter().map(|method| {
                let indexer = match file.language.as_str() {
                    "javascript" => IntentionalBoundaryIndexerKind::TypeScriptJavaScript,
                    "python" => IntentionalBoundaryIndexerKind::Python,
                    "rust" => IntentionalBoundaryIndexerKind::Rust,
                    _ => unreachable!(),
                };
                IntentionalBoundarySemanticMethod {
                    parser_unit_id: method.parser_unit_id.clone(),
                    repository_path: file.repository_path.clone(),
                    symbol_name: method.symbol_name.clone(),
                    start_line: method.start_line,
                    end_line: method.end_line,
                    indexer,
                    status: IntentionalBoundarySemanticMethodStatus::Resolved {
                        symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                            symbol_id: format!("fixture {}", method.parser_unit_id),
                            provider_identity: format!("fixture {}", method.parser_unit_id),
                            display_name: Some(method.symbol_name.clone()),
                            category: IntentionalBoundarySemanticSymbolCategory::Callable,
                            provider_kind: "function".to_string(),
                            documentation: Vec::new(),
                            signature: None,
                            signature_referenced_symbols: Vec::new(),
                            owner: None,
                            definitions: vec![range(&file.repository_path)],
                            visibility: IntentionalBoundarySemanticVisibility::Public,
                            surfaces: Vec::new(),
                            origin: IntentionalBoundarySemanticOrigin::Repository,
                            ambiguity_notes: Vec::new(),
                        }),
                        joined_definition: Some(range(&file.repository_path)),
                    },
                    occurrences: Vec::new(),
                    calls: Vec::new(),
                    relationships: Vec::new(),
                    imports: Vec::new(),
                    test_relationships: Vec::new(),
                }
            })
        })
        .collect::<Vec<_>>();
    let mut semantic_census = IntentionalBoundarySemanticCensus {
        schema_version: super::super::INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: super::super::intentional_boundary_semantic::SEMANTIC_CENSUS_CONTRACT
            .to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        indexers: vec![
            indexer(IntentionalBoundaryIndexerKind::TypeScriptJavaScript, '1'),
            indexer(IntentionalBoundaryIndexerKind::Python, '2'),
            indexer(IntentionalBoundaryIndexerKind::Rust, '3'),
        ],
        source_references: Vec::new(),
        resolved_method_count: methods.len(),
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        methods,
        semantic_census_sha256: String::new(),
    };
    semantic_census.semantic_census_sha256 =
        super::super::intentional_boundary_semantic::compute_semantic_census_sha256(
            &semantic_census,
        )
        .unwrap();

    let mut declarations = vec![
        declaration(
            Provider::NodePackageManifest,
            "package.json",
            '4',
            DeclarationKind::PublishedModule,
            Target::RepositoryPath {
                repository_path: "js/index.js".to_string(),
            },
            1,
        ),
        declaration(
            Provider::NodePackageManifest,
            "package.json",
            '4',
            DeclarationKind::RuntimeEntrypoint,
            Target::RepositoryPath {
                repository_path: "js/index.js".to_string(),
            },
            2,
        ),
        declaration(
            Provider::CargoManifest,
            "Cargo.toml",
            '5',
            DeclarationKind::RuntimeEntrypoint,
            Target::RepositoryPath {
                repository_path: "rust/main.rs".to_string(),
            },
            1,
        ),
        declaration(
            Provider::CargoManifest,
            "Cargo.toml",
            '5',
            DeclarationKind::BuildScript,
            Target::RepositoryPath {
                repository_path: "build.rs".to_string(),
            },
            2,
        ),
        declaration(
            Provider::PythonProjectManifest,
            "pyproject.toml",
            '6',
            DeclarationKind::RuntimeEntrypoint,
            Target::PythonObject {
                module: vec!["demo".to_string(), "cli".to_string()],
                qualname: vec!["main".to_string()],
            },
            1,
        ),
        declaration(
            Provider::PythonProjectManifest,
            "pyproject.toml",
            '6',
            DeclarationKind::RuntimeEntrypoint,
            Target::PythonObject {
                module: vec!["demo".to_string(), "cli".to_string()],
                qualname: vec!["Plugin".to_string(), "create".to_string()],
            },
            2,
        ),
    ];
    declarations.sort();
    let documents = vec![
        IntentionalBoundaryManifestDocument {
            provider: Provider::CargoManifest,
            repository_path: "Cargo.toml".to_string(),
            object_id: "5".repeat(40),
            source_sha256: "5".repeat(64),
            declaration_count: 2,
        },
        IntentionalBoundaryManifestDocument {
            provider: Provider::NodePackageManifest,
            repository_path: "package.json".to_string(),
            object_id: "4".repeat(40),
            source_sha256: "4".repeat(64),
            declaration_count: 2,
        },
        IntentionalBoundaryManifestDocument {
            provider: Provider::PythonProjectManifest,
            repository_path: "pyproject.toml".to_string(),
            object_id: "6".repeat(40),
            source_sha256: "6".repeat(64),
            declaration_count: 2,
        },
    ];
    let document_count_by_provider = BTreeMap::from([
        (Provider::CargoManifest, 1),
        (Provider::NodePackageManifest, 1),
        (Provider::PythonProjectManifest, 1),
    ]);
    let declaration_count_by_kind = BTreeMap::from([
        (DeclarationKind::PublishedModule, 1),
        (DeclarationKind::RuntimeEntrypoint, 4),
        (DeclarationKind::BuildScript, 1),
    ]);
    let mut manifest_census = IntentionalBoundaryManifestCensus {
        schema_version: super::super::INTENTIONAL_BOUNDARY_MANIFEST_CENSUS_SCHEMA_VERSION,
        manifest_contract: super::super::intentional_boundary_manifest::MANIFEST_CONTRACT
            .to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        inventory_sha256: source_census.inventory_sha256.clone(),
        documents,
        document_count_by_provider,
        declarations,
        declaration_count_by_kind,
        manifest_census_sha256: String::new(),
    };
    manifest_census.manifest_census_sha256 =
        super::super::intentional_boundary_manifest::compute_manifest_census_sha256(
            &manifest_census,
        )
        .unwrap();
    (source_census, semantic_census, manifest_census)
}

#[test]
fn binds_every_manifest_declaration_to_an_explicit_outcome() {
    let (source, semantic, manifest) = fixture();

    let bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifest).unwrap();

    assert_eq!(bindings.bindings.len(), manifest.declarations.len());
    assert_eq!(bindings.bound_declaration_count, 3);
    assert_eq!(bindings.non_method_declaration_count, 1);
    assert_eq!(bindings.awaiting_generator_replay_count, 1);
    assert_eq!(bindings.unresolved_declaration_count, 1);
    assert_eq!(bindings.binding_census_sha256.len(), 64);
    assert!(bindings.bindings.iter().any(|binding| matches!(
        binding.outcome,
        Outcome::Unresolved {
            reason: UnresolvedReason::UnsupportedPythonQualname,
            ..
        }
    )));
    validate_intentional_boundary_manifest_bindings(&source, &semantic, &manifest, &bindings)
        .unwrap();
}

#[test]
fn binding_replay_rejects_missing_declaration_outcomes() {
    let (source, semantic, manifest) = fixture();
    let mut bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifest).unwrap();
    bindings.bindings.pop();

    assert!(
        validate_intentional_boundary_manifest_bindings(&source, &semantic, &manifest, &bindings,)
            .unwrap_err()
            .contains("changed")
    );
}

#[test]
fn binding_replay_rejects_bound_subject_tampering() {
    let (source, semantic, manifest) = fixture();
    let mut bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifest).unwrap();
    let subject = bindings
        .bindings
        .iter_mut()
        .find_map(|binding| match &mut binding.outcome {
            Outcome::Bound { subjects } => subjects.first_mut(),
            _ => None,
        })
        .expect("bound subject");
    subject.subject_symbol_id = "invented compiler identity".to_string();

    assert!(
        validate_intentional_boundary_manifest_bindings(&source, &semantic, &manifest, &bindings,)
            .unwrap_err()
            .contains("changed")
    );
}

#[test]
fn compiler_unresolved_target_is_not_bound_by_source_name() {
    let (source, mut semantic, manifest) = fixture();
    let unresolved_unit = source.source_files[0].methods[0].parser_unit_id.clone();
    let semantic_method = semantic
        .methods
        .iter_mut()
        .find(|method| method.parser_unit_id == unresolved_unit)
        .expect("semantic method");
    semantic_method.status = IntentionalBoundarySemanticMethodStatus::Unresolved {
        reason: IntentionalBoundarySemanticUnresolvedReason::MissingIndexerFact,
        raw_target: None,
        detail: "fixture compiler fact missing".to_string(),
    };
    semantic.resolved_method_count -= 1;
    semantic.unresolved_method_count += 1;
    semantic.semantic_census_sha256 =
        super::super::intentional_boundary_semantic::compute_semantic_census_sha256(&semantic)
            .unwrap();

    let bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifest).unwrap();

    assert!(bindings.bindings.iter().any(|binding| matches!(
        binding.outcome,
        Outcome::Unresolved {
            reason: UnresolvedReason::CompilerMethodUnavailable,
            ..
        }
    )));
    assert!(!bindings.bindings.iter().any(|binding| {
        match &binding.outcome {
            Outcome::Bound { subjects } => subjects
                .iter()
                .any(|subject| subject.parser_unit_id == unresolved_unit),
            _ => false,
        }
    }));
}

#[test]
fn duplicate_manifest_declarations_fail_closed_even_with_a_recomputed_hash() {
    let (source, _, mut manifest) = fixture();
    let duplicate = manifest.declarations[0].clone();
    manifest.declarations.push(duplicate.clone());
    manifest.declarations.sort();
    *manifest
        .declaration_count_by_kind
        .get_mut(&duplicate.declaration_kind)
        .unwrap() += 1;
    manifest
        .documents
        .iter_mut()
        .find(|document| {
            document.provider == duplicate.provider
                && document.repository_path == duplicate.manifest_repository_path
        })
        .unwrap()
        .declaration_count += 1;
    manifest.manifest_census_sha256 =
        super::super::intentional_boundary_manifest::compute_manifest_census_sha256(&manifest)
            .unwrap();

    assert!(
        super::super::intentional_boundary_manifest::validate_manifest_census_commitment(
            &source.inventory_sha256,
            &manifest,
        )
        .unwrap_err()
        .contains("ordering")
    );
}

#[test]
fn emits_manifest_evidence_only_for_compiler_bound_method_subjects() {
    let (source, semantic, manifest) = fixture();
    let bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifest).unwrap();
    let compiler =
        super::super::extract_intentional_boundary_compiler_evidence(&source, &semantic).unwrap();

    let evidence = super::super::intentional_boundary_manifest_evidence::derive_manifest_evidence(
        &source, &semantic, &manifest, &bindings, compiler,
    )
    .unwrap();

    assert_eq!(
        evidence
            .input_census_sha256
            .get("package_manifest_declarations"),
        Some(&manifest.manifest_census_sha256)
    );
    assert_eq!(
        evidence
            .input_census_sha256
            .get("package_manifest_bindings"),
        Some(&bindings.binding_census_sha256)
    );
    let manifest_atoms = evidence
        .atoms
        .iter()
        .filter(|atom| {
            matches!(
                atom.proof,
                IntentionalBoundaryEvidenceProof::ManifestContract(_)
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(manifest_atoms.len(), 4);
    assert_eq!(
        manifest_atoms
            .iter()
            .filter(|atom| {
                matches!(
                    atom.proof,
                    IntentionalBoundaryEvidenceProof::ManifestContract(
                        IntentionalBoundaryManifestProofKind::PublishedExport
                    )
                )
            })
            .count(),
        2
    );
    assert_eq!(
        manifest_atoms
            .iter()
            .filter(|atom| atom.evidence_kind == BoundaryEvidenceKind::RuntimeOrPackageManifest)
            .count(),
        2
    );
    assert!(manifest_atoms.iter().all(|atom| {
        atom.locations.iter().any(|location| {
            matches!(
                location.repository_path.as_str(),
                "Cargo.toml" | "package.json" | "pyproject.toml"
            )
        })
    }));
    assert!(!manifest_atoms.iter().any(|atom| {
        atom.subject_parser_unit_id.contains("Plugin")
            || matches!(
                atom.proof,
                IntentionalBoundaryEvidenceProof::ManifestContract(
                    IntentionalBoundaryManifestProofKind::GeneratorConfiguration
                )
            )
    }));
}

#[test]
fn python_binding_resolves_a_unique_src_layout_module_without_guessing_a_root() {
    let (mut source, semantic, manifest) = fixture();
    let file = source
        .source_files
        .iter_mut()
        .find(|file| file.repository_path == "demo/cli.py")
        .unwrap();
    file.repository_path = "src/demo/cli.py".to_string();
    let semantic_methods = semantic
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let declaration = manifest
        .declarations
        .iter()
        .find(|declaration| {
            matches!(
                &declaration.target,
                Target::PythonObject { qualname, .. } if qualname == &["main".to_string()]
            )
        })
        .unwrap();
    let Target::PythonObject { module, qualname } = &declaration.target else {
        unreachable!()
    };

    let outcome =
        bind_python_object(&source, &semantic_methods, declaration, module, qualname).unwrap();

    assert!(matches!(outcome, Outcome::Bound { subjects } if subjects.len() == 1));
}

#[test]
fn python_binding_rejects_multiple_possible_import_roots() {
    let (mut source, semantic, manifest) = fixture();
    let duplicate = {
        let file = source
            .source_files
            .iter_mut()
            .find(|file| file.repository_path == "demo/cli.py")
            .unwrap();
        file.repository_path = "src/demo/cli.py".to_string();
        let mut duplicate = file.clone();
        duplicate.repository_path = "lib/demo/cli.py".to_string();
        duplicate
    };
    source.source_files.push(duplicate);
    let semantic_methods = semantic
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let declaration = manifest
        .declarations
        .iter()
        .find(|declaration| {
            matches!(
                &declaration.target,
                Target::PythonObject { qualname, .. } if qualname == &["main".to_string()]
            )
        })
        .unwrap();
    let Target::PythonObject { module, qualname } = &declaration.target else {
        unreachable!()
    };

    let outcome =
        bind_python_object(&source, &semantic_methods, declaration, module, qualname).unwrap();

    assert!(matches!(
        outcome,
        Outcome::Unresolved {
            reason: UnresolvedReason::AmbiguousSourceTarget,
            ..
        }
    ));
}
