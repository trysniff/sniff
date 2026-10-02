use super::*;
use crate::semantic_index::{QualifiedSemanticIndex, SemanticIndexVariant, SemanticVariantId};
use std::path::PathBuf;

struct Fixture {
    root: PathBuf,
    files: Vec<FileRecord>,
    index: SemanticIndex,
}

impl Fixture {
    fn new() -> Self {
        let (root, files, index, _) = super::super::tests::reference_fixture();
        Self { root, files, index }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn world(index: &SemanticIndex, name: &str) -> QualifiedSemanticIndex {
    let mut index = index.clone();
    index.variant = SemanticIndexVariant::Qualified {
        identity: SemanticVariantId(name.to_string()),
        dimensions: BTreeMap::from([("target".to_string(), name.to_string())]),
    };
    QualifiedSemanticIndex {
        index,
        ignored_documents: BTreeSet::new(),
    }
}

fn sets(worlds: Vec<QualifiedSemanticIndex>) -> BTreeMap<SemanticIndexerKind, SemanticIndexSet> {
    let variants = worlds
        .into_iter()
        .map(|world| {
            let SemanticIndexVariant::Qualified { identity, .. } = &world.index.variant else {
                panic!("test world must be qualified")
            };
            (identity.clone(), world)
        })
        .collect();
    BTreeMap::from([(
        SemanticIndexerKind::Rust,
        SemanticIndexSet::Qualified { variants },
    )])
}

#[test]
fn normal_unqualified_evidence_keeps_exact_census_and_explicit_world_status() {
    let fixture = Fixture::new();
    let sets = BTreeMap::from([(
        SemanticIndexerKind::Rust,
        SemanticIndexSet::Unqualified {
            index: Box::new(fixture.index.clone()),
        },
    )]);
    let evidence = build_compiler_method_evidence(&fixture.root, &fixture.files, &sets).unwrap();
    assert_eq!(evidence.contexts.len(), 2);
    assert_eq!(evidence.references.len(), 1);
    assert_eq!(
        evidence.references[0].variant,
        SemanticIndexVariant::Unqualified
    );
    for context in evidence.contexts.values() {
        assert!(context.contains("compiler variant: unqualified"));
    }
}

#[test]
fn identical_edges_in_two_worlds_remain_distinct_and_both_dossiers_survive() {
    let fixture = Fixture::new();
    let sets = sets(vec![
        world(&fixture.index, "linux"),
        world(&fixture.index, "windows"),
    ]);
    let evidence = build_compiler_method_evidence(&fixture.root, &fixture.files, &sets).unwrap();
    assert_eq!(evidence.contexts.len(), 2);
    assert_eq!(evidence.references.len(), 2);
    assert_ne!(
        evidence.references[0].variant,
        evidence.references[1].variant
    );
    for context in evidence.contexts.values() {
        assert_eq!(context.matches("compiler variant: qualified").count(), 2);
        assert!(context.contains("\"linux\""));
        assert!(context.contains("\"windows\""));
    }
}

#[test]
fn hundred_world_evidence_compacts_dossiers_but_keeps_all_relationship_worlds() {
    let fixture = Fixture::new();
    let worlds = (0..100)
        .map(|ordinal| {
            let mut world = world(&fixture.index, &format!("world-{ordinal:03}"));
            let SemanticIndexVariant::Qualified { dimensions, .. } = &mut world.index.variant
            else {
                unreachable!()
            };
            dimensions.insert("source_snapshot_sha256".to_string(), "a".repeat(64));
            dimensions.insert("compiler_runtime_sha256".to_string(), "b".repeat(64));
            world
        })
        .collect::<Vec<_>>();
    let sets = sets(worlds);
    let evidence = build_compiler_method_evidence(&fixture.root, &fixture.files, &sets).unwrap();
    assert_eq!(evidence.contexts.len(), 2);
    assert_eq!(evidence.references.len(), 100);
    let SemanticIndexSet::Qualified { variants } = &sets[&SemanticIndexerKind::Rust] else {
        unreachable!()
    };
    assert_eq!(variants.len(), 100);
    let mut original = BTreeMap::<String, Vec<String>>::new();
    for world in variants.values() {
        let join = join_methods(&fixture.root, &fixture.files, &world.index).unwrap();
        for (key, context) in super::super::render_compiler_method_contexts(
            &fixture.root,
            &fixture.files,
            &world.index,
            &join,
        )
        .unwrap()
        {
            original.entry(key).or_default().push(context);
        }
    }
    for (key, context) in &evidence.contexts {
        assert_eq!(context.matches("compiler variant: qualified").count(), 100);
        assert_eq!(context.matches("SCIP provider: test").count(), 1);
        assert_eq!(context.matches(&"a".repeat(64)).count(), 1);
        assert!(context.contains("facts in observed worlds W1-W100:"));
        assert!(context.len() * 3 < original[key].join("\n\n").len());
    }
}

#[test]
fn explicit_ignored_document_is_not_resolved_from_another_world() {
    let fixture = Fixture::new();
    let mut windows = world(&fixture.index, "windows");
    let excluded = RepositoryPath("src/target.rs".to_string());
    windows.index.documents.remove(&excluded);
    windows
        .index
        .symbols
        .remove(&crate::semantic_index::SemanticSymbolId(
            "rust test target".to_string(),
        ));
    windows.ignored_documents.insert(excluded);
    let sets = sets(vec![world(&fixture.index, "linux"), windows]);
    let evidence = build_compiler_method_evidence(&fixture.root, &fixture.files, &sets).unwrap();
    let target = &fixture.files[1];
    let key = method_context_key(&target.file_path, "target", 1);
    let context = &evidence.contexts[&key];
    assert_eq!(
        context
            .matches("compiler coverage: excluded (document not selected in this compiler variant)")
            .count(),
        1
    );
    assert_eq!(
        context
            .matches("compiler symbol: resolved rust test target")
            .count(),
        1
    );
    assert_eq!(evidence.references.len(), 1);
    assert_eq!(
        evidence.references[0].variant,
        world(&fixture.index, "linux").index.variant
    );
}

#[test]
fn missing_method_in_one_world_is_fatal_despite_another_complete_world() {
    let fixture = Fixture::new();
    let mut windows = world(&fixture.index, "windows");
    windows
        .index
        .documents
        .remove(&RepositoryPath("src/target.rs".to_string()));
    windows
        .index
        .symbols
        .remove(&crate::semantic_index::SemanticSymbolId(
            "rust test target".to_string(),
        ));
    let sets = sets(vec![world(&fixture.index, "linux"), windows]);
    let error = build_compiler_method_evidence(&fixture.root, &fixture.files, &sets)
        .err()
        .unwrap();
    assert!(error.contains("join is incomplete"));
}

#[test]
fn missing_extra_or_empty_provider_world_sets_fail_closed() {
    let fixture = Fixture::new();
    let empty = BTreeMap::new();
    assert!(build_compiler_method_evidence(&fixture.root, &fixture.files, &empty).is_err());
    let mut extra = sets(vec![world(&fixture.index, "linux")]);
    extra.insert(
        SemanticIndexerKind::Go,
        extra[&SemanticIndexerKind::Rust].clone(),
    );
    assert!(build_compiler_method_evidence(&fixture.root, &fixture.files, &extra).is_err());
    let empty_worlds = sets(Vec::new());
    let error = build_compiler_method_evidence(&fixture.root, &fixture.files, &empty_worlds)
        .err()
        .unwrap();
    assert!(error.contains("no variants"));
}

#[test]
fn contradictory_exclusion_and_variant_identity_fail_closed() {
    let fixture = Fixture::new();
    let mut contradictory = world(&fixture.index, "linux");
    contradictory
        .ignored_documents
        .insert(RepositoryPath("src/target.rs".to_string()));
    assert!(
        build_compiler_method_evidence(&fixture.root, &fixture.files, &sets(vec![contradictory]))
            .is_err()
    );
    let mut mismatched = sets(vec![world(&fixture.index, "linux")]);
    let SemanticIndexSet::Qualified { variants } =
        mismatched.get_mut(&SemanticIndexerKind::Rust).unwrap()
    else {
        unreachable!()
    };
    let old = variants
        .remove(&SemanticVariantId("linux".to_string()))
        .unwrap();
    variants.insert(SemanticVariantId("different".to_string()), old);
    assert!(build_compiler_method_evidence(&fixture.root, &fixture.files, &mismatched).is_err());
}

#[test]
fn different_repository_and_duplicate_ast_identity_fail_closed() {
    let mut fixture = Fixture::new();
    let foreign = tempfile::tempdir().unwrap();
    let mut foreign_world = world(&fixture.index, "linux");
    foreign_world.index.repository_root = foreign.path().to_string_lossy().to_string();
    let error =
        build_compiler_method_evidence(&fixture.root, &fixture.files, &sets(vec![foreign_world]))
            .err()
            .unwrap();
    assert!(error.contains("different repository root"));
    let duplicate = fixture.files[0].methods[0].clone();
    fixture.files[0].methods.push(duplicate);
    let error = build_compiler_method_evidence(
        &fixture.root,
        &fixture.files,
        &sets(vec![world(&fixture.index, "linux")]),
    )
    .err()
    .unwrap();
    assert!(error.contains("duplicate compiler evidence AST method"));
}

#[test]
fn relationship_extraction_rejects_incomplete_qualified_metadata_before_io() {
    let fixture = Fixture::new();
    let mut index = fixture.index.clone();
    index.variant = SemanticIndexVariant::Qualified {
        identity: SemanticVariantId("variant".to_string()),
        dimensions: BTreeMap::new(),
    };
    let join = super::super::join_methods(&fixture.root, &fixture.files, &fixture.index).unwrap();
    let error =
        compiler_method_references(Path::new("not-a-repository"), &fixture.files, &index, &join)
            .unwrap_err();
    assert!(error.contains("incomplete qualified variant"));
}

#[test]
fn qualified_rust_world_never_inherits_host_cfg_or_default_test_exclusions() {
    let inactive_host = if cfg!(windows) { "unix" } else { "windows" };
    for predicate in [inactive_host, "test"] {
        let mut fixture = Fixture::new();
        let source = format!("#[cfg({predicate})]\nfn process(value: i32) -> i32 {{ value }}\n");
        fs::write(&fixture.files[0].file_path, &source).unwrap();
        fixture.files[0].source = source.clone();
        fixture.files[0].methods[0].source = source;
        fixture.files[0].methods[0].start_line = 2;
        fixture.files[0].methods[0].end_line = 2;
        fixture
            .index
            .symbols
            .remove(&crate::semantic_index::SemanticSymbolId(
                "rust test process".to_string(),
            ));
        let error = build_compiler_method_evidence(
            &fixture.root,
            &fixture.files,
            &sets(vec![world(&fixture.index, "other-target")]),
        )
        .err()
        .unwrap();
        assert!(error.contains("join is incomplete"));
    }
}

#[test]
fn unqualified_rust_index_cannot_prove_cfg_exclusion_from_sniff_build_flags() {
    let inactive_host = if cfg!(windows) { "unix" } else { "windows" };
    for predicate in [
        inactive_host,
        "test",
        "not(debug_assertions)",
        "feature = \"optional-provider\"",
        "any(test, windows)",
    ] {
        let mut fixture = Fixture::new();
        let source = format!("#[cfg({predicate})]\nfn process(value: i32) -> i32 {{ value }}\n");
        fs::write(&fixture.files[0].file_path, &source).unwrap();
        fixture.files[0].source = source.clone();
        fixture.files[0].methods[0].source = source;
        fixture.files[0].methods[0].start_line = 2;
        fixture.files[0].methods[0].end_line = 2;
        fixture
            .index
            .symbols
            .remove(&crate::semantic_index::SemanticSymbolId(
                "rust test process".to_string(),
            ));
        let indexes = BTreeMap::from([(
            SemanticIndexerKind::Rust,
            SemanticIndexSet::Unqualified {
                index: Box::new(fixture.index.clone()),
            },
        )]);
        let result = build_compiler_method_evidence(&fixture.root, &fixture.files, &indexes);
        assert!(
            result.is_err(),
            "cfg({predicate}) was accepted without compiler evidence"
        );
        assert!(result.err().unwrap().contains("join is incomplete"));
    }
}

#[test]
fn ignored_definition_cannot_leak_into_callee_contract_or_test_context() {
    let fixture = Fixture::new();
    let mut inconsistent = world(&fixture.index, "windows");
    let excluded = RepositoryPath("src/target.rs".to_string());
    inconsistent.index.documents.remove(&excluded);
    inconsistent.ignored_documents.insert(excluded);
    let definition = fixture.index.symbols
        [&crate::semantic_index::SemanticSymbolId("rust test process".to_string())]
        .definitions
        .iter()
        .next()
        .unwrap()
        .clone();
    inconsistent
        .index
        .calls
        .insert(crate::semantic_index::SemanticCallEdge {
            caller: crate::semantic_index::SemanticSymbolId("rust test process".to_string()),
            callee: SemanticResolution::Resolved {
                value: crate::semantic_index::SemanticSymbolId("rust test target".to_string()),
            },
            callsite: definition,
            dispatch: crate::semantic_index::SemanticDispatch::Static,
        });
    inconsistent
        .index
        .relationships
        .insert(crate::semantic_index::SemanticRelationship {
            source: crate::semantic_index::SemanticSymbolId("rust test process".to_string()),
            target: crate::semantic_index::SemanticSymbolId("rust test target".to_string()),
            kind: crate::semantic_index::SemanticRelationshipKind::Implementation,
        });
    inconsistent
        .index
        .test_relationships
        .insert(crate::semantic_index::SemanticTestRelationship {
            test: crate::semantic_index::SemanticSymbolId("rust test process".to_string()),
            production: SemanticResolution::Resolved {
                value: crate::semantic_index::SemanticSymbolId("rust test target".to_string()),
            },
            kind: crate::semantic_index::SemanticTestRelationshipKind::Mocks,
        });
    let error =
        build_compiler_method_evidence(&fixture.root, &fixture.files, &sets(vec![inconsistent]))
            .err()
            .unwrap();
    assert!(error.contains("conflicting document coverage"));
}

#[test]
fn ignored_callsite_is_rejected_even_without_an_ignored_symbol_definition() {
    let fixture = Fixture::new();
    let target_id = crate::semantic_index::SemanticSymbolId("rust test target".to_string());
    let callsite = fixture.index.symbols[&target_id]
        .definitions
        .iter()
        .next()
        .unwrap()
        .clone();
    let mut inconsistent = world(&fixture.index, "windows");
    inconsistent.index.documents.remove(&callsite.document);
    inconsistent
        .ignored_documents
        .insert(callsite.document.clone());
    inconsistent.index.symbols.remove(&target_id);
    inconsistent
        .index
        .calls
        .insert(crate::semantic_index::SemanticCallEdge {
            caller: crate::semantic_index::SemanticSymbolId("rust test process".to_string()),
            callee: SemanticResolution::Resolved { value: target_id },
            callsite,
            dispatch: crate::semantic_index::SemanticDispatch::Static,
        });
    let error =
        build_compiler_method_evidence(&fixture.root, &fixture.files, &sets(vec![inconsistent]))
            .err()
            .unwrap();
    assert!(error.contains("conflicting document coverage"));
}

#[test]
fn noncanonical_ignored_document_metadata_is_rejected() {
    let fixture = Fixture::new();
    for path in [
        "../escape.rs",
        "/outside.rs",
        "C:/outside.rs",
        "src\\lib.rs",
        "bad\0.rs",
        "",
    ] {
        let mut inconsistent = world(&fixture.index, "windows");
        inconsistent
            .ignored_documents
            .insert(RepositoryPath(path.to_string()));
        assert!(
            build_compiler_method_evidence(
                &fixture.root,
                &fixture.files,
                &sets(vec![inconsistent])
            )
            .is_err()
        );
    }
}
