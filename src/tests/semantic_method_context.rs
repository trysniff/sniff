use super::*;
use crate::semantic_index::{
    SemanticRelationship, SemanticRelationshipKind, SemanticSignature, SemanticSurface,
    SemanticSymbolId, SemanticTestRelationship, SemanticTestRelationshipKind,
    SemanticUnresolvedReason, SemanticVariantId,
};
use std::collections::BTreeSet;

fn fixture() -> (SemanticIndex, SemanticMethodBinding) {
    let (root, files, index) = super::super::tests::fixture(Vec::new(), 0, false, false);
    let join = super::super::join_methods(&root, &files, &index).unwrap();
    let binding = join.bindings.values().next().unwrap().clone();
    fs::remove_dir_all(root).unwrap();
    (index, binding)
}

fn context(index: &SemanticIndex, binding: &SemanticMethodBinding) -> String {
    render_single_world(CompilerMethodWorld {
        variant: index.variant.clone(),
        lines: render_binding_facts(index, binding, &contracts::CompilerContracts::new(index)),
    })
}

fn id(value: &str) -> SemanticSymbolId {
    SemanticSymbolId(value.to_string())
}

fn add_symbol(index: &mut SemanticIndex, identity: &str, name: &str, signature: &str) {
    let mut symbol = index.symbols.values().next().unwrap().clone();
    symbol.id = id(identity);
    symbol.provider_identity = identity.to_string();
    symbol.display_name = Some(name.to_string());
    symbol.owner = None;
    symbol.definitions.clear();
    symbol.signatures = BTreeSet::from([SemanticSignature {
        language: "rust".to_string(),
        text: signature.to_string(),
        referenced_symbols: BTreeSet::new(),
    }]);
    index.symbols.insert(symbol.id.clone(), symbol);
}

fn relate(index: &mut SemanticIndex, source: &str, target: &str, kind: SemanticRelationshipKind) {
    index.relationships.insert(SemanticRelationship {
        source: id(source),
        target: id(target),
        kind,
    });
}

#[test]
fn single_world_reference_renderer_preserves_legacy_bytes_and_header_position() {
    let (root, files, mut index) = super::super::tests::fixture(Vec::new(), 0, false, false);
    let join = super::super::join_methods(&root, &files, &index).unwrap();
    let key = method_context_key(&files[0].file_path, "process", 1);
    let facts = concat!(
        "compiler symbol: resolved rust test process\n",
        "compiler kind: Callable; visibility: Private; origin: Repository\n",
        "compiler public/entrypoint surfaces: not established by this index\n",
        "compiler signature: fn process(value: i32) -> i32\n",
        "compiler contract links: not established by this index\n",
        "compiler enclosing symbol: not reported\n",
        "compiler test linkage: not established by this index; not proof that tests are absent",
    );
    for (variant, header) in [
        (
            SemanticIndexVariant::Unqualified,
            "compiler variant: unqualified; not proof of all build configurations",
        ),
        (
            SemanticIndexVariant::Qualified {
                identity: SemanticVariantId("linux-amd64".to_string()),
                dimensions: BTreeMap::from([
                    ("GOARCH".to_string(), "amd64".to_string()),
                    ("GOOS".to_string(), "linux".to_string()),
                ]),
            },
            "compiler variant: qualified \"linux-amd64\"; dimensions: {\"GOARCH\": \"amd64\", \"GOOS\": \"linux\"}",
        ),
    ] {
        index.variant = variant;
        let actual = render_compiler_method_contexts(&root, &files, &index, &join).unwrap();
        assert_eq!(
            actual[&key],
            format!("SCIP provider: test\n{header}\n{facts}")
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn retains_method_and_enclosing_contract_links_but_not_unrelated_links() {
    let (mut index, binding) = fixture();
    add_symbol(&mut index, "service", "Service", "struct Service");
    add_symbol(&mut index, "protocol", "Protocol", "trait Protocol");
    add_symbol(
        &mut index,
        "required",
        "process",
        "fn process(value: i32) -> i32;",
    );
    index
        .symbols
        .get_mut(&id("rust test process"))
        .unwrap()
        .owner = Some(SemanticResolution::Resolved {
        value: id("service"),
    });
    relate(
        &mut index,
        "rust test process",
        "required",
        SemanticRelationshipKind::Implementation,
    );
    relate(
        &mut index,
        "service",
        "protocol",
        SemanticRelationshipKind::Implementation,
    );
    relate(
        &mut index,
        "unrelated",
        "unrelated_contract",
        SemanticRelationshipKind::Implementation,
    );
    relate(
        &mut index,
        "service",
        "namespace_reference",
        SemanticRelationshipKind::Reference,
    );

    let text = context(&index, &binding);
    assert!(text.contains("compiler method relationship: \"process\" [rust test process] --Implementation--> \"process\" [required]"));
    assert!(text.contains("compiler enclosing symbol relationship: \"Service\" [service] --Implementation--> \"Protocol\" [protocol]"));
    assert!(text.contains(
        "compiler related signature \"process\" [required]: fn process(value: i32) -> i32;"
    ));
    assert!(!text.contains("unrelated"));
    assert!(!text.contains("namespace_reference"));
}

#[test]
fn preserves_every_reported_relationship_kind_and_direction() {
    let (mut index, binding) = fixture();
    for kind in [
        SemanticRelationshipKind::Reference,
        SemanticRelationshipKind::Implementation,
        SemanticRelationshipKind::TypeDefinition,
        SemanticRelationshipKind::Definition,
        SemanticRelationshipKind::Override,
    ] {
        relate(&mut index, "rust test process", "outgoing", kind);
        relate(&mut index, "incoming", "rust test process", kind);
    }
    let text = context(&index, &binding);
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("compiler method relationship:"))
            .count(),
        10
    );
    assert!(text.contains("incoming --Override--> \"process\" [rust test process]"));
    assert!(text.contains("--Override--> outgoing"));
}

#[test]
fn missing_index_facts_do_not_assert_no_tests_exports_or_build_variants() {
    let (index, binding) = fixture();
    let text = context(&index, &binding);
    assert!(text.contains("compiler variant: unqualified; not proof of all build configurations"));
    assert!(text.contains("compiler public/entrypoint surfaces: not established by this index"));
    assert!(text.contains("compiler contract links: not established by this index"));
    assert!(text.contains(
        "compiler test linkage: not established by this index; not proof that tests are absent"
    ));
}

#[test]
fn retains_explicit_surface_evidence_without_inferring_other_surfaces() {
    let (mut index, binding) = fixture();
    index
        .symbols
        .get_mut(&id("rust test process"))
        .unwrap()
        .surfaces
        .insert(SemanticSurface::PublicApi);
    let text = context(&index, &binding);
    assert!(text.contains("compiler surfaces: {PublicApi}"));
    assert!(!text.contains("compiler public/entrypoint surfaces: not established"));
}

#[test]
fn qualified_identity_and_dimensions_survive_context_rendering() {
    let (mut index, binding) = fixture();
    index.variant = SemanticIndexVariant::Qualified {
        identity: SemanticVariantId("linux-amd64".to_string()),
        dimensions: BTreeMap::from([
            ("GOOS".to_string(), "linux".to_string()),
            ("GOARCH".to_string(), "amd64".to_string()),
        ]),
    };
    index.variant.validate().unwrap();
    let text = context(&index, &binding);
    assert!(text.contains("compiler variant: qualified \"linux-amd64\""));
    assert!(text.contains("\"GOOS\": \"linux\""));
    assert!(text.contains("\"GOARCH\": \"amd64\""));
    assert!(!text.contains("compiler variant: unqualified"));
}

#[test]
fn rejects_incomplete_qualified_metadata_before_rendering_any_context() {
    let (mut index, _) = fixture();
    for (identity, dimensions) in [
        (
            "",
            BTreeMap::from([("GOOS".to_string(), "linux".to_string())]),
        ),
        ("variant", BTreeMap::new()),
        (
            "variant",
            BTreeMap::from([("".to_string(), "linux".to_string())]),
        ),
        (
            "variant",
            BTreeMap::from([("GOOS".to_string(), " ".to_string())]),
        ),
    ] {
        index.variant = SemanticIndexVariant::Qualified {
            identity: SemanticVariantId(identity.to_string()),
            dimensions,
        };
        let error = render_compiler_method_contexts(
            Path::new("not-a-repository"),
            &[],
            &index,
            &SemanticMethodJoin {
                bindings: BTreeMap::new(),
            },
        )
        .unwrap_err();
        assert!(error.contains("incomplete qualified variant"));
    }
}

#[test]
fn retains_typed_tests_for_production_and_test_methods_without_name_guesses() {
    let (mut index, binding) = fixture();
    index.test_relationships.insert(SemanticTestRelationship {
        test: id("arbitrary_identity"),
        production: SemanticResolution::Resolved {
            value: id("rust test process"),
        },
        kind: SemanticTestRelationshipKind::Mocks,
    });
    index.test_relationships.insert(SemanticTestRelationship {
        test: id("rust test process"),
        production: SemanticResolution::Resolved {
            value: id("production"),
        },
        kind: SemanticTestRelationshipKind::AssertsContract,
    });
    index.test_relationships.insert(SemanticTestRelationship {
        test: id("test_process_by_name_only"),
        production: SemanticResolution::Resolved {
            value: id("unrelated"),
        },
        kind: SemanticTestRelationshipKind::Exercises,
    });
    let text = context(&index, &binding);
    assert!(text.contains("arbitrary_identity --Mocks--> \"process\" [rust test process]"));
    assert!(text.contains("--AssertsContract--> production"));
    assert!(!text.contains("test_process_by_name_only"));
    assert!(!text.contains("compiler test linkage: not established"));
}

#[test]
fn retains_unresolved_enclosing_and_test_targets_as_unknown_not_contract_proof() {
    let (mut index, binding) = fixture();
    let unresolved = SemanticResolution::Unresolved {
        reason: SemanticUnresolvedReason::MissingIndexerFact,
        raw_target: None,
        detail: "provider omitted target".to_string(),
    };
    index
        .symbols
        .get_mut(&id("rust test process"))
        .unwrap()
        .owner = Some(unresolved.clone());
    index.test_relationships.insert(SemanticTestRelationship {
        test: id("rust test process"),
        production: unresolved,
        kind: SemanticTestRelationshipKind::Exercises,
    });
    let text = context(&index, &binding);
    assert!(text.contains(
        "compiler enclosing symbol: unresolved (MissingIndexerFact): provider omitted target"
    ));
    assert!(
        text.contains("--Exercises--> unresolved (MissingIndexerFact): provider omitted target")
    );
}

#[test]
fn incoming_enclosing_links_preserve_both_endpoint_signatures() {
    let (mut index, binding) = fixture();
    add_symbol(&mut index, "owner", "Protocol", "trait Protocol");
    add_symbol(&mut index, "implementer", "Service", "struct Service");
    index
        .symbols
        .get_mut(&id("rust test process"))
        .unwrap()
        .owner = Some(SemanticResolution::Resolved { value: id("owner") });
    relate(
        &mut index,
        "implementer",
        "owner",
        SemanticRelationshipKind::Implementation,
    );
    let text = context(&index, &binding);
    assert!(text.contains("compiler enclosing symbol relationship: \"Service\" [implementer] --Implementation--> \"Protocol\" [owner]"));
    assert!(text.contains("compiler related signature \"Protocol\" [owner]: trait Protocol"));
    assert!(text.contains("compiler related signature \"Service\" [implementer]: struct Service"));
}

#[test]
fn unresolved_targets_with_same_reason_and_detail_remain_distinguishable() {
    let (mut index, binding) = fixture();
    index
        .symbols
        .get_mut(&id("rust test process"))
        .unwrap()
        .owner = Some(SemanticResolution::Unresolved {
        reason: SemanticUnresolvedReason::MissingIndexerFact,
        raw_target: Some("owner identity".to_string()),
        detail: "omitted".to_string(),
    });
    for target in ["production identity A", "production identity B"] {
        index.test_relationships.insert(SemanticTestRelationship {
            test: id("rust test process"),
            production: SemanticResolution::Unresolved {
                reason: SemanticUnresolvedReason::MissingIndexerFact,
                raw_target: Some(target.to_string()),
                detail: "omitted".to_string(),
            },
            kind: SemanticTestRelationshipKind::Exercises,
        });
    }
    let text = context(&index, &binding);
    for target in [
        "owner identity",
        "production identity A",
        "production identity B",
    ] {
        assert!(text.contains(&format!("raw target {target:?}: omitted")));
    }
}
