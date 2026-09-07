use super::*;
use crate::semantic_index::{
    QualifiedSemanticIndex, RepositoryPath, SEMANTIC_INDEX_FORMAT_VERSION, SemanticIndexProvenance,
    SemanticIndexSet, SemanticIndexerContribution, SemanticIndexerVariantPlan,
    SemanticRelationshipKind, SemanticResolution, SemanticSymbolId, SemanticVariantId,
};
use crate::semantic_indexer_installation::SemanticIndexerStore;

fn write_go_file(root: &Path, relative: &str, source: &str) -> FileRecord {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, source).unwrap();
    FileRecord {
        file_path: path.to_string_lossy().into_owned(),
        source: source.to_string(),
        language: "go".to_string(),
        methods: Vec::new(),
    }
}

fn symbol_id(index: &SemanticIndex, display_name: &str) -> SemanticSymbolId {
    let matches = index
        .symbols
        .values()
        .filter(|symbol| symbol.display_name.as_deref() == Some(display_name))
        .map(|symbol| symbol.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one compiler symbol named {display_name}: {matches:?}"
    );
    matches.into_iter().next().unwrap()
}

fn digest(character: char) -> String {
    character.to_string().repeat(64)
}

fn empty_index(root: &Path) -> SemanticIndex {
    SemanticIndex {
        format_version: SEMANTIC_INDEX_FORMAT_VERSION,
        repository_root: strip_windows_verbatim_prefix(fs::canonicalize(root).unwrap())
            .to_string_lossy()
            .into_owned(),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: "scip-go".to_string(),
            tool_version: Some("test".to_string()),
            arguments: Vec::new(),
            source_text_encoding: None,
            invocations: Vec::new(),
            diagnostics: Vec::new(),
        },
        variant: crate::semantic_index::SemanticIndexVariant::Unqualified,
        documents: BTreeMap::new(),
        symbols: BTreeMap::new(),
        relationships: BTreeSet::new(),
        imports: BTreeSet::new(),
        calls: BTreeSet::new(),
        test_relationships: BTreeSet::new(),
        unresolved_edges: BTreeSet::new(),
    }
}

fn variant_plan(
    identity: &str,
    selected_documents: &[&str],
    ignored_documents: &[&str],
) -> SemanticIndexerVariantPlan {
    SemanticIndexerVariantPlan {
        identity: SemanticVariantId(identity.to_string()),
        dimensions: BTreeMap::from([
            ("goarch".to_string(), "amd64".to_string()),
            ("goos".to_string(), "linux".to_string()),
        ]),
        environment: BTreeMap::from([
            ("CGO_ENABLED".to_string(), "0".to_string()),
            ("GOARCH".to_string(), "amd64".to_string()),
            ("GOFLAGS".to_string(), String::new()),
            ("GOOS".to_string(), "linux".to_string()),
        ]),
        selected_documents: selected_documents
            .iter()
            .map(|path| RepositoryPath((*path).to_string()))
            .collect(),
        ignored_documents: ignored_documents
            .iter()
            .map(|path| RepositoryPath((*path).to_string()))
            .collect(),
    }
}

fn package_inventory(
    selected_documents: &[&str],
    ignored_documents: &[&str],
) -> super::go_shards::GoPackageInventory {
    super::go_shards::GoPackageInventory {
        packages: if selected_documents.is_empty() && ignored_documents.is_empty() {
            Vec::new()
        } else {
            vec![super::go_shards::GoPackage {
                import_path: "example.test/fixture".to_string(),
                source_documents: selected_documents
                    .iter()
                    .map(|path| RepositoryPath((*path).to_string()))
                    .collect(),
                source_bytes: 1,
            }]
        },
        ignored_documents: ignored_documents
            .iter()
            .map(|path| RepositoryPath((*path).to_string()))
            .collect(),
    }
}

#[test]
fn go_variant_inventory_requires_exact_nonempty_document_sets() {
    let plan = variant_plan("linux", &["fixture/main.go"], &["fixture/windows.go"]);
    let exact = package_inventory(&["fixture/main.go"], &["fixture/windows.go"]);
    validate_go_variant_inventory(&plan, &exact).unwrap();

    let drifted = package_inventory(&["fixture/invented.go"], &["fixture/other.go"]);
    let error = validate_go_variant_inventory(&plan, &drifted).unwrap_err();

    assert!(error.contains("missing_selected=[\"fixture/main.go\"]"));
    assert!(error.contains("invented_selected=[\"fixture/invented.go\"]"));
    assert!(error.contains("missing_ignored=[\"fixture/windows.go\"]"));
    assert!(error.contains("invented_ignored=[\"fixture/other.go\"]"));
}

#[test]
fn empty_go_variant_uses_the_committed_ignored_ledger_without_inventing_paths() {
    let plan = variant_plan("linux-empty", &[], &["fixture/only_windows.go"]);
    validate_go_variant_inventory(&plan, &package_inventory(&[], &[])).unwrap();
    validate_go_variant_inventory(&plan, &package_inventory(&[], &["fixture/only_windows.go"]))
        .unwrap();

    let invented = package_inventory(&[], &["fixture/invented.go"]);
    let error = validate_go_variant_inventory(&plan, &invented).unwrap_err();

    assert!(error.contains("invented_ignored=[\"fixture/invented.go\"]"));
}

#[test]
fn bounded_merge_failure_is_processless_snapshot_assembly() {
    let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
    let failure = go_snapshot_assembly_failure(spec, "document shards overlap");

    assert_eq!(
        failure.kind,
        SemanticIndexerRunFailureKind::IncompleteOutput
    );
    assert_eq!(failure.phase, SemanticIndexerRunPhase::SnapshotAssembly);
    assert!(failure.process.is_none());
}

#[tokio::test]
async fn completed_progress_unit_skips_the_compiler_invocation() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let unit = SemanticProgressUnit::new(
        "document-00000000".to_string(),
        "document-shard",
        vec!["example.test/pkg".to_string()],
        &BTreeSet::from([RepositoryPath("pkg/pkg.go".to_string())]),
        true,
    )
    .unwrap();
    let scope = SemanticProgressScope::new(SemanticProgressScopeInputs {
        indexer: SemanticIndexerKind::Go,
        indexer_version: "test".to_string(),
        installation_tree_sha256: digest('1'),
        runtime_sha256: digest('2'),
        repository_content_sha256: digest('3'),
        file_scope_sha256: digest('4'),
        variant: crate::semantic_index::SemanticIndexVariant::Unqualified,
        build_context: BTreeMap::from([("GOOS".to_string(), "linux".to_string())]),
        build_context_output_sha256: digest('5'),
        package_inventory_sha256: digest('6'),
        shard_plan_sha256: digest('7'),
        units: vec![unit.clone()],
    })
    .unwrap();
    let progress = SemanticProgressStore::open(state.path(), scope).unwrap();
    let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
    let calls = std::cell::Cell::new(0_usize);

    run_or_resume_go_unit(Some(&progress), &unit, repository.path(), spec, || async {
        calls.set(calls.get() + 1);
        Ok(empty_index(repository.path()))
    })
    .await
    .unwrap();
    run_or_resume_go_unit(Some(&progress), &unit, repository.path(), spec, || async {
        calls.set(calls.get() + 1);
        Ok(empty_index(repository.path()))
    })
    .await
    .unwrap();

    assert_eq!(calls.get(), 1);
}

#[tokio::test]
#[ignore = "requires the installed pinned Go semantic indexer"]
async fn live_multi_shard_go_index_preserves_calls_and_structural_implementations() {
    let repository = tempfile::tempdir().unwrap();
    fs::write(
        repository.path().join("go.mod"),
        "module example.test/sharded\n\ngo 1.22\n",
    )
    .unwrap();
    let files = vec![
        write_go_file(
            repository.path(),
            "contract/contract.go",
            "package contract\n\ntype Speaker interface { Speak() string }\n\nfunc Invoke(s Speaker) string { return s.Speak() }\n",
        ),
        write_go_file(
            repository.path(),
            "impl/impl.go",
            "package impl\n\ntype Dog struct{}\n\nfunc (Dog) Speak() string { return \"woof\" }\n",
        ),
        write_go_file(
            repository.path(),
            "app/app.go",
            "package app\n\nimport (\n    \"example.test/sharded/contract\"\n    \"example.test/sharded/impl\"\n)\n\nfunc Run() string { return contract.Invoke(impl.Dog{}) }\n",
        ),
    ];
    let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
    let store = SemanticIndexerStore::for_user().unwrap();
    let installed = store.verify(spec).unwrap();
    let recovery = SemanticIndexerRecoveryGuard::begin(repository.path()).unwrap();

    let repository_content_sha256 =
        repository_snapshot::repository_content_digest(repository.path()).unwrap();
    let inputs = GoIndexerRunInputs {
        spec,
        root: repository.path(),
        installed: &installed,
        files: &files,
        required_documents: &files,
        recovery: &recovery,
        repository_content_sha256: &repository_content_sha256,
        progress_root: None,
    };
    let result = run_required_go_indexer_with_limits(
        &inputs,
        GoShardLimits {
            target_source_bytes: u64::MAX,
            max_packages: 1,
        },
    )
    .await;
    recovery.finish().unwrap();
    let index = result.unwrap();

    assert_eq!(
        index.documents.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            RepositoryPath("app/app.go".to_string()),
            RepositoryPath("contract/contract.go".to_string()),
            RepositoryPath("impl/impl.go".to_string()),
        ])
    );
    let contribution_count = |contribution| {
        index
            .provenance
            .invocations
            .iter()
            .filter(|invocation| invocation.contribution == contribution)
            .count()
    };
    assert_eq!(
        contribution_count(SemanticIndexerContribution::BuildContextDiscovery),
        1
    );
    assert_eq!(
        contribution_count(SemanticIndexerContribution::PackageInventory),
        1
    );
    assert_eq!(
        contribution_count(SemanticIndexerContribution::DocumentShard),
        3
    );
    assert_eq!(
        contribution_count(SemanticIndexerContribution::ImplementationPair),
        3
    );

    let run = symbol_id(&index, "Run");
    let invoke = symbol_id(&index, "Invoke");
    assert!(index.calls.iter().any(|call| {
        call.caller == run
            && call.callee
                == SemanticResolution::Resolved {
                    value: invoke.clone(),
                }
    }));

    let dog = symbol_id(&index, "Dog");
    let speaker = symbol_id(&index, "Speaker");
    assert!(index.relationships.iter().any(|relationship| {
        relationship.kind == SemanticRelationshipKind::Implementation
            && relationship.source == dog
            && relationship.target == speaker
    }));
}

#[tokio::test]
#[ignore = "requires Go and the installed pinned Go semantic indexer"]
async fn live_empty_go_variant_is_recorded_without_a_scip_invocation() {
    let repository = tempfile::tempdir().unwrap();
    fs::write(
        repository.path().join("go.mod"),
        "module example.test/empty\n\ngo 1.22\n",
    )
    .unwrap();
    let files = vec![write_go_file(
        repository.path(),
        "only_windows.go",
        "package empty\n\nfunc WindowsOnly() {}\n",
    )];
    let plan = variant_plan("linux-empty", &[], &["only_windows.go"]);
    let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
    let store = SemanticIndexerStore::for_user().unwrap();
    let installed = store.verify(spec).unwrap();
    let recovery = SemanticIndexerRecoveryGuard::begin(repository.path()).unwrap();
    let repository_content_sha256 =
        repository_snapshot::repository_content_digest(repository.path()).unwrap();
    let inputs = GoIndexerRunInputs {
        spec,
        root: repository.path(),
        installed: &installed,
        files: &files,
        required_documents: &[],
        recovery: &recovery,
        repository_content_sha256: &repository_content_sha256,
        progress_root: None,
    };

    let result = run_required_go_indexer_variants_with_limits(
        &inputs,
        std::slice::from_ref(&plan),
        GoShardLimits {
            target_source_bytes: u64::MAX,
            max_packages: 1,
        },
    )
    .await;
    recovery.finish().unwrap();
    let SemanticIndexSet::Qualified { variants } = result.unwrap() else {
        panic!("expected a qualified Go semantic index set");
    };
    let QualifiedSemanticIndex {
        index,
        ignored_documents,
    } = variants.get(&plan.identity).unwrap();

    assert_eq!(index.provenance.format, "go-compiler-empty-world");
    assert_eq!(index.provenance.tool_name, "go");
    assert_eq!(index.variant, plan.index_variant());
    assert!(index.documents.is_empty());
    assert!(index.symbols.is_empty());
    assert_eq!(ignored_documents, &plan.ignored_documents);
    assert_eq!(index.provenance.invocations.len(), 2);
    assert_eq!(
        index
            .provenance
            .invocations
            .iter()
            .map(|invocation| invocation.contribution)
            .collect::<Vec<_>>(),
        vec![
            SemanticIndexerContribution::BuildContextDiscovery,
            SemanticIndexerContribution::PackageInventory,
        ]
    );
}
