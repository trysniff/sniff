use super::*;
use crate::semantic_index::{SEMANTIC_INDEX_FORMAT_VERSION, SemanticIndexProvenance};

fn digest(character: char) -> String {
    character.to_string().repeat(64)
}

fn unit() -> SemanticProgressUnit {
    SemanticProgressUnit::new(
        "document-0000".to_string(),
        "document-shard",
        vec!["example.test/pkg".to_string()],
        &BTreeSet::from([RepositoryPath("pkg/pkg.go".to_string())]),
        true,
    )
    .unwrap()
}

fn scope(unit: SemanticProgressUnit) -> SemanticProgressScope {
    SemanticProgressScope::new(SemanticProgressScopeInputs {
        indexer: SemanticIndexerKind::Go,
        indexer_version: "v1".to_string(),
        installation_tree_sha256: digest('1'),
        runtime_sha256: digest('2'),
        repository_content_sha256: digest('3'),
        file_scope_sha256: digest('4'),
        build_context: BTreeMap::from([("GOOS".to_string(), "linux".to_string())]),
        build_context_output_sha256: digest('5'),
        package_inventory_sha256: digest('6'),
        shard_plan_sha256: digest('7'),
        units: vec![unit],
    })
    .unwrap()
}

fn index(root: &Path) -> SemanticIndex {
    SemanticIndex {
        format_version: SEMANTIC_INDEX_FORMAT_VERSION,
        repository_root: canonical_root_text(root).unwrap(),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: "scip-go".to_string(),
            tool_version: Some("v1".to_string()),
            arguments: Vec::new(),
            source_text_encoding: None,
            invocations: Vec::new(),
            diagnostics: Vec::new(),
        },
        documents: BTreeMap::new(),
        symbols: BTreeMap::new(),
        relationships: BTreeSet::new(),
        imports: BTreeSet::new(),
        calls: BTreeSet::new(),
        test_relationships: BTreeSet::new(),
        unresolved_edges: BTreeSet::new(),
    }
}

#[test]
fn completed_unit_survives_repository_relocation() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let unit = unit();
    let scope = scope(unit.clone());
    let store = SemanticProgressStore::open(state.path(), scope.clone()).unwrap();
    store
        .publish(&unit, first.path(), &index(first.path()))
        .unwrap();
    let resumed = SemanticProgressStore::open(state.path(), scope)
        .unwrap()
        .load(&unit, second.path())
        .unwrap()
        .unwrap();
    assert_eq!(
        resumed.repository_root,
        canonical_root_text(second.path()).unwrap()
    );
}

#[test]
fn changed_scope_and_corrupt_or_extra_evidence_fail_closed() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let unit = unit();
    let original = scope(unit.clone());
    let store = SemanticProgressStore::open(state.path(), original.clone()).unwrap();
    store
        .publish(&unit, repository.path(), &index(repository.path()))
        .unwrap();

    let mut changed = original.clone();
    changed.repository_content_sha256 = digest('8');
    changed.scope_sha256.clear();
    changed.scope_sha256 = canonical_sha256(&changed).unwrap();
    assert!(SemanticProgressStore::open(state.path(), changed).is_err());

    let checkpoint = store.unit_path(&unit);
    fs::write(&checkpoint, b"{}\n").unwrap();
    assert!(store.load(&unit, repository.path()).is_err());
    fs::write(
        state.path().join(UNITS_DIRECTORY).join("unexpected.json"),
        b"{}\n",
    )
    .unwrap();
    assert!(store.load(&unit, repository.path()).is_err());
}

#[test]
fn incomplete_unit_transaction_is_removed_before_resume() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let unit = unit();
    let store = SemanticProgressStore::open(state.path(), scope(unit.clone())).unwrap();
    fs::write(store.unit_temp_path(&unit), b"partial").unwrap();
    assert!(store.load(&unit, repository.path()).unwrap().is_none());
    assert!(!store.unit_temp_path(&unit).exists());
}

#[test]
fn recovery_preserves_completed_units_and_removes_only_incomplete_transactions() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let unit = unit();
    let store = SemanticProgressStore::open(state.path(), scope(unit.clone())).unwrap();
    store
        .publish(&unit, repository.path(), &index(repository.path()))
        .unwrap();
    fs::write(store.unit_temp_path(&unit), b"partial").unwrap();

    SemanticProgressStore::recover_existing(state.path()).unwrap();

    assert!(store.unit_path(&unit).is_file());
    assert!(!store.unit_temp_path(&unit).exists());
    assert!(store.load(&unit, repository.path()).unwrap().is_some());
}

#[cfg(unix)]
#[test]
fn symlinked_unit_checkpoint_fails_closed() {
    use std::os::unix::fs::symlink;

    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let unit = unit();
    let store = SemanticProgressStore::open(state.path(), scope(unit.clone())).unwrap();
    symlink(outside.path(), store.unit_path(&unit)).unwrap();

    assert!(store.load(&unit, repository.path()).is_err());
}

#[cfg(unix)]
#[test]
fn dangling_progress_root_symlink_fails_closed() {
    use std::os::unix::fs::symlink;

    let state = tempfile::tempdir().unwrap();
    let missing = state.path().join("missing");
    let progress = state.path().join("progress");
    symlink(&missing, &progress).unwrap();

    assert!(SemanticProgressStore::recover_existing(&progress).is_err());
}
