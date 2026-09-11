use super::*;
use crate::semantic_index::{
    SEMANTIC_INDEX_FORMAT_VERSION, SemanticIndexProvenance, SemanticIndexerContribution,
    SemanticIndexerInvocation,
};

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

fn second_unit() -> SemanticProgressUnit {
    SemanticProgressUnit::new(
        "document-0001".to_string(),
        "document-shard",
        vec!["example.test/other".to_string()],
        &BTreeSet::from([RepositoryPath("other/other.go".to_string())]),
        true,
    )
    .unwrap()
}

#[test]
fn compiler_world_progress_allows_an_explicit_empty_document_partition() {
    let unit = SemanticProgressUnit::new(
        "compiler-world".to_string(),
        "compiler-project",
        vec!["index".to_string(), "tsconfig.json".to_string()],
        &BTreeSet::new(),
        true,
    )
    .unwrap();

    assert!(unit.expected_documents.is_empty());
}

fn scope(unit: SemanticProgressUnit) -> SemanticProgressScope {
    scope_with_units(vec![unit])
}

fn scope_with_units(units: Vec<SemanticProgressUnit>) -> SemanticProgressScope {
    scope_with_variant(
        units,
        crate::semantic_index::SemanticIndexVariant::Unqualified,
    )
}

fn scope_with_variant(
    units: Vec<SemanticProgressUnit>,
    variant: crate::semantic_index::SemanticIndexVariant,
) -> SemanticProgressScope {
    SemanticProgressScope::new(SemanticProgressScopeInputs {
        indexer: SemanticIndexerKind::Go,
        indexer_version: "v1".to_string(),
        installation_tree_sha256: digest('1'),
        runtime_sha256: digest('2'),
        repository_content_sha256: digest('3'),
        file_scope_sha256: digest('4'),
        variant,
        compiler_context: BTreeMap::from([("GOOS".to_string(), "linux".to_string())]),
        compiler_context_sha256: digest('5'),
        document_partition_sha256: digest('6'),
        unit_plan_sha256: digest('7'),
        units,
    })
    .unwrap()
}

#[test]
fn qualified_world_recovery_reports_exact_progress_identity() {
    let state = tempfile::tempdir().unwrap();
    let family_root = state.path().join("go");
    fs::create_dir(&family_root).unwrap();
    let world = digest('a');
    let world_root = family_root.join(&world);
    let variant_identity = "ibpme-v7:fixture".to_string();
    let dimensions = BTreeMap::from([
        ("cgo_enabled".to_string(), "false".to_string()),
        ("goarch".to_string(), "amd64".to_string()),
        ("goos".to_string(), "linux".to_string()),
    ]);
    SemanticProgressStore::open(
        &world_root,
        scope_with_variant(
            vec![unit(), second_unit()],
            crate::semantic_index::SemanticIndexVariant::Qualified {
                identity: crate::semantic_index::SemanticVariantId(variant_identity.clone()),
                dimensions: dimensions.clone(),
            },
        ),
    )
    .unwrap();

    let recovered = super::super::recover_semantic_indexer_progress(state.path()).unwrap();

    assert_eq!(recovered.len(), 1);
    let recovered = &recovered[0];
    assert_eq!(recovered.family, "go");
    assert_eq!(recovered.world, world);
    assert_eq!(
        recovered.variant_identity.as_deref(),
        Some(&*variant_identity)
    );
    assert_eq!(recovered.dimensions, dimensions);
    assert_eq!(recovered.planned_unit_count, 2);
    assert_eq!(recovered.completed_unit_count, 0);
    assert_eq!(recovered.next_unit_id.as_deref(), Some("document-0000"));
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
            invocations: vec![SemanticIndexerInvocation {
                arguments: vec!["fixture".to_string()],
                context: BTreeMap::new(),
                contribution: SemanticIndexerContribution::CompleteIndex,
                output_sha256: digest('a'),
            }],
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

#[cfg(windows)]
#[test]
fn windows_verbatim_payload_root_normalizes_to_the_same_repository() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let unit = unit();
    let scope = scope(unit.clone());
    let store = SemanticProgressStore::open(state.path(), scope).unwrap();
    let mut payload = index(repository.path());
    payload.repository_root = format!("//?/{}", payload.repository_root.replace('\\', "/"));

    store.publish(&unit, repository.path(), &payload).unwrap();

    assert!(store.load(&unit, repository.path()).unwrap().is_some());
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

    let recovery = SemanticProgressStore::recover_existing(state.path())
        .unwrap()
        .unwrap();

    assert!(store.unit_path(&unit).is_file());
    assert!(!store.unit_temp_path(&unit).exists());
    assert!(store.load(&unit, repository.path()).unwrap().is_some());
    assert_eq!(recovery.variant_identity, None);
    assert!(recovery.dimensions.is_empty());
    assert_eq!(recovery.planned_unit_count, 1);
    assert_eq!(recovery.completed_unit_count, 0);
    assert_eq!(recovery.next_unit_id.as_deref(), Some("document-0000"));
}

#[test]
fn assembled_prefix_survives_relocation_and_supersedes_older_prefix() {
    use crate::semantic_index_merge::{begin_document_shard, merge_document_shard};

    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let units = vec![unit(), second_unit()];
    let store = SemanticProgressStore::open(state.path(), scope_with_units(units.clone())).unwrap();
    for unit in &units {
        store
            .publish(unit, first.path(), &index(first.path()))
            .unwrap();
    }

    let first_unit = store.load(&units[0], first.path()).unwrap().unwrap();
    let assembled = begin_document_shard(first_unit).unwrap();
    store
        .publish_assembly(&units[..1], first.path(), &assembled)
        .unwrap();
    let mut resumed = store.load_assembly(second.path()).unwrap().unwrap();
    assert_eq!(resumed.completed_unit_count, 1);
    assert_eq!(
        resumed.payload.repository_root,
        canonical_root_text(second.path()).unwrap()
    );

    let second_unit = store.load(&units[1], second.path()).unwrap().unwrap();
    merge_document_shard(&mut resumed.payload, second_unit).unwrap();
    store
        .publish_assembly(&units, second.path(), &resumed.payload)
        .unwrap();
    assert!(!store.assembly_path(1).exists());
    assert!(store.assembly_path(2).is_file());
    for unit in &units {
        assert!(!store.unit_path(unit).exists());
    }
    let recovery = SemanticProgressStore::recover_existing(state.path())
        .unwrap()
        .unwrap();
    let completed = store.load_assembly(second.path()).unwrap().unwrap();
    assert_eq!(completed.completed_unit_count, 2);
    assert_eq!(completed.payload.provenance.invocations.len(), 2);
    assert_eq!(recovery.planned_unit_count, 2);
    assert_eq!(recovery.completed_unit_count, 2);
    assert_eq!(recovery.next_unit_id, None);
}

#[test]
fn recovery_finishes_interrupted_final_unit_pruning() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let units = vec![unit(), second_unit()];
    let store = SemanticProgressStore::open(state.path(), scope_with_units(units.clone())).unwrap();
    for unit in &units {
        store
            .publish(unit, repository.path(), &index(repository.path()))
            .unwrap();
    }
    let first_checkpoint = fs::read(store.unit_path(&units[0])).unwrap();
    store
        .publish_assembly(&units, repository.path(), &index(repository.path()))
        .unwrap();
    fs::write(store.unit_path(&units[0]), first_checkpoint).unwrap();

    SemanticProgressStore::recover_existing(state.path()).unwrap();

    for unit in &units {
        assert!(!store.unit_path(unit).exists());
    }
    assert_eq!(
        store
            .load_assembly(repository.path())
            .unwrap()
            .unwrap()
            .completed_unit_count,
        2
    );
}

#[test]
fn assembly_rejects_non_prefix_and_changed_unit_evidence() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let units = vec![unit(), second_unit()];
    let store = SemanticProgressStore::open(state.path(), scope_with_units(units.clone())).unwrap();
    for unit in &units {
        store
            .publish(unit, repository.path(), &index(repository.path()))
            .unwrap();
    }
    assert!(
        store
            .publish_assembly(&units[1..], repository.path(), &index(repository.path()))
            .is_err()
    );
    store
        .publish_assembly(&units[..1], repository.path(), &index(repository.path()))
        .unwrap();
    fs::write(store.unit_path(&units[0]), b"changed\n").unwrap();
    assert!(store.load_assembly(repository.path()).is_err());
}

#[test]
fn recovery_removes_incomplete_assembly_transaction() {
    let state = tempfile::tempdir().unwrap();
    let unit = unit();
    let store = SemanticProgressStore::open(state.path(), scope(unit)).unwrap();
    fs::write(store.assembly_temp_path(1), b"partial").unwrap();
    fs::write(store.assembly_payload_temp_path(1), b"partial").unwrap();

    SemanticProgressStore::recover_existing(state.path()).unwrap();

    assert!(!store.assembly_temp_path(1).exists());
    assert!(!store.assembly_payload_temp_path(1).exists());
}

#[test]
fn recovery_removes_uncommitted_payload_and_payload_tampering_fails_closed() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let unit = unit();
    let store = SemanticProgressStore::open(state.path(), scope(unit.clone())).unwrap();
    fs::write(store.assembly_payload_path(1), b"uncommitted\n").unwrap();
    SemanticProgressStore::recover_existing(state.path()).unwrap();
    assert!(!store.assembly_payload_path(1).exists());

    store
        .publish(&unit, repository.path(), &index(repository.path()))
        .unwrap();
    store
        .publish_assembly(&[unit], repository.path(), &index(repository.path()))
        .unwrap();
    fs::write(store.assembly_payload_path(1), b"changed\n").unwrap();
    assert!(store.load_assembly(repository.path()).is_err());
}

#[test]
fn recovery_validates_overlapping_commits_before_pruning_the_older_prefix() {
    let repository = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let units = vec![unit(), second_unit()];
    let store = SemanticProgressStore::open(state.path(), scope_with_units(units.clone())).unwrap();
    for unit in &units {
        store
            .publish(unit, repository.path(), &index(repository.path()))
            .unwrap();
    }
    store
        .publish_assembly(&units[..1], repository.path(), &index(repository.path()))
        .unwrap();
    let older = fs::read(store.assembly_path(1)).unwrap();
    let older_payload = fs::read(store.assembly_payload_path(1)).unwrap();
    let unit_checkpoints = units
        .iter()
        .map(|unit| fs::read(store.unit_path(unit)).unwrap())
        .collect::<Vec<_>>();
    store
        .publish_assembly(&units, repository.path(), &index(repository.path()))
        .unwrap();
    for (unit, checkpoint) in units.iter().zip(unit_checkpoints) {
        fs::write(store.unit_path(unit), checkpoint).unwrap();
    }
    fs::write(store.assembly_payload_path(1), older_payload).unwrap();
    fs::write(store.assembly_path(1), older).unwrap();

    SemanticProgressStore::recover_existing(state.path()).unwrap();

    assert!(!store.assembly_path(1).exists());
    assert!(store.assembly_path(2).is_file());
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
