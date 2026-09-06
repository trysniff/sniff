use super::*;
use crate::benchmark::{
    HISTORICAL_V2_NODE_PACKAGE_SURFACE_CENSUS_SCHEMA_VERSION,
    HISTORICAL_V2_PYTHON_DISTRIBUTION_SURFACE_CENSUS_SCHEMA_VERSION,
    HistoricalV2NodePackageSurfaceCensus, HistoricalV2PythonDistributionSurfaceCensus,
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryProjectModelCensus,
};
use std::fs;

fn digest(character: char) -> String {
    character.to_string().repeat(64)
}

fn empty_cargo_project_model(revision: &str) -> IntentionalBoundaryProjectModelCensus {
    IntentionalBoundaryProjectModelCensus {
        schema_version: INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
        project_model_contract: "fixture".to_string(),
        repository: "example/repository".to_string(),
        revision: revision.to_string(),
        inventory_sha256: digest('1'),
        executions: Vec::new(),
        targets: Vec::new(),
        execution_count_by_provider: BTreeMap::new(),
        target_count_by_status: BTreeMap::new(),
        project_model_census_sha256: digest('0'),
    }
}

fn empty_node_package_surfaces(revision: &str) -> HistoricalV2NodePackageSurfaceCensus {
    HistoricalV2NodePackageSurfaceCensus {
        schema_version: HISTORICAL_V2_NODE_PACKAGE_SURFACE_CENSUS_SCHEMA_VERSION,
        contract: "fixture".to_string(),
        repository: "example/repository".to_string(),
        revision: revision.to_string(),
        inventory_sha256: digest('1'),
        documents: Vec::new(),
        exposures: Vec::new(),
        exposure_count_by_entry_kind: BTreeMap::new(),
        census_sha256: digest('9'),
    }
}

fn empty_python_distribution_surfaces(
    revision: &str,
) -> HistoricalV2PythonDistributionSurfaceCensus {
    HistoricalV2PythonDistributionSurfaceCensus {
        schema_version: HISTORICAL_V2_PYTHON_DISTRIBUTION_SURFACE_CENSUS_SCHEMA_VERSION,
        contract: "fixture".to_string(),
        repository: "example/repository".to_string(),
        revision: revision.to_string(),
        inventory_sha256: digest('1'),
        distributions: Vec::new(),
        modules: Vec::new(),
        module_count_by_kind: BTreeMap::new(),
        census_sha256: digest('8'),
    }
}

fn source_snapshot(revision: &str, digest_character: char) -> HistoricalV2SourceSnapshotCensus {
    HistoricalV2SourceSnapshotCensus {
        revision: revision.to_string(),
        inventory_sha256: digest('1'),
        parser_census_sha256: digest('2'),
        cargo_project_model: empty_cargo_project_model(revision),
        node_package_surfaces: empty_node_package_surfaces(revision),
        python_distribution_surfaces: empty_python_distribution_surfaces(revision),
        tracked_entry_count: 0,
        source_files: Vec::new(),
        source_file_count: 0,
        method_counts_by_language: BTreeMap::new(),
        method_count: 0,
        public_declaration_count: 0,
        public_reexport_count: 0,
        snapshot_census_sha256: digest(digest_character),
    }
}

fn materialization() -> HistoricalV2Materialization {
    HistoricalV2Materialization {
        schema_version: 1,
        materialization_contract: "fixture".to_string(),
        canonical_repository: "example/repository".to_string(),
        base_revision: "a".repeat(40),
        object_format: "sha1".to_string(),
        base_tree_oid: "b".repeat(40),
        historical_patch_sha256: digest('3'),
        patched_tree_oid: "c".repeat(40),
        patched_commit_oid: "d".repeat(40),
        materialization_sha256: digest('4'),
    }
}

fn source_census() -> HistoricalV2SourceCensus {
    HistoricalV2SourceCensus {
        schema_version: 2,
        source_census_contract: "fixture".to_string(),
        canonical_repository: "example/repository".to_string(),
        materialization_sha256: digest('4'),
        base: source_snapshot(&"a".repeat(40), '5'),
        patched: source_snapshot(&"d".repeat(40), '6'),
        source_census_sha256: digest('7'),
    }
}

fn semantic_snapshot(
    source: &HistoricalV2SourceSnapshotCensus,
) -> HistoricalV2SemanticSnapshotCensus {
    HistoricalV2SemanticSnapshotCensus {
        revision: source.revision.clone(),
        source_snapshot_census_sha256: source.snapshot_census_sha256.clone(),
        required_document_paths: Vec::new(),
        public_surface_document_paths: Vec::new(),
        indexers: Vec::new(),
        methods: Vec::new(),
        public_bindings: Vec::new(),
        public_roots: Vec::new(),
        public_reexport_hops: Vec::new(),
        symbols: Vec::new(),
        symbol_count: 0,
        public_binding_count: 0,
        public_root_count: 0,
        public_reexport_hop_count: 0,
        public_symbol_count: 0,
        resolved_method_count: 0,
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        semantic_snapshot_sha256: digest('8'),
    }
}

#[test]
fn completed_snapshot_resumes_only_under_the_exact_identity() {
    let state = tempfile::tempdir().unwrap();
    let root = state.path().join("progress");
    let progress = HistoricalV2SemanticProgress::open(&root).unwrap();
    let materialization = materialization();
    let source_census = source_census();
    let changed = BTreeSet::from([SemanticIndexerKind::Go]);
    let required = BTreeSet::new();
    let snapshot = semantic_snapshot(&source_census.base);
    progress
        .publish_snapshot(
            &materialization,
            &source_census,
            HistoricalV2SemanticSnapshotSide::Base,
            &source_census.base,
            &changed,
            &required,
            &snapshot,
        )
        .unwrap();

    assert_eq!(
        progress
            .load_snapshot(
                &materialization,
                &source_census,
                HistoricalV2SemanticSnapshotSide::Base,
                &source_census.base,
                &changed,
                &required,
            )
            .unwrap(),
        Some(snapshot)
    );
    let mut changed_source = source_census.clone();
    changed_source.source_census_sha256 = digest('9');
    assert!(
        progress
            .load_snapshot(
                &materialization,
                &changed_source,
                HistoricalV2SemanticSnapshotSide::Base,
                &changed_source.base,
                &changed,
                &required,
            )
            .is_err()
    );
}

#[test]
fn previous_snapshot_progress_schema_is_not_reinterpreted() {
    let state = tempfile::tempdir().unwrap();
    let root = state.path().join("progress");
    let progress = HistoricalV2SemanticProgress::open(&root).unwrap();
    let materialization = materialization();
    let source_census = source_census();
    let changed = BTreeSet::from([SemanticIndexerKind::Go]);
    let required = BTreeSet::new();
    let snapshot = semantic_snapshot(&source_census.base);
    progress
        .publish_snapshot(
            &materialization,
            &source_census,
            HistoricalV2SemanticSnapshotSide::Base,
            &source_census.base,
            &changed,
            &required,
            &snapshot,
        )
        .unwrap();
    let path = progress
        .side_root(HistoricalV2SemanticSnapshotSide::Base)
        .join(SNAPSHOT_FILE);
    let mut checkpoint: SnapshotCheckpoint =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    checkpoint.schema_version = SNAPSHOT_PROGRESS_SCHEMA_VERSION - 1;
    checkpoint.progress_contract = "historical-v2-semantic-snapshot-progress-v1".to_string();
    checkpoint.checkpoint_sha256.clear();
    checkpoint.checkpoint_sha256 = canonical_sha256(&checkpoint).unwrap();
    fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();

    assert!(
        progress
            .load_snapshot(
                &materialization,
                &source_census,
                HistoricalV2SemanticSnapshotSide::Base,
                &source_census.base,
                &changed,
                &required,
            )
            .unwrap_err()
            .contains("changed immutable evidence")
    );
}

#[test]
fn corrupt_extra_and_incomplete_snapshot_entries_are_not_trusted() {
    let state = tempfile::tempdir().unwrap();
    let root = state.path().join("progress");
    let progress = HistoricalV2SemanticProgress::open(&root).unwrap();
    fs::write(
        progress
            .side_root(HistoricalV2SemanticSnapshotSide::Base)
            .join(SNAPSHOT_TEMP_FILE),
        b"partial",
    )
    .unwrap();
    HistoricalV2SemanticProgress::recover_existing(&root).unwrap();
    assert!(
        !progress
            .side_root(HistoricalV2SemanticSnapshotSide::Base)
            .join(SNAPSHOT_TEMP_FILE)
            .exists()
    );

    fs::write(
        progress
            .side_root(HistoricalV2SemanticSnapshotSide::Base)
            .join("unexpected.json"),
        b"{}\n",
    )
    .unwrap();
    assert!(HistoricalV2SemanticProgress::open(&root).is_err());
}

#[cfg(unix)]
#[test]
fn dangling_progress_root_symlink_fails_closed() {
    use std::os::unix::fs::symlink;

    let state = tempfile::tempdir().unwrap();
    let missing = state.path().join("missing");
    let progress = state.path().join("progress");
    symlink(&missing, &progress).unwrap();

    assert!(HistoricalV2SemanticProgress::recover_existing(&progress).is_err());
}
