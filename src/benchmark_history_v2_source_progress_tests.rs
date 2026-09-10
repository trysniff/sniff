use super::*;
use std::cell::Cell;
use std::fs;

fn digest(character: char) -> String {
    character.to_string().repeat(64)
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

#[test]
fn completed_unit_resumes_only_under_its_exact_identity() {
    let state = tempfile::tempdir().unwrap();
    let root = state.path().join("source-progress");
    let progress = HistoricalV2SourceProgress::open(&root).unwrap();
    let materialization = materialization();
    let revision = materialization.base_revision.clone();
    let dependencies = vec![digest('5')];
    let payload = vec!["completed".to_string()];

    progress
        .publish(
            &materialization,
            HistoricalV2SourceSnapshotSide::Base,
            &revision,
            HistoricalV2SourceProgressUnit::GoProjectModel,
            &dependencies,
            &payload,
        )
        .unwrap();
    assert_eq!(
        progress
            .load::<Vec<String>>(
                &materialization,
                HistoricalV2SourceSnapshotSide::Base,
                &revision,
                HistoricalV2SourceProgressUnit::GoProjectModel,
                &dependencies,
            )
            .unwrap(),
        Some(payload.clone())
    );
    assert!(
        progress
            .load::<Vec<String>>(
                &materialization,
                HistoricalV2SourceSnapshotSide::Base,
                &revision,
                HistoricalV2SourceProgressUnit::GoProjectModel,
                &[digest('6')],
            )
            .unwrap_err()
            .contains("changed immutable evidence")
    );
    assert!(
        progress
            .publish(
                &materialization,
                HistoricalV2SourceSnapshotSide::Base,
                &revision,
                HistoricalV2SourceProgressUnit::GoProjectModel,
                &dependencies,
                &payload,
            )
            .unwrap_err()
            .contains("already exists")
    );
}

#[test]
fn completed_unit_skips_the_production_compute_path_on_resume() {
    let state = tempfile::tempdir().unwrap();
    let progress = HistoricalV2SourceProgress::open(&state.path().join("source-progress")).unwrap();
    let materialization = materialization();
    let revision = materialization.base_revision.clone();
    let calls = Cell::new(0_usize);
    let compute = || {
        calls.set(calls.get() + 1);
        Ok(vec!["computed".to_string()])
    };

    let first = super::super::execution::source_progress_value(
        Some(&progress),
        &materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &revision,
        HistoricalV2SourceProgressUnit::CargoProjectModel,
        &[],
        compute,
        |_| Ok(()),
    )
    .unwrap();
    let second = super::super::execution::source_progress_value(
        Some(&progress),
        &materialization,
        HistoricalV2SourceSnapshotSide::Base,
        &revision,
        HistoricalV2SourceProgressUnit::CargoProjectModel,
        &[],
        compute,
        |_| Ok(()),
    )
    .unwrap();

    assert_eq!(first, vec!["computed"]);
    assert_eq!(second, first);
    assert_eq!(calls.get(), 1);
}

#[test]
fn changed_schema_and_payload_are_rejected() {
    let state = tempfile::tempdir().unwrap();
    let root = state.path().join("source-progress");
    let progress = HistoricalV2SourceProgress::open(&root).unwrap();
    let materialization = materialization();
    let revision = materialization.base_revision.clone();
    let dependencies = vec![digest('5')];
    progress
        .publish(
            &materialization,
            HistoricalV2SourceSnapshotSide::Base,
            &revision,
            HistoricalV2SourceProgressUnit::Inventory,
            &dependencies,
            &"payload",
        )
        .unwrap();
    let path = progress
        .side_root(HistoricalV2SourceSnapshotSide::Base)
        .join(HistoricalV2SourceProgressUnit::Inventory.file_name());
    let mut checkpoint: SourceProgressCheckpoint =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    checkpoint.schema_version = 0;
    checkpoint.checkpoint_sha256.clear();
    checkpoint.checkpoint_sha256 = canonical_sha256(&checkpoint).unwrap();
    fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    assert!(
        progress
            .load::<String>(
                &materialization,
                HistoricalV2SourceSnapshotSide::Base,
                &revision,
                HistoricalV2SourceProgressUnit::Inventory,
                &dependencies,
            )
            .unwrap_err()
            .contains("changed immutable evidence")
    );

    checkpoint.schema_version = SOURCE_PROGRESS_SCHEMA_VERSION;
    checkpoint.payload = serde_json::json!("changed");
    fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    assert!(
        progress
            .load::<String>(
                &materialization,
                HistoricalV2SourceSnapshotSide::Base,
                &revision,
                HistoricalV2SourceProgressUnit::Inventory,
                &dependencies,
            )
            .unwrap_err()
            .contains("changed immutable evidence")
    );
}

#[test]
fn recovery_removes_known_temporary_files_and_rejects_unknown_entries() {
    let state = tempfile::tempdir().unwrap();
    let root = state.path().join("source-progress");
    let progress = HistoricalV2SourceProgress::open(&root).unwrap();
    let temp = progress
        .side_root(HistoricalV2SourceSnapshotSide::Patched)
        .join(HistoricalV2SourceProgressUnit::ParserCensus.temp_file_name());
    fs::write(&temp, b"partial").unwrap();
    HistoricalV2SourceProgress::recover_existing(&root).unwrap();
    assert!(!temp.exists());

    fs::write(root.join("base").join("unexpected.json"), b"{}").unwrap();
    assert!(
        HistoricalV2SourceProgress::open(&root)
            .unwrap_err()
            .contains("unexpected entry")
    );
}

#[cfg(unix)]
#[test]
fn source_progress_rejects_symlinked_entries() {
    use std::os::unix::fs::symlink;

    let state = tempfile::tempdir().unwrap();
    let root = state.path().join("source-progress");
    HistoricalV2SourceProgress::open(&root).unwrap();
    let outside = state.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    symlink(
        &outside,
        root.join("base")
            .join(HistoricalV2SourceProgressUnit::Inventory.file_name()),
    )
    .unwrap();
    assert!(
        HistoricalV2SourceProgress::open(&root)
            .unwrap_err()
            .contains("symlink")
    );
}
