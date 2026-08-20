use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub(super) fn build_bundle(
    prepared: &PreparedReviewSlot<'_>,
) -> Result<HistoricalV2SourceReviewBundle, String> {
    let snapshots = vec![
        review_snapshot(
            HistoricalV2ReviewSnapshotSide::Before,
            &prepared.roots.base_root,
            &prepared.before_inventory,
            &prepared.materialization.base_tree_oid,
            &prepared.source_census.base.snapshot_census_sha256,
        )?,
        review_snapshot(
            HistoricalV2ReviewSnapshotSide::After,
            &prepared.roots.patched_root,
            &prepared.after_inventory,
            &prepared.materialization.patched_tree_oid,
            &prepared.source_census.patched.snapshot_census_sha256,
        )?,
    ];
    let review_item_id = format!(
        "hvr-v1:{}",
        review_hash_json(&(
            REVIEW_ITEM_CONTRACT,
            &prepared.protocol.protocol_sha256,
            prepared.selection_sha256,
            prepared.terminal_checkpoint_sha256,
        ))?
    );
    let mut changed_methods = prepared
        .qualification
        .changed_methods
        .iter()
        .map(|method| HistoricalV2ReviewChangedMethod {
            side: method.side,
            language: method.language.clone(),
            repository_path: method.repository_path.clone(),
            symbol_name: method.symbol_name.clone(),
            start_line: method.start_line,
            end_line: method.end_line,
            source_sha256: method.source_sha256.clone(),
        })
        .collect::<Vec<_>>();
    changed_methods.sort();
    changed_methods.dedup();
    let behavior = HistoricalV2ReviewBehaviorEvidence {
        test_plan_sha256: prepared.plan.plan_sha256.clone(),
        execution_sha256: prepared.execution.execution_sha256.clone(),
        events: prepared.execution.events.clone(),
    };
    let mut bundle = HistoricalV2SourceReviewBundle {
        schema_version: HISTORICAL_V2_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION,
        bundle_contract: BUNDLE_CONTRACT.to_string(),
        protocol_sha256: prepared.protocol.protocol_sha256.clone(),
        selection_sha256: prepared.selection_sha256.to_string(),
        assessment_identity_sha256: prepared.assessment.assessment_identity_sha256.clone(),
        terminal_checkpoint_sha256: prepared.terminal_checkpoint_sha256.to_string(),
        review_item_id,
        language: prepared.language.to_string(),
        source_only: true,
        sniff_output_included: false,
        dataset_judgments_included: false,
        public_surface_preserved: true,
        public_surface_delta_sha256: prepared.qualification.public_surface.delta_sha256.clone(),
        snapshots,
        changed_methods,
        behavior,
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = bundle_sha256(&bundle)?;
    validate_bundle_contract(&bundle)?;
    Ok(bundle)
}

fn review_snapshot(
    side: HistoricalV2ReviewSnapshotSide,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    tree_oid: &str,
    source_snapshot_sha256: &str,
) -> Result<HistoricalV2ReviewSourceSnapshot, String> {
    let artifacts = inventory
        .tracked_entries
        .iter()
        .map(|entry| {
            let (artifact_path, content_sha256) = match entry.byte_length {
                Some(length) => {
                    let bytes = read_intentional_boundary_git_blob(root, &entry.object_id, length)?;
                    let content_sha256 = review_sha256(&bytes);
                    (
                        Some(object_artifact_path(&content_sha256)),
                        Some(content_sha256),
                    )
                }
                None if entry.kind == BoundaryGitEntryKind::Gitlink => (None, None),
                None => return Err("historical-v2 review blob has no committed length".into()),
            };
            Ok(HistoricalV2ReviewSourceArtifact {
                repository_path: entry.repository_path.clone(),
                mode: entry.mode.clone(),
                kind: entry.kind,
                object_id: entry.object_id.clone(),
                byte_length: entry.byte_length,
                artifact_path,
                content_sha256,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(HistoricalV2ReviewSourceSnapshot {
        side,
        revision: inventory.revision.clone(),
        tree_oid: tree_oid.to_string(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_snapshot_sha256: source_snapshot_sha256.to_string(),
        tracked_entry_count: artifacts.len(),
        artifacts,
    })
}

pub(super) fn materialize_bundle(
    root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    prepared: &PreparedReviewSlot<'_>,
) -> Result<(), String> {
    let roots = BTreeMap::from([
        (
            HistoricalV2ReviewSnapshotSide::Before,
            prepared.roots.base_root.as_path(),
        ),
        (
            HistoricalV2ReviewSnapshotSide::After,
            prepared.roots.patched_root.as_path(),
        ),
    ]);
    let mut written = BTreeSet::new();
    for snapshot in &bundle.snapshots {
        let source_root = roots
            .get(&snapshot.side)
            .ok_or_else(|| "historical-v2 review snapshot root disappeared".to_string())?;
        for artifact in &snapshot.artifacts {
            let Some(relative) = &artifact.artifact_path else {
                continue;
            };
            if !written.insert(relative.clone()) {
                continue;
            }
            let length = artifact.byte_length.ok_or_else(|| {
                "historical-v2 review source artifact has no committed length".to_string()
            })?;
            let bytes =
                read_intentional_boundary_git_blob(source_root, &artifact.object_id, length)?;
            if artifact.content_sha256.as_deref() != Some(review_sha256(&bytes).as_str()) {
                return Err("historical-v2 review source changed during publication".into());
            }
            let path = review_safe_path(root, relative)?;
            fs::create_dir_all(path.parent().expect("object path has parent"))
                .map_err(|error| format!("failed to create review object directory: {error}"))?;
            write_review_file_new(&path, &bytes, "historical-v2 review object")?;
        }
    }
    let mut manifest = serde_json::to_vec_pretty(bundle)
        .map_err(|error| format!("failed to serialize historical-v2 review manifest: {error}"))?;
    manifest.push(b'\n');
    write_review_file_new(
        &root.join(MANIFEST_NAME),
        &manifest,
        "historical-v2 review manifest",
    )
}

pub(super) fn object_artifact_path(content_sha256: &str) -> String {
    format!("objects/{}/{}.blob", &content_sha256[..2], content_sha256)
}
