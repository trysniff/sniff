use super::*;
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn validate_persisted_bundle(
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
) -> Result<(), String> {
    validate_bundle_contract(bundle)?;
    let manifest = read_plain_review_file(&bundle_root.join(MANIFEST_NAME), "review manifest")?;
    let persisted: HistoricalV2SourceReviewBundle = serde_json::from_slice(&manifest)
        .map_err(|error| format!("invalid historical-v2 review manifest: {error}"))?;
    if &persisted != bundle {
        return Err("historical-v2 persisted review manifest changed".to_string());
    }
    let mut expected_files = BTreeSet::from([MANIFEST_NAME.to_string()]);
    let mut sides = BTreeSet::new();
    for snapshot in &bundle.snapshots {
        if !sides.insert(snapshot.side)
            || snapshot.tracked_entry_count != snapshot.artifacts.len()
            || !is_review_object_id(&snapshot.revision)
            || !is_review_object_id(&snapshot.tree_oid)
            || !is_review_sha256(&snapshot.inventory_sha256)
            || !is_review_sha256(&snapshot.source_snapshot_sha256)
            || snapshot
                .artifacts
                .windows(2)
                .any(|pair| pair[0].repository_path >= pair[1].repository_path)
        {
            return Err("historical-v2 review snapshot commitment changed".to_string());
        }
        validate_snapshot_artifacts(bundle_root, snapshot, &mut expected_files)?;
    }
    if sides
        != BTreeSet::from([
            HistoricalV2ReviewSnapshotSide::Before,
            HistoricalV2ReviewSnapshotSide::After,
        ])
    {
        return Err("historical-v2 review bundle requires exact before and after snapshots".into());
    }
    validate_changed_methods(bundle_root, bundle)?;
    validate_behavior(&bundle.behavior)?;
    if collect_review_files(bundle_root)? != expected_files {
        return Err("historical-v2 review bundle contains unexpected or missing files".into());
    }
    Ok(())
}

pub(super) fn validate_bundle_contract(
    bundle: &HistoricalV2SourceReviewBundle,
) -> Result<(), String> {
    if bundle.schema_version != HISTORICAL_V2_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION
        || bundle.bundle_contract != BUNDLE_CONTRACT
        || bundle.bundle_sha256 != bundle_sha256(bundle)?
        || !bundle
            .review_item_id
            .strip_prefix("hvr-v1:")
            .is_some_and(is_review_sha256)
        || !bundle.source_only
        || bundle.sniff_output_included
        || bundle.dataset_judgments_included
        || !bundle.public_surface_preserved
        || bundle.snapshots.len() != 2
        || bundle.changed_methods.is_empty()
        || bundle
            .changed_methods
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || bundle.language.trim().is_empty()
        || ![
            &bundle.protocol_sha256,
            &bundle.selection_sha256,
            &bundle.assessment_identity_sha256,
            &bundle.terminal_checkpoint_sha256,
            &bundle.public_surface_delta_sha256,
            &bundle.behavior.test_plan_sha256,
            &bundle.behavior.execution_sha256,
        ]
        .into_iter()
        .all(|value| is_review_sha256(value))
    {
        return Err("historical-v2 source review bundle commitment changed".into());
    }
    Ok(())
}

fn validate_snapshot_artifacts(
    root: &Path,
    snapshot: &HistoricalV2ReviewSourceSnapshot,
    expected_files: &mut BTreeSet<String>,
) -> Result<(), String> {
    let mut repository_paths = BTreeSet::new();
    for artifact in &snapshot.artifacts {
        if !repository_paths.insert(artifact.repository_path.as_str())
            || artifact.repository_path.trim().is_empty()
            || !is_review_object_id(&artifact.object_id)
            || artifact.mode.trim().is_empty()
        {
            return Err("historical-v2 review source artifact metadata changed".into());
        }
        match (
            &artifact.artifact_path,
            &artifact.content_sha256,
            artifact.byte_length,
        ) {
            (Some(relative), Some(expected_sha), Some(expected_length)) => {
                if !is_review_sha256(expected_sha) {
                    return Err("historical-v2 review object hash changed".into());
                }
                expected_files.insert(relative.clone());
                let bytes =
                    read_plain_review_file(&review_safe_path(root, relative)?, "review object")?;
                if review_sha256(&bytes) != *expected_sha || bytes.len() as u64 != expected_length {
                    return Err("historical-v2 review object changed".into());
                }
            }
            (None, None, None) if artifact.kind == BoundaryGitEntryKind::Gitlink => {}
            _ => return Err("historical-v2 review artifact binding is incomplete".into()),
        }
    }
    Ok(())
}

fn validate_changed_methods(
    root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
) -> Result<(), String> {
    for method in &bundle.changed_methods {
        if method.language != bundle.language
            || method.repository_path.trim().is_empty()
            || method.symbol_name.trim().is_empty()
            || method.start_line == 0
            || method.end_line < method.start_line
            || !is_review_sha256(&method.source_sha256)
        {
            return Err("historical-v2 review changed-method identity changed".into());
        }
        let side = match method.side {
            HistoricalRevisionSide::Parent => HistoricalV2ReviewSnapshotSide::Before,
            HistoricalRevisionSide::Commit => HistoricalV2ReviewSnapshotSide::After,
        };
        let snapshot = bundle
            .snapshots
            .iter()
            .find(|snapshot| snapshot.side == side)
            .ok_or_else(|| {
                "historical-v2 review changed-method snapshot disappeared".to_string()
            })?;
        let artifact = snapshot
            .artifacts
            .iter()
            .find(|artifact| artifact.repository_path == method.repository_path)
            .ok_or_else(|| "historical-v2 review changed-method source disappeared".to_string())?;
        let relative = artifact
            .artifact_path
            .as_deref()
            .ok_or_else(|| "historical-v2 changed method is not a Git blob".to_string())?;
        let bytes =
            read_plain_review_file(&review_safe_path(root, relative)?, "changed-method source")?;
        let parsed = crate::parser::parse_source_checked(&method.repository_path, &bytes)?;
        if parsed.language != method.language
            || !parsed.methods.iter().any(|candidate| {
                candidate.name == method.symbol_name
                    && candidate.start_line == method.start_line
                    && candidate.end_line == method.end_line
                    && review_sha256(candidate.source.as_bytes()) == method.source_sha256
            })
        {
            return Err(
                "historical-v2 review changed method no longer matches exact source".into(),
            );
        }
    }
    Ok(())
}

fn validate_behavior(behavior: &HistoricalV2ReviewBehaviorEvidence) -> Result<(), String> {
    let test_sides = behavior
        .events
        .iter()
        .filter(|event| event.phase == HistoricalV2ExecutionPhase::Test)
        .map(|event| event.side)
        .collect::<BTreeSet<_>>();
    if behavior.events.is_empty()
        || test_sides
            != BTreeSet::from([
                HistoricalV2ExecutionSide::Base,
                HistoricalV2ExecutionSide::Patched,
            ])
        || behavior
            .events
            .iter()
            .any(|event| event.timed_out || event.exit_code != Some(0))
    {
        return Err(
            "historical-v2 review behavior evidence is not identical passing execution".into(),
        );
    }
    Ok(())
}

pub(super) fn bundle_sha256(bundle: &HistoricalV2SourceReviewBundle) -> Result<String, String> {
    review_hash_json(&(
        bundle.schema_version,
        &bundle.bundle_contract,
        &bundle.protocol_sha256,
        &bundle.selection_sha256,
        &bundle.assessment_identity_sha256,
        &bundle.terminal_checkpoint_sha256,
        &bundle.review_item_id,
        &bundle.language,
        bundle.source_only,
        bundle.sniff_output_included,
        bundle.dataset_judgments_included,
        bundle.public_surface_preserved,
        &bundle.public_surface_delta_sha256,
        &bundle.snapshots,
        &bundle.changed_methods,
        &bundle.behavior,
    ))
}
