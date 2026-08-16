use super::history_v2_materialization_git::{
    apply_indexed_patch, canonical_path, deterministic_commit, git, git_common_directory, git_text,
    path_text, require_clean, require_oid, require_sha256, write_create_new,
};
use super::{
    HISTORICAL_V2_TEST_MATERIALIZATION_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2TestMaterialization,
    HistoricalV2TestMaterializedRoots, validate_historical_v2_materialization,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const TEST_MATERIALIZATION_CONTRACT: &str =
    "sniffbench-historical-v2-identical-test-materialization-v1";

pub fn materialize_historical_v2_test_snapshots(
    materialization: &HistoricalV2Materialization,
    materialized_roots: &HistoricalV2MaterializedRoots,
    test_patch: &str,
    expected_test_patch_sha256: &str,
) -> Result<
    (
        HistoricalV2TestMaterialization,
        HistoricalV2TestMaterializedRoots,
    ),
    String,
> {
    validate_historical_v2_materialization(materialization, materialized_roots)?;
    require_sha256(expected_test_patch_sha256)?;
    if test_patch.is_empty() || sha256(test_patch.as_bytes()) != expected_test_patch_sha256 {
        return Err(
            "historical-v2 test patch does not match its selected payload hash".to_string(),
        );
    }

    let repository_root = canonical_path(&materialized_roots.repository_root, "repository root")?;
    let slot_root = repository_root
        .parent()
        .ok_or_else(|| "historical-v2 repository root has no slot parent".to_string())?
        .to_path_buf();
    let roots = HistoricalV2TestMaterializedRoots {
        base_test_root: slot_root.join("base-tested"),
        patched_test_root: slot_root.join("patched-tested"),
    };
    let patch_path = slot_root.join("test.patch");
    let message_path = slot_root.join("test-commit-message.txt");
    for path in [
        &roots.base_test_root,
        &roots.patched_test_root,
        &patch_path,
        &message_path,
    ] {
        if path.exists() {
            return Err(format!(
                "historical-v2 identical-test materialization path already exists: {}",
                path.display()
            ));
        }
    }

    let result = materialize_test_snapshots(
        materialization,
        &repository_root,
        &roots,
        test_patch,
        expected_test_patch_sha256,
        &patch_path,
        &message_path,
    );
    if result.is_err() {
        cleanup_test_materialization(
            &repository_root,
            &roots,
            &[patch_path.as_path(), message_path.as_path()],
        );
    }
    result.map(|artifact| (artifact, roots))
}

fn materialize_test_snapshots(
    materialization: &HistoricalV2Materialization,
    repository_root: &Path,
    roots: &HistoricalV2TestMaterializedRoots,
    test_patch: &str,
    expected_test_patch_sha256: &str,
    patch_path: &Path,
    message_path: &Path,
) -> Result<HistoricalV2TestMaterialization, String> {
    add_worktree(
        repository_root,
        &roots.base_test_root,
        &materialization.base_revision,
    )?;
    add_worktree(
        repository_root,
        &roots.patched_test_root,
        &materialization.patched_commit_oid,
    )?;
    write_create_new(patch_path, test_patch.as_bytes())?;
    let patch_text = path_text(patch_path)?;

    // Prove the same patch applies to both snapshots before either index is changed.
    apply_indexed_patch(&roots.base_test_root, &patch_text, true)?;
    apply_indexed_patch(&roots.patched_test_root, &patch_text, true)?;
    apply_indexed_patch(&roots.base_test_root, &patch_text, false)?;
    apply_indexed_patch(&roots.patched_test_root, &patch_text, false)?;
    fs::remove_file(patch_path)
        .map_err(|error| format!("failed to remove historical-v2 test patch input: {error}"))?;

    let base_test_tree_oid = git_text(&roots.base_test_root, &["write-tree"])?;
    let patched_test_tree_oid = git_text(&roots.patched_test_root, &["write-tree"])?;
    if base_test_tree_oid == materialization.base_tree_oid
        || patched_test_tree_oid == materialization.patched_tree_oid
    {
        return Err("historical-v2 test patch produced no Git tree change".to_string());
    }

    write_create_new(
        message_path,
        b"SniffBench historical-v2 identical-test snapshot\n",
    )?;
    let message_text = path_text(message_path)?;
    let base_test_commit_oid = deterministic_commit(
        &roots.base_test_root,
        &base_test_tree_oid,
        &materialization.base_revision,
        &message_text,
    )?;
    let patched_test_commit_oid = deterministic_commit(
        &roots.patched_test_root,
        &patched_test_tree_oid,
        &materialization.patched_commit_oid,
        &message_text,
    )?;
    fs::remove_file(message_path)
        .map_err(|error| format!("failed to remove historical-v2 test commit input: {error}"))?;
    git(
        &roots.base_test_root,
        &["reset", "--hard", &base_test_commit_oid],
    )?;
    git(
        &roots.patched_test_root,
        &["reset", "--hard", &patched_test_commit_oid],
    )?;
    require_clean(&roots.base_test_root)?;
    require_clean(&roots.patched_test_root)?;

    let mut artifact = HistoricalV2TestMaterialization {
        schema_version: HISTORICAL_V2_TEST_MATERIALIZATION_SCHEMA_VERSION,
        test_materialization_contract: TEST_MATERIALIZATION_CONTRACT.to_string(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        test_patch_sha256: expected_test_patch_sha256.to_string(),
        base_input_commit_oid: materialization.base_revision.clone(),
        base_test_tree_oid,
        base_test_commit_oid,
        patched_input_commit_oid: materialization.patched_commit_oid.clone(),
        patched_test_tree_oid,
        patched_test_commit_oid,
        test_materialization_sha256: String::new(),
    };
    artifact.test_materialization_sha256 = test_materialization_sha256(&artifact)?;
    Ok(artifact)
}

pub fn validate_historical_v2_test_materialization(
    materialization: &HistoricalV2Materialization,
    materialized_roots: &HistoricalV2MaterializedRoots,
    expected_test_patch_sha256: &str,
    artifact: &HistoricalV2TestMaterialization,
    roots: &HistoricalV2TestMaterializedRoots,
) -> Result<(), String> {
    validate_historical_v2_materialization(materialization, materialized_roots)?;
    require_sha256(expected_test_patch_sha256)?;
    if artifact.schema_version != HISTORICAL_V2_TEST_MATERIALIZATION_SCHEMA_VERSION
        || artifact.test_materialization_contract != TEST_MATERIALIZATION_CONTRACT
        || artifact.materialization_sha256 != materialization.materialization_sha256
        || artifact.test_patch_sha256 != expected_test_patch_sha256
        || artifact.base_input_commit_oid != materialization.base_revision
        || artifact.patched_input_commit_oid != materialization.patched_commit_oid
        || artifact.test_materialization_sha256 != test_materialization_sha256(artifact)?
    {
        return Err("historical-v2 identical-test materialization commitment changed".to_string());
    }
    require_sha256(&artifact.test_patch_sha256)?;
    for oid in [
        &artifact.base_input_commit_oid,
        &artifact.base_test_tree_oid,
        &artifact.base_test_commit_oid,
        &artifact.patched_input_commit_oid,
        &artifact.patched_test_tree_oid,
        &artifact.patched_test_commit_oid,
    ] {
        require_oid(oid)?;
    }

    let repository_root = canonical_path(&materialized_roots.repository_root, "repository root")?;
    let base_test_root = canonical_path(&roots.base_test_root, "base tested snapshot")?;
    let patched_test_root = canonical_path(&roots.patched_test_root, "patched tested snapshot")?;
    if base_test_root.file_name().and_then(|value| value.to_str()) != Some("base-tested")
        || patched_test_root
            .file_name()
            .and_then(|value| value.to_str())
            != Some("patched-tested")
        || base_test_root.parent() != repository_root.parent()
        || patched_test_root.parent() != repository_root.parent()
        || git_common_directory(&base_test_root)? != git_common_directory(&repository_root)?
        || git_common_directory(&patched_test_root)? != git_common_directory(&repository_root)?
    {
        return Err(
            "historical-v2 tested snapshots are not bound to the materialized clone".into(),
        );
    }
    require_clean(&base_test_root)?;
    require_clean(&patched_test_root)?;
    if git_text(&base_test_root, &["rev-parse", "--is-shallow-repository"])? != "false"
        || git_text(
            &patched_test_root,
            &["rev-parse", "--is-shallow-repository"],
        )? != "false"
    {
        return Err("historical-v2 tested snapshots are shallow".to_string());
    }
    if artifact.base_test_tree_oid == materialization.base_tree_oid
        || artifact.patched_test_tree_oid == materialization.patched_tree_oid
    {
        return Err("historical-v2 test patch produced no Git tree change".to_string());
    }
    if git_text(&base_test_root, &["rev-parse", "HEAD"])? != artifact.base_test_commit_oid
        || git_text(&base_test_root, &["rev-parse", "HEAD^{tree}"])? != artifact.base_test_tree_oid
        || git_text(&patched_test_root, &["rev-parse", "HEAD"])? != artifact.patched_test_commit_oid
        || git_text(&patched_test_root, &["rev-parse", "HEAD^{tree}"])?
            != artifact.patched_test_tree_oid
    {
        return Err("historical-v2 tested Git identities changed".to_string());
    }
    Ok(())
}

fn add_worktree(
    repository_root: &Path,
    worktree_root: &Path,
    revision: &str,
) -> Result<(), String> {
    let worktree_text = path_text(worktree_root)?;
    git(
        repository_root,
        &[
            "worktree",
            "add",
            "--detach",
            "--force",
            &worktree_text,
            revision,
        ],
    )
}

fn cleanup_test_materialization(
    repository_root: &Path,
    roots: &HistoricalV2TestMaterializedRoots,
    inputs: &[&Path],
) {
    for input in inputs {
        if input.is_file() {
            let _ = fs::remove_file(input);
        }
    }
    for root in [&roots.base_test_root, &roots.patched_test_root] {
        if root.exists()
            && let Ok(root_text) = path_text(root)
        {
            let _ = git(
                repository_root,
                &["worktree", "remove", "--force", &root_text],
            );
        }
    }
}

fn test_materialization_sha256(value: &HistoricalV2TestMaterialization) -> Result<String, String> {
    hash_json(&(
        value.schema_version,
        &value.test_materialization_contract,
        &value.materialization_sha256,
        &value.test_patch_sha256,
        &value.base_input_commit_oid,
        &value.base_test_tree_oid,
        &value.base_test_commit_oid,
        &value.patched_input_commit_oid,
        &value.patched_test_tree_oid,
        &value.patched_test_commit_oid,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 test materialization: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
