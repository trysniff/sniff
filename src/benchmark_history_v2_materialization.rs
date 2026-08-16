use super::history_v2_materialization_git::{
    apply_indexed_patch, canonical_path, create_new_absolute_directory, deterministic_commit, git,
    git_common_directory, git_text, path_text, remove_generated_root, require_clean,
    require_exact_commit, require_oid, require_repository, require_revision, require_sha256,
    write_create_new,
};
use super::{
    HISTORICAL_V2_MATERIALIZATION_SCHEMA_VERSION, HistoricalCloneOutcome,
    HistoricalV2Materialization, HistoricalV2MaterializedRoots,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const MATERIALIZATION_CONTRACT: &str = "sniffbench-historical-v2-materialization-v1";

pub fn materialize_historical_v2_repository(
    canonical_repository: &str,
    base_revision: &str,
    historical_patch: &str,
    expected_patch_sha256: &str,
    slot_root: &Path,
) -> Result<(HistoricalV2Materialization, HistoricalV2MaterializedRoots), String> {
    let url = format!("https://{canonical_repository}.git");
    materialize_from_url(
        canonical_repository,
        &url,
        base_revision,
        historical_patch,
        expected_patch_sha256,
        slot_root,
    )
}

pub(super) fn materialize_from_url(
    canonical_repository: &str,
    repository_url: &str,
    base_revision: &str,
    historical_patch: &str,
    expected_patch_sha256: &str,
    slot_root: &Path,
) -> Result<(HistoricalV2Materialization, HistoricalV2MaterializedRoots), String> {
    require_repository(canonical_repository)?;
    require_revision(base_revision)?;
    require_sha256(expected_patch_sha256)?;
    if historical_patch.is_empty() || sha256(historical_patch.as_bytes()) != expected_patch_sha256 {
        return Err("historical-v2 patch does not match its fixed selection hash".to_string());
    }
    let slot_root = create_new_absolute_directory(slot_root)?;
    let inputs = MaterializationInputs {
        canonical_repository,
        repository_url,
        base_revision,
        historical_patch,
        expected_patch_sha256,
        repository_root: slot_root.join("repository"),
        patched_root: slot_root.join("patched"),
        slot_root,
    };
    let result = materialize_in_root(&inputs);
    if result.is_err() {
        let _ = remove_generated_root(&inputs.slot_root);
    }
    result
}

struct MaterializationInputs<'a> {
    canonical_repository: &'a str,
    repository_url: &'a str,
    base_revision: &'a str,
    historical_patch: &'a str,
    expected_patch_sha256: &'a str,
    slot_root: std::path::PathBuf,
    repository_root: std::path::PathBuf,
    patched_root: std::path::PathBuf,
}

fn materialize_in_root(
    inputs: &MaterializationInputs<'_>,
) -> Result<(HistoricalV2Materialization, HistoricalV2MaterializedRoots), String> {
    let outcome = super::non_blind_history_materialize::clone_complete_historical_repository_url(
        inputs.canonical_repository,
        inputs.repository_url,
        &inputs.repository_root,
    )?;
    if outcome != HistoricalCloneOutcome::Complete {
        return Err("historical-v2 repository has no reachable Git commit".to_string());
    }
    git(
        &inputs.repository_root,
        &["config", "--local", "core.autocrlf", "false"],
    )?;
    git(
        &inputs.repository_root,
        &["config", "--local", "core.eol", "lf"],
    )?;
    require_exact_commit(&inputs.repository_root, inputs.base_revision)?;
    git(
        &inputs.repository_root,
        &["checkout", "--force", "--detach", inputs.base_revision],
    )?;
    require_clean(&inputs.repository_root)?;
    let object_format = git_text(
        &inputs.repository_root,
        &["rev-parse", "--show-object-format"],
    )?;
    if object_format != "sha1" {
        return Err(format!(
            "historical-v2 base revision requires SHA-1 but repository uses {object_format}"
        ));
    }
    let base_tree_oid = git_text(&inputs.repository_root, &["rev-parse", "HEAD^{tree}"])?;

    let patched_text = path_text(&inputs.patched_root)?;
    git(
        &inputs.repository_root,
        &[
            "worktree",
            "add",
            "--detach",
            "--force",
            &patched_text,
            inputs.base_revision,
        ],
    )?;
    let patch_path = inputs.slot_root.join("historical.patch");
    write_create_new(&patch_path, inputs.historical_patch.as_bytes())?;
    let patch_text = path_text(&patch_path)?;
    apply_indexed_patch(&inputs.patched_root, &patch_text, true)?;
    apply_indexed_patch(&inputs.patched_root, &patch_text, false)?;
    fs::remove_file(&patch_path)
        .map_err(|error| format!("failed to remove historical-v2 patch input: {error}"))?;
    let patched_tree_oid = git_text(&inputs.patched_root, &["write-tree"])?;
    if patched_tree_oid == base_tree_oid {
        return Err("historical-v2 patch produced no Git tree change".to_string());
    }
    let message_path = inputs.slot_root.join("commit-message.txt");
    write_create_new(
        &message_path,
        b"SniffBench historical-v2 patched snapshot\n",
    )?;
    let patched_commit_oid = deterministic_commit(
        &inputs.patched_root,
        &patched_tree_oid,
        inputs.base_revision,
        &path_text(&message_path)?,
    )?;
    fs::remove_file(&message_path)
        .map_err(|error| format!("failed to remove historical-v2 commit input: {error}"))?;
    git(
        &inputs.patched_root,
        &["reset", "--hard", &patched_commit_oid],
    )?;
    require_clean(&inputs.patched_root)?;
    if git_text(&inputs.patched_root, &["rev-parse", "HEAD^{tree}"])? != patched_tree_oid {
        return Err("historical-v2 patched snapshot tree changed after commit".to_string());
    }

    let mut artifact = HistoricalV2Materialization {
        schema_version: HISTORICAL_V2_MATERIALIZATION_SCHEMA_VERSION,
        materialization_contract: MATERIALIZATION_CONTRACT.to_string(),
        canonical_repository: inputs.canonical_repository.to_string(),
        base_revision: inputs.base_revision.to_string(),
        object_format,
        base_tree_oid,
        historical_patch_sha256: inputs.expected_patch_sha256.to_string(),
        patched_tree_oid,
        patched_commit_oid,
        materialization_sha256: String::new(),
    };
    artifact.materialization_sha256 = materialization_sha256(&artifact)?;
    let roots = HistoricalV2MaterializedRoots {
        repository_root: inputs.repository_root.clone(),
        base_root: inputs.repository_root.clone(),
        patched_root: inputs.patched_root.clone(),
    };
    Ok((artifact, roots))
}

pub fn validate_historical_v2_materialization(
    artifact: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
) -> Result<(), String> {
    if artifact.schema_version != HISTORICAL_V2_MATERIALIZATION_SCHEMA_VERSION
        || artifact.materialization_contract != MATERIALIZATION_CONTRACT
        || artifact.object_format != "sha1"
        || artifact.materialization_sha256 != materialization_sha256(artifact)?
    {
        return Err("historical-v2 materialization commitment changed".to_string());
    }
    require_repository(&artifact.canonical_repository)?;
    require_revision(&artifact.base_revision)?;
    require_sha256(&artifact.historical_patch_sha256)?;
    require_oid(&artifact.base_tree_oid)?;
    require_oid(&artifact.patched_tree_oid)?;
    require_oid(&artifact.patched_commit_oid)?;
    let repository_root = canonical_path(&roots.repository_root, "repository root")?;
    let base_root = canonical_path(&roots.base_root, "base snapshot")?;
    let patched_root = canonical_path(&roots.patched_root, "patched snapshot")?;
    if base_root != repository_root
        || repository_root.file_name().and_then(|value| value.to_str()) != Some("repository")
        || patched_root.file_name().and_then(|value| value.to_str()) != Some("patched")
        || repository_root.parent() != patched_root.parent()
        || git_common_directory(&repository_root)? != git_common_directory(&patched_root)?
    {
        return Err("historical-v2 base snapshot is not the exact cloned repository".to_string());
    }
    require_clean(&base_root)?;
    require_clean(&patched_root)?;
    if git_text(&base_root, &["rev-parse", "--is-shallow-repository"])? != "false"
        || git_text(&patched_root, &["rev-parse", "--is-shallow-repository"])? != "false"
    {
        return Err("historical-v2 materialized repository is shallow".to_string());
    }
    if git_text(&base_root, &["rev-parse", "HEAD"])? != artifact.base_revision
        || git_text(&base_root, &["rev-parse", "HEAD^{tree}"])? != artifact.base_tree_oid
        || git_text(&patched_root, &["rev-parse", "HEAD"])? != artifact.patched_commit_oid
        || git_text(&patched_root, &["rev-parse", "HEAD^{tree}"])? != artifact.patched_tree_oid
    {
        return Err("historical-v2 materialized Git identities changed".to_string());
    }
    Ok(())
}

fn materialization_sha256(value: &HistoricalV2Materialization) -> Result<String, String> {
    hash_json(&(
        value.schema_version,
        &value.materialization_contract,
        &value.canonical_repository,
        &value.base_revision,
        &value.object_format,
        &value.base_tree_oid,
        &value.historical_patch_sha256,
        &value.patched_tree_oid,
        &value.patched_commit_oid,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 materialization: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn materializes_exact_base_and_deterministic_patched_tree() {
        let source = tempfile::tempdir().unwrap();
        initialize_repository(source.path());
        fs::write(source.path().join("main.rs"), "fn value() -> i32 { 1 }\n").unwrap();
        git_ok(source.path(), &["add", "."]);
        git_ok(source.path(), &["commit", "-m", "base"]);
        let base = git_text(source.path(), &["rev-parse", "HEAD"]).unwrap();
        fs::write(source.path().join("main.rs"), "fn value() -> i32 { 2 }\n").unwrap();
        let patch = git_text(source.path(), &["diff", "--binary", "HEAD"]).unwrap() + "\n";
        git_ok(source.path(), &["reset", "--hard", "HEAD"]);

        let parent = tempfile::tempdir().unwrap();
        let expected_patch_sha256 = sha256(patch.as_bytes());
        let first = materialize_from_url(
            "github.com/example/repo",
            &source.path().to_string_lossy(),
            &base,
            &patch,
            &expected_patch_sha256,
            &parent.path().join("first"),
        )
        .unwrap();
        let second = materialize_from_url(
            "github.com/example/repo",
            &source.path().to_string_lossy(),
            &base,
            &patch,
            &expected_patch_sha256,
            &parent.path().join("second"),
        )
        .unwrap();

        assert_eq!(first.0, second.0);
        assert_ne!(first.0.base_tree_oid, first.0.patched_tree_oid);
        assert_eq!(
            fs::read_to_string(first.1.patched_root.join("main.rs")).unwrap(),
            "fn value() -> i32 { 2 }\n"
        );
        validate_historical_v2_materialization(&first.0, &first.1).unwrap();
        validate_historical_v2_materialization(&second.0, &second.1).unwrap();

        let crossed = HistoricalV2MaterializedRoots {
            repository_root: first.1.repository_root.clone(),
            base_root: first.1.base_root.clone(),
            patched_root: second.1.patched_root.clone(),
        };
        assert!(validate_historical_v2_materialization(&first.0, &crossed).is_err());
    }

    #[test]
    fn rejects_changed_patch_before_creating_work() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("slot");
        let error = materialize_from_url(
            "github.com/example/repo",
            "unused",
            &"1".repeat(40),
            "patch",
            &"2".repeat(64),
            &root,
        )
        .unwrap_err();
        assert!(error.contains("fixed selection hash"));
        assert!(!root.exists());
    }

    fn initialize_repository(root: &Path) {
        git_ok(root, &["init", "-b", "main"]);
        git_ok(root, &["config", "user.email", "fixture@example.test"]);
        git_ok(root, &["config", "user.name", "Fixture"]);
    }

    fn git_ok(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
