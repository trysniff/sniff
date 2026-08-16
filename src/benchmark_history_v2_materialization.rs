use super::history_v2_materialization_git::{
    HistoricalV2GitCheckOutcome, apply_indexed_patch, canonical_path,
    create_new_absolute_directory, deterministic_commit, git, git_check, git_common_directory,
    git_text, path_text, remove_generated_root, require_clean, require_new_absolute_directory,
    require_oid, require_repository, require_revision, require_sha256, write_create_new,
};
use super::{
    HISTORICAL_V2_MATERIALIZATION_SCHEMA_VERSION, HistoricalCloneOutcome,
    HistoricalV2Materialization, HistoricalV2MaterializationExclusion,
    HistoricalV2MaterializationExclusionEvidence, HistoricalV2MaterializationExclusionReason,
    HistoricalV2MaterializedRoots, HistoricalV2SlotStage, HistoricalV2SlotStageError,
    HistoricalV2SlotStageErrorKind, HistoricalV2StageResult, seal_materialization_exclusion,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const MATERIALIZATION_CONTRACT: &str = "sniffbench-historical-v2-materialization-v1";
type MaterializationValue = (HistoricalV2Materialization, HistoricalV2MaterializedRoots);
type MaterializationStageResult =
    HistoricalV2StageResult<MaterializationValue, HistoricalV2MaterializationExclusion>;

pub fn materialize_historical_v2_repository(
    canonical_repository: &str,
    base_revision: &str,
    historical_patch: &str,
    expected_patch_sha256: &str,
    slot_root: &Path,
) -> Result<(HistoricalV2Materialization, HistoricalV2MaterializedRoots), String> {
    let url = format!("https://github.com/{canonical_repository}.git");
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
    match materialize_from_url_typed(
        canonical_repository,
        repository_url,
        base_revision,
        historical_patch,
        expected_patch_sha256,
        slot_root,
    )
    .map_err(|error| error.detail)?
    {
        HistoricalV2StageResult::Completed(value) => Ok(value),
        HistoricalV2StageResult::Excluded(exclusion) => Err(format!(
            "historical-v2 materialization excluded: {:?}",
            exclusion.reason
        )),
    }
}

pub(super) fn materialize_from_url_typed(
    canonical_repository: &str,
    repository_url: &str,
    base_revision: &str,
    historical_patch: &str,
    expected_patch_sha256: &str,
    slot_root: &Path,
) -> Result<MaterializationStageResult, HistoricalV2SlotStageError> {
    validate_materialization_request(
        canonical_repository,
        base_revision,
        historical_patch,
        expected_patch_sha256,
        slot_root,
    )?;
    let slot_root = create_new_absolute_directory(slot_root).map_err(infrastructure)?;
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
    if matches!(&result, Ok(HistoricalV2StageResult::Completed(_))) {
        return result;
    }
    if let Err(cleanup) = remove_generated_root(&inputs.slot_root) {
        let prior = match &result {
            Ok(HistoricalV2StageResult::Excluded(exclusion)) => {
                format!("terminal exclusion {:?}", exclusion.reason)
            }
            Ok(HistoricalV2StageResult::Completed(_)) => unreachable!(),
            Err(error) => error.detail.clone(),
        };
        return Err(infrastructure(format!(
            "{prior}; materialization cleanup also failed: {cleanup}"
        )));
    }
    result
}

pub(super) fn validate_materialization_request(
    canonical_repository: &str,
    base_revision: &str,
    historical_patch: &str,
    expected_patch_sha256: &str,
    slot_root: &Path,
) -> Result<(), HistoricalV2SlotStageError> {
    require_repository(canonical_repository).map_err(invalid)?;
    require_revision(base_revision).map_err(invalid)?;
    require_sha256(expected_patch_sha256).map_err(invalid)?;
    if historical_patch.is_empty() || sha256(historical_patch.as_bytes()) != expected_patch_sha256 {
        return Err(invalid(
            "historical-v2 patch does not match its fixed selection hash",
        ));
    }
    require_new_absolute_directory(slot_root).map_err(invalid)
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
) -> Result<MaterializationStageResult, HistoricalV2SlotStageError> {
    let outcome = super::non_blind_history_materialize::clone_complete_historical_repository_url(
        inputs.canonical_repository,
        inputs.repository_url,
        &inputs.repository_root,
    )
    .map_err(infrastructure)?;
    if outcome != HistoricalCloneOutcome::Complete {
        return excluded(
            inputs,
            HistoricalV2MaterializationExclusionReason::RepositoryEmpty,
            HistoricalV2MaterializationExclusionEvidence::RepositoryEmpty {
                clone_url: inputs.repository_url.to_string(),
            },
        );
    }
    git(
        &inputs.repository_root,
        &["config", "--local", "core.autocrlf", "false"],
    )
    .map_err(infrastructure)?;
    git(
        &inputs.repository_root,
        &["config", "--local", "core.eol", "lf"],
    )
    .map_err(infrastructure)?;
    let revision_arg = format!("{}^{{commit}}", inputs.base_revision);
    match git_check(
        &inputs.repository_root,
        &["rev-parse", "--verify", &revision_arg],
    )
    .map_err(infrastructure)?
    {
        HistoricalV2GitCheckOutcome::Accepted(bytes) => {
            if git_output_text(bytes).map_err(invalid)? != inputs.base_revision {
                return Err(invalid(
                    "historical-v2 base revision resolved to a different commit",
                ));
            }
        }
        HistoricalV2GitCheckOutcome::Rejected(command) => {
            return excluded(
                inputs,
                HistoricalV2MaterializationExclusionReason::BaseRevisionUnavailable,
                HistoricalV2MaterializationExclusionEvidence::BaseRevisionUnavailable {
                    revision: inputs.base_revision.to_string(),
                    command,
                },
            );
        }
    }
    git(
        &inputs.repository_root,
        &["checkout", "--force", "--detach", inputs.base_revision],
    )
    .map_err(infrastructure)?;
    require_clean(&inputs.repository_root).map_err(invalid)?;
    let object_format = git_text(
        &inputs.repository_root,
        &["rev-parse", "--show-object-format"],
    )
    .map_err(infrastructure)?;
    if object_format != "sha1" {
        return excluded(
            inputs,
            HistoricalV2MaterializationExclusionReason::UnsupportedGitObjectFormat,
            HistoricalV2MaterializationExclusionEvidence::UnsupportedGitObjectFormat {
                object_format,
            },
        );
    }
    let base_tree_oid =
        git_text(&inputs.repository_root, &["rev-parse", "HEAD^{tree}"]).map_err(infrastructure)?;

    let patched_text = path_text(&inputs.patched_root).map_err(infrastructure)?;
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
    )
    .map_err(infrastructure)?;
    let patch_path = inputs.slot_root.join("historical.patch");
    write_create_new(&patch_path, inputs.historical_patch.as_bytes()).map_err(infrastructure)?;
    let patch_text = path_text(&patch_path).map_err(infrastructure)?;
    match git_check(
        &inputs.patched_root,
        &[
            "apply",
            "--check",
            "--index",
            "--whitespace=nowarn",
            &patch_text,
        ],
    )
    .map_err(infrastructure)?
    {
        HistoricalV2GitCheckOutcome::Accepted(_) => {}
        HistoricalV2GitCheckOutcome::Rejected(command) => {
            return excluded(
                inputs,
                HistoricalV2MaterializationExclusionReason::HistoricalPatchDoesNotApply,
                HistoricalV2MaterializationExclusionEvidence::HistoricalPatchRejected {
                    patch_sha256: inputs.expected_patch_sha256.to_string(),
                    command,
                },
            );
        }
    }
    apply_indexed_patch(&inputs.patched_root, &patch_text, false).map_err(infrastructure)?;
    fs::remove_file(&patch_path).map_err(|error| {
        infrastructure(format!(
            "failed to remove historical-v2 patch input: {error}"
        ))
    })?;
    let patched_tree_oid =
        git_text(&inputs.patched_root, &["write-tree"]).map_err(infrastructure)?;
    if patched_tree_oid == base_tree_oid {
        return excluded(
            inputs,
            HistoricalV2MaterializationExclusionReason::HistoricalPatchProducesNoTreeChange,
            HistoricalV2MaterializationExclusionEvidence::HistoricalPatchProducesNoTreeChange {
                base_tree_oid,
            },
        );
    }
    let message_path = inputs.slot_root.join("commit-message.txt");
    write_create_new(
        &message_path,
        b"SniffBench historical-v2 patched snapshot\n",
    )
    .map_err(infrastructure)?;
    let patched_commit_oid = deterministic_commit(
        &inputs.patched_root,
        &patched_tree_oid,
        inputs.base_revision,
        &path_text(&message_path).map_err(infrastructure)?,
    )
    .map_err(infrastructure)?;
    fs::remove_file(&message_path).map_err(|error| {
        infrastructure(format!(
            "failed to remove historical-v2 commit input: {error}"
        ))
    })?;
    git(
        &inputs.patched_root,
        &["reset", "--hard", &patched_commit_oid],
    )
    .map_err(infrastructure)?;
    require_clean(&inputs.patched_root).map_err(invalid)?;
    if git_text(&inputs.patched_root, &["rev-parse", "HEAD^{tree}"]).map_err(infrastructure)?
        != patched_tree_oid
    {
        return Err(invalid(
            "historical-v2 patched snapshot tree changed after commit",
        ));
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
    artifact.materialization_sha256 = materialization_sha256(&artifact).map_err(invalid)?;
    let roots = HistoricalV2MaterializedRoots {
        repository_root: inputs.repository_root.clone(),
        base_root: inputs.repository_root.clone(),
        patched_root: inputs.patched_root.clone(),
    };
    Ok(HistoricalV2StageResult::Completed((artifact, roots)))
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

fn excluded(
    inputs: &MaterializationInputs<'_>,
    reason: HistoricalV2MaterializationExclusionReason,
    evidence: HistoricalV2MaterializationExclusionEvidence,
) -> Result<MaterializationStageResult, HistoricalV2SlotStageError> {
    let exclusion = seal_materialization_exclusion(
        inputs.canonical_repository,
        inputs.base_revision,
        inputs.expected_patch_sha256,
        reason,
        evidence,
    )?;
    Ok(HistoricalV2StageResult::Excluded(exclusion))
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

fn git_output_text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes)
        .map(|value| value.trim().to_string())
        .map_err(|_| "historical-v2 Git identity is not UTF-8".to_string())
}

fn invalid(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::Materialization,
        kind: HistoricalV2SlotStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

fn infrastructure(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::Materialization,
        kind: HistoricalV2SlotStageErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_history_v2_materialization_tests.rs"]
mod tests;
