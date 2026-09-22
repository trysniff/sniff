use super::git::{
    binary_patch, head_revision, inspect_repository, origin_url, pull_head, sha256,
    validate_checkout, worktree_matches_index, write_tree,
};
use super::layout::validate_root_layout;
use super::{
    CandidateContext, EXCLUSION_CONTRACT, HISTORICAL_V3_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V3_MATERIALIZATION_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3Materialization, HistoricalV3MaterializationError,
    HistoricalV3MaterializationExclusion, HistoricalV3MaterializationExclusionEvidence,
    HistoricalV3MaterializationExclusionReason, HistoricalV3MaterializedRoots,
    HistoricalV3Protocol, MATERIALIZATION_CONTRACT, candidate_context, failed, invalid,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;

pub fn validate_historical_v3_materialization_commitment(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    artifact: &HistoricalV3Materialization,
) -> Result<(), HistoricalV3MaterializationError> {
    let context = candidate_context(protocol, collection, artifact.stream_rank)?;
    let object_id_length = object_id_length(&artifact.git_object_format);
    if artifact.schema_version != HISTORICAL_V3_MATERIALIZATION_SCHEMA_VERSION
        || artifact.materialization_contract != MATERIALIZATION_CONTRACT
        || artifact.protocol_sha256 != context.protocol.protocol_sha256
        || artifact.candidate_manifest_sha256 != context.collection.manifest.manifest_sha256
        || artifact.stream_task_sha256 != context.collection.manifest.stream_task.task_sha256
        || artifact.rank_sha256 != context.task.rank_sha256
        || artifact.identity != context.task.identity
        || artifact.name_with_owner != context.name_with_owner
        || artifact.clone_url != context.clone_url
        || !valid_oid(&artifact.base_tree_oid, object_id_length)
        || !valid_oid(&artifact.head_tree_oid, object_id_length)
        || !valid_oid(&artifact.merge_tree_oid, object_id_length)
        || artifact.merge_parent_commits.is_empty()
        || artifact
            .merge_parent_commits
            .iter()
            .any(|parent| !valid_oid(parent, object_id_length))
        || !valid_sha256(&artifact.patch_sha256)
        || artifact.materialization_sha256 != commitment_sha256(artifact)?
    {
        return Err(invalid("historical-v3 materialization commitment changed"));
    }
    Ok(())
}

pub fn validate_historical_v3_materialization(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    artifact: &HistoricalV3Materialization,
    roots: &HistoricalV3MaterializedRoots,
) -> Result<(), HistoricalV3MaterializationError> {
    validate_historical_v3_materialization_commitment(protocol, collection, artifact)?;
    validate_root_layout(roots)?;
    if origin_url(&roots.repository_root)? != artifact.clone_url {
        return Err(invalid("historical-v3 materialization origin changed"));
    }
    let facts = inspect_repository(
        &roots.repository_root,
        &artifact.identity.base_commit,
        &artifact.identity.head_commit,
        &artifact.identity.merge_commit,
    )?;
    if facts.object_format != artifact.git_object_format
        || facts.base_tree != artifact.base_tree_oid
        || facts.head_tree != artifact.head_tree_oid
        || facts.merge_tree != artifact.merge_tree_oid
        || facts.merge_parents != artifact.merge_parent_commits
        || pull_head(&roots.repository_root)? != artifact.identity.head_commit
    {
        return Err(invalid(
            "historical-v3 materialized repository changed identity",
        ));
    }
    validate_checkout(
        &roots.base_root,
        &artifact.identity.base_commit,
        &artifact.base_tree_oid,
    )?;
    validate_checkout(
        &roots.head_root,
        &artifact.identity.head_commit,
        &artifact.head_tree_oid,
    )?;
    validate_checkout(
        &roots.merge_root,
        &artifact.identity.merge_commit,
        &artifact.merge_tree_oid,
    )?;
    let patch = fs::read(&roots.patch_path)
        .map_err(|error| failed(format!("failed to read historical-v3 patch: {error}")))?;
    let regenerated = binary_patch(
        &roots.repository_root,
        &artifact.identity.base_commit,
        &artifact.identity.merge_commit,
    )?;
    if patch != regenerated
        || sha256(&patch) != artifact.patch_sha256
        || u64::try_from(patch.len()).ok() != Some(artifact.patch_byte_count)
        || write_tree(&roots.reproduced_root)? != artifact.merge_tree_oid
        || head_revision(&roots.reproduced_root)? != artifact.identity.base_commit
        || !worktree_matches_index(&roots.reproduced_root)?
    {
        return Err(invalid("historical-v3 materialized patch changed"));
    }
    Ok(())
}

pub fn validate_historical_v3_materialization_exclusion(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    artifact: &HistoricalV3MaterializationExclusion,
) -> Result<(), HistoricalV3MaterializationError> {
    let context = candidate_context(protocol, collection, artifact.stream_rank)?;
    let evidence_valid = match (&artifact.reason, &artifact.evidence) {
        (
            HistoricalV3MaterializationExclusionReason::RevisionUnavailable,
            HistoricalV3MaterializationExclusionEvidence::RevisionUnavailable { missing },
        ) => {
            let unique = missing.iter().map(|item| item.kind).collect::<HashSet<_>>();
            !missing.is_empty()
                && unique.len() == missing.len()
                && missing.iter().all(|item| {
                    let expected = match item.kind {
                        super::HistoricalV3RevisionKind::Base => &context.task.identity.base_commit,
                        super::HistoricalV3RevisionKind::Head => &context.task.identity.head_commit,
                        super::HistoricalV3RevisionKind::Merge => {
                            &context.task.identity.merge_commit
                        }
                    };
                    &item.revision == expected && valid_rejection_evidence(&item.fetch)
                })
        }
        (
            HistoricalV3MaterializationExclusionReason::UnsupportedGitObjectFormat,
            HistoricalV3MaterializationExclusionEvidence::UnsupportedGitObjectFormat {
                object_format,
            },
        ) => !object_format.is_empty() && !matches!(object_format.as_str(), "sha1" | "sha256"),
        (
            HistoricalV3MaterializationExclusionReason::PullRequestHeadChanged,
            HistoricalV3MaterializationExclusionEvidence::PullRequestHeadChanged {
                expected_head_commit,
                fetched_head_commit,
            },
        ) => {
            expected_head_commit == &context.task.identity.head_commit
                && fetched_head_commit != expected_head_commit
                && fetched_head_commit.len() == expected_head_commit.len()
                && fetched_head_commit.bytes().all(lower_hex)
        }
        (
            HistoricalV3MaterializationExclusionReason::BaseNotAncestorOfMerge,
            HistoricalV3MaterializationExclusionEvidence::BaseNotAncestorOfMerge {
                base_commit,
                merge_commit,
            },
        ) => {
            base_commit == &context.task.identity.base_commit
                && merge_commit == &context.task.identity.merge_commit
        }
        (
            HistoricalV3MaterializationExclusionReason::PatchDoesNotReproduceMerge,
            HistoricalV3MaterializationExclusionEvidence::PatchDoesNotReproduceMerge {
                patch_sha256,
                expected_merge_tree,
                reproduced_tree,
            },
        ) => {
            valid_sha256(patch_sha256)
                && matches!(expected_merge_tree.len(), 40 | 64)
                && expected_merge_tree.len() == context.task.identity.merge_commit.len()
                && expected_merge_tree.bytes().all(lower_hex)
                && reproduced_tree.as_ref().is_none_or(|tree| {
                    tree != expected_merge_tree
                        && tree.len() == expected_merge_tree.len()
                        && tree.bytes().all(lower_hex)
                })
        }
        _ => false,
    };
    if artifact.schema_version != HISTORICAL_V3_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION
        || artifact.exclusion_contract != EXCLUSION_CONTRACT
        || artifact.protocol_sha256 != context.protocol.protocol_sha256
        || artifact.candidate_manifest_sha256 != context.collection.manifest.manifest_sha256
        || artifact.stream_task_sha256 != context.collection.manifest.stream_task.task_sha256
        || artifact.rank_sha256 != context.task.rank_sha256
        || artifact.identity != context.task.identity
        || artifact.name_with_owner != context.name_with_owner
        || !evidence_valid
        || artifact.exclusion_sha256 != commitment_sha256(artifact)?
    {
        return Err(invalid(
            "historical-v3 materialization exclusion commitment changed",
        ));
    }
    Ok(())
}

pub(super) fn exclusion(
    context: &CandidateContext<'_>,
    reason: HistoricalV3MaterializationExclusionReason,
    evidence: HistoricalV3MaterializationExclusionEvidence,
) -> Result<HistoricalV3MaterializationExclusion, HistoricalV3MaterializationError> {
    let mut artifact = HistoricalV3MaterializationExclusion {
        schema_version: HISTORICAL_V3_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        protocol_sha256: context.protocol.protocol_sha256.clone(),
        candidate_manifest_sha256: context.collection.manifest.manifest_sha256.clone(),
        stream_task_sha256: context.collection.manifest.stream_task.task_sha256.clone(),
        stream_rank: context.task.stream_rank,
        rank_sha256: context.task.rank_sha256.clone(),
        identity: context.task.identity.clone(),
        name_with_owner: context.name_with_owner.to_string(),
        reason,
        evidence,
        exclusion_sha256: String::new(),
    };
    artifact.exclusion_sha256 = commitment_sha256(&artifact)?;
    validate_historical_v3_materialization_exclusion(
        context.protocol,
        context.collection,
        &artifact,
    )?;
    Ok(artifact)
}

pub(super) fn seal_materialization(
    mut artifact: HistoricalV3Materialization,
) -> Result<HistoricalV3Materialization, HistoricalV3MaterializationError> {
    artifact.materialization_sha256 = commitment_sha256(&artifact)?;
    Ok(artifact)
}

fn commitment_sha256<T>(value: &T) -> Result<String, HistoricalV3MaterializationError>
where
    T: Serialize + Clone + ClearCommitment,
{
    let mut committed = value.clone();
    committed.clear_commitment();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            failed(format!(
                "failed to commit materialization artifact: {error}"
            ))
        })
}

trait ClearCommitment {
    fn clear_commitment(&mut self);
}

impl ClearCommitment for HistoricalV3Materialization {
    fn clear_commitment(&mut self) {
        self.materialization_sha256.clear();
    }
}

impl ClearCommitment for HistoricalV3MaterializationExclusion {
    fn clear_commitment(&mut self) {
        self.exclusion_sha256.clear();
    }
}

fn object_id_length(object_format: &str) -> usize {
    match object_format {
        "sha1" => 40,
        "sha256" => 64,
        _ => 0,
    }
}

fn valid_oid(value: &str, expected_length: usize) -> bool {
    expected_length != 0 && value.len() == expected_length && value.bytes().all(lower_hex)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex)
}

fn valid_rejection_evidence(evidence: &super::HistoricalV3GitCommandEvidence) -> bool {
    evidence.command_label == "fetch exact historical-v3 revision"
        && evidence.exit_code != Some(0)
        && valid_sha256(&evidence.stdout_sha256)
        && valid_sha256(&evidence.stderr_sha256)
        && evidence.retained_stderr.chars().count() <= 4096
        && !evidence.stdout_truncated
        && !evidence.stderr_truncated
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}
