use super::commitment::{exclusion, seal_materialization, validate_historical_v3_materialization};
use super::git::{
    add_worktree, apply_patch, binary_patch, clone_repository, create_destination,
    fetch_exact_revision, fetch_pull_head, inspect_repository, is_ancestor, pull_head,
    remove_destination, set_origin, sha256, write_tree,
};
use super::layout::write_new;
use super::{
    CandidateContext, HISTORICAL_V3_MATERIALIZATION_SCHEMA_VERSION,
    HistoricalV3CandidateCollection, HistoricalV3Materialization, HistoricalV3MaterializationError,
    HistoricalV3MaterializationExclusionEvidence, HistoricalV3MaterializationExclusionReason,
    HistoricalV3MaterializationOutcome, HistoricalV3MaterializedRoots, HistoricalV3Protocol,
    HistoricalV3RevisionKind, HistoricalV3UnavailableRevision, MATERIALIZATION_CONTRACT,
    candidate_context, failed,
};
use std::path::Path;

pub fn materialize_historical_v3_candidate(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    destination: &Path,
) -> Result<HistoricalV3MaterializationOutcome, HistoricalV3MaterializationError> {
    let context = candidate_context(protocol, collection, stream_rank)?;
    let source_url = context.clone_url.clone();
    materialize_from_url(context, destination, &source_url)
}

fn materialize_from_url(
    context: CandidateContext<'_>,
    destination: &Path,
    source_url: &str,
) -> Result<HistoricalV3MaterializationOutcome, HistoricalV3MaterializationError> {
    let destination = create_destination(destination)?;
    match materialize_created_destination(&context, &destination, source_url) {
        Ok(HistoricalV3MaterializationOutcome::Excluded(exclusion)) => {
            remove_destination(&destination)?;
            Ok(HistoricalV3MaterializationOutcome::Excluded(exclusion))
        }
        Ok(completed) => Ok(completed),
        Err(error) => match remove_destination(&destination) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(failed(format!(
                "{}; cleanup also failed: {}",
                error.detail, cleanup.detail
            ))),
        },
    }
}

fn materialize_created_destination(
    context: &CandidateContext<'_>,
    destination: &Path,
    source_url: &str,
) -> Result<HistoricalV3MaterializationOutcome, HistoricalV3MaterializationError> {
    let repository_root = destination.join("repository");
    clone_repository(source_url, &repository_root)?;
    fetch_pull_head(&repository_root, context.task.identity.pull_request_number)?;
    set_origin(&repository_root, &context.clone_url)?;

    let fetched_head = pull_head(&repository_root)?;
    if fetched_head != context.task.identity.head_commit {
        return exclusion(
            context,
            HistoricalV3MaterializationExclusionReason::PullRequestHeadChanged,
            HistoricalV3MaterializationExclusionEvidence::PullRequestHeadChanged {
                expected_head_commit: context.task.identity.head_commit.clone(),
                fetched_head_commit: fetched_head,
            },
        )
        .map(|artifact| HistoricalV3MaterializationOutcome::Excluded(Box::new(artifact)));
    }

    let mut missing = Vec::new();
    for (kind, revision, local_ref) in [
        (
            HistoricalV3RevisionKind::Base,
            context.task.identity.base_commit.as_str(),
            "refs/sniff/historical-v3-base",
        ),
        (
            HistoricalV3RevisionKind::Head,
            context.task.identity.head_commit.as_str(),
            "refs/sniff/historical-v3-exact-head",
        ),
        (
            HistoricalV3RevisionKind::Merge,
            context.task.identity.merge_commit.as_str(),
            "refs/sniff/historical-v3-merge",
        ),
    ] {
        if let Some(fetch) = fetch_exact_revision(&repository_root, revision, local_ref)? {
            missing.push(HistoricalV3UnavailableRevision {
                kind,
                revision: revision.to_string(),
                fetch,
            });
        }
    }
    if !missing.is_empty() {
        return exclusion(
            context,
            HistoricalV3MaterializationExclusionReason::RevisionUnavailable,
            HistoricalV3MaterializationExclusionEvidence::RevisionUnavailable { missing },
        )
        .map(|artifact| HistoricalV3MaterializationOutcome::Excluded(Box::new(artifact)));
    }

    let facts = inspect_repository(
        &repository_root,
        &context.task.identity.base_commit,
        &context.task.identity.head_commit,
        &context.task.identity.merge_commit,
    )?;
    if !matches!(facts.object_format.as_str(), "sha1" | "sha256") {
        return exclusion(
            context,
            HistoricalV3MaterializationExclusionReason::UnsupportedGitObjectFormat,
            HistoricalV3MaterializationExclusionEvidence::UnsupportedGitObjectFormat {
                object_format: facts.object_format,
            },
        )
        .map(|artifact| HistoricalV3MaterializationOutcome::Excluded(Box::new(artifact)));
    }
    if !is_ancestor(
        &repository_root,
        &context.task.identity.base_commit,
        &context.task.identity.merge_commit,
    )? {
        return exclusion(
            context,
            HistoricalV3MaterializationExclusionReason::BaseNotAncestorOfMerge,
            HistoricalV3MaterializationExclusionEvidence::BaseNotAncestorOfMerge {
                base_commit: context.task.identity.base_commit.clone(),
                merge_commit: context.task.identity.merge_commit.clone(),
            },
        )
        .map(|artifact| HistoricalV3MaterializationOutcome::Excluded(Box::new(artifact)));
    }

    let patch = binary_patch(
        &repository_root,
        &context.task.identity.base_commit,
        &context.task.identity.merge_commit,
    )?;
    let patch_sha256 = sha256(&patch);
    let patch_path = destination.join("merge.patch");
    write_new(&patch_path, &patch)?;
    let base_root = destination.join("base");
    let head_root = destination.join("head");
    let merge_root = destination.join("merge");
    let reproduced_root = destination.join("reproduced");
    add_worktree(
        &repository_root,
        &base_root,
        &context.task.identity.base_commit,
    )?;
    add_worktree(
        &repository_root,
        &head_root,
        &context.task.identity.head_commit,
    )?;
    add_worktree(
        &repository_root,
        &merge_root,
        &context.task.identity.merge_commit,
    )?;
    add_worktree(
        &repository_root,
        &reproduced_root,
        &context.task.identity.base_commit,
    )?;
    if !patch.is_empty() && !apply_patch(&reproduced_root, &patch_path)? {
        return exclusion(
            context,
            HistoricalV3MaterializationExclusionReason::PatchDoesNotReproduceMerge,
            HistoricalV3MaterializationExclusionEvidence::PatchDoesNotReproduceMerge {
                patch_sha256,
                expected_merge_tree: facts.merge_tree,
                reproduced_tree: None,
            },
        )
        .map(|artifact| HistoricalV3MaterializationOutcome::Excluded(Box::new(artifact)));
    }
    let reproduced_tree = write_tree(&reproduced_root)?;
    if reproduced_tree != facts.merge_tree {
        return exclusion(
            context,
            HistoricalV3MaterializationExclusionReason::PatchDoesNotReproduceMerge,
            HistoricalV3MaterializationExclusionEvidence::PatchDoesNotReproduceMerge {
                patch_sha256,
                expected_merge_tree: facts.merge_tree,
                reproduced_tree: Some(reproduced_tree),
            },
        )
        .map(|artifact| HistoricalV3MaterializationOutcome::Excluded(Box::new(artifact)));
    }

    let patch_byte_count =
        u64::try_from(patch.len()).map_err(|_| failed("historical-v3 patch length exceeds u64"))?;
    let artifact = seal_materialization(HistoricalV3Materialization {
        schema_version: HISTORICAL_V3_MATERIALIZATION_SCHEMA_VERSION,
        materialization_contract: MATERIALIZATION_CONTRACT.to_string(),
        protocol_sha256: context.protocol.protocol_sha256.clone(),
        candidate_manifest_sha256: context.collection.manifest.manifest_sha256.clone(),
        stream_task_sha256: context.collection.manifest.stream_task.task_sha256.clone(),
        stream_rank: context.task.stream_rank,
        rank_sha256: context.task.rank_sha256.clone(),
        identity: context.task.identity.clone(),
        name_with_owner: context.name_with_owner.to_string(),
        clone_url: context.clone_url.clone(),
        git_object_format: facts.object_format,
        base_tree_oid: facts.base_tree,
        head_tree_oid: facts.head_tree,
        merge_tree_oid: facts.merge_tree,
        merge_parent_commits: facts.merge_parents,
        patch_sha256,
        patch_byte_count,
        materialization_sha256: String::new(),
    })?;
    let roots = HistoricalV3MaterializedRoots {
        repository_root,
        base_root,
        head_root,
        merge_root,
        reproduced_root,
        patch_path,
    };
    validate_historical_v3_materialization(
        context.protocol,
        context.collection,
        &artifact,
        &roots,
    )?;
    Ok(HistoricalV3MaterializationOutcome::Completed {
        artifact: Box::new(artifact),
        roots,
    })
}

#[cfg(test)]
pub(crate) fn materialize_historical_v3_candidate_from_url(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    destination: &Path,
    source_url: &str,
) -> Result<HistoricalV3MaterializationOutcome, HistoricalV3MaterializationError> {
    let context = candidate_context(protocol, collection, stream_rank)?;
    materialize_from_url(context, destination, source_url)
}
