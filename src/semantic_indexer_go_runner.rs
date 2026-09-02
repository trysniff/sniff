use super::go_shards::{
    GO_SHARD_LIMITS, GoShardLimits, parse_go_package_inventory, plan_go_package_shards_with_limits,
    shard_pairs,
};
use super::*;
use crate::semantic_index_merge::{merge_document_shards, merge_implementation_pair};
use crate::semantic_indexer_runner::progress::{
    SemanticProgressScope, SemanticProgressScopeInputs, SemanticProgressStore, SemanticProgressUnit,
};
use serde::Serialize;

use super::go_commands::{
    GoScipExecution, discover_go_build_context, go_output_validation_failure,
    package_inventory_invocation, run_go_scip, run_go_tool,
};

const GO_LIST_FIELDS: &str = "ImportPath,Dir,GoFiles,CgoFiles,TestGoFiles,XTestGoFiles";

pub(super) struct GoIndexerRunInputs<'a> {
    pub(super) spec: PinnedIndexer,
    pub(super) root: &'a Path,
    pub(super) installed: &'a InstalledIndexer,
    pub(super) files: &'a [FileRecord],
    pub(super) required_documents: &'a [FileRecord],
    pub(super) recovery: &'a SemanticIndexerRecoveryGuard,
    pub(super) repository_content_sha256: &'a str,
    pub(super) progress_root: Option<&'a Path>,
}

pub(super) async fn run_required_go_indexer(
    inputs: GoIndexerRunInputs<'_>,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    run_required_go_indexer_with_limits(&inputs, GO_SHARD_LIMITS).await
}

async fn run_required_go_indexer_with_limits(
    inputs: &GoIndexerRunInputs<'_>,
    shard_limits: GoShardLimits,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    let execution_root = inputs.recovery.prepare_indexer_run().map_err(|detail| {
        indexer_failure(
            inputs.spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            detail,
        )
    })?;
    let run_result = run_go_in_recovery_scope(inputs, &execution_root, shard_limits).await;
    let cleanup_result = inputs.recovery.finish_indexer_run().map_err(|detail| {
        indexer_failure(
            inputs.spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Cleanup,
            detail,
        )
    });
    combine_typed_run_and_integrity(run_result, cleanup_result)
}

async fn run_go_in_recovery_scope(
    inputs: &GoIndexerRunInputs<'_>,
    execution_root: &Path,
    shard_limits: GoShardLimits,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    let GoIndexerRunInputs {
        spec,
        root,
        installed,
        files,
        required_documents,
        repository_content_sha256,
        progress_root,
        ..
    } = *inputs;
    repository_snapshot::stage_repository_snapshot(root, execution_root).map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            detail,
        )
    })?;
    fs::create_dir(execution_root.join(INDEXER_TEMP_DIR)).map_err(|error| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            format!(
                "failed to create isolated semantic runtime directory under {}: {error}",
                execution_root.display()
            ),
        )
    })?;
    let source_digest_before =
        source_integrity_digest_at(root, execution_root, files).map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InvalidInput,
                SemanticIndexerRunPhase::IntegrityVerification,
                detail,
            )
        })?;
    prepare_go_dependency_cache(spec, execution_root, installed).await?;
    let (context, context_invocation) =
        discover_go_build_context(spec, execution_root, installed).await?;
    let inventory_arguments = vec![
        "list".to_string(),
        format!("-json={GO_LIST_FIELDS}"),
        "-mod=readonly".to_string(),
        "-buildvcs=false".to_string(),
        "./...".to_string(),
    ];
    let inventory_output = run_go_tool(
        spec,
        execution_root,
        installed,
        inventory_arguments.clone(),
        "Go package inventory",
    )
    .await?;
    let inventory_invocation = package_inventory_invocation(
        inventory_arguments,
        context.clone(),
        inventory_output.stdout_sha256.clone(),
    );
    let packages = parse_go_package_inventory(execution_root, &inventory_output.stdout)
        .map_err(|detail| go_output_validation_failure(spec, detail, &inventory_output))?;
    let package_inventory_sha256 =
        canonical_sha256(&packages).map_err(|detail| go_progress_failure(spec, detail))?;
    let shards = plan_go_package_shards_with_limits(packages, shard_limits)
        .map_err(|detail| go_snapshot_assembly_failure(spec, detail))?;
    let expected_languages =
        expected_document_languages(root, &files_for_indexer(files, spec.kind)).map_err(
            |detail| {
                indexer_failure(
                    spec,
                    SemanticIndexerRunFailureKind::InvalidInput,
                    SemanticIndexerRunPhase::SnapshotAssembly,
                    detail,
                )
            },
        )?;

    let document_units = shards
        .iter()
        .enumerate()
        .map(|(index, shard)| {
            SemanticProgressUnit::new(
                format!("document-{index:08}"),
                "document-shard",
                shard.patterns(),
                &shard.source_documents(),
                true,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|detail| go_progress_failure(spec, detail))?;
    let pairs = shard_pairs(shards.len());
    let pair_units = pairs
        .iter()
        .map(|&(left, right)| {
            let patterns = shards[left]
                .patterns()
                .into_iter()
                .chain(shards[right].patterns())
                .collect();
            let expected_documents = shards[left]
                .source_documents()
                .into_iter()
                .chain(shards[right].source_documents())
                .collect();
            SemanticProgressUnit::new(
                format!("pair-{left:08}-{right:08}"),
                "implementation-pair",
                patterns,
                &expected_documents,
                false,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|detail| go_progress_failure(spec, detail))?;
    let progress = match progress_root {
        Some(progress_root) => {
            let runtime_sha256 = runtime_identity_sha256(spec, execution_root, installed)
                .map_err(|detail| go_progress_failure(spec, detail))?;
            let file_scope_sha256 = file_scope_sha256(root, files, required_documents)
                .map_err(|detail| go_progress_failure(spec, detail))?;
            let shard_plan_sha256 = canonical_sha256(&(shard_limits, &shards))
                .map_err(|detail| go_progress_failure(spec, detail))?;
            let mut units = document_units.clone();
            units.extend(pair_units.clone());
            let scope = SemanticProgressScope::new(SemanticProgressScopeInputs {
                indexer: spec.kind,
                indexer_version: spec.version.to_string(),
                installation_tree_sha256: installed.tree_sha256.clone(),
                runtime_sha256,
                repository_content_sha256: repository_content_sha256.to_string(),
                file_scope_sha256,
                build_context: context.clone(),
                build_context_output_sha256: context_invocation.output_sha256.clone(),
                package_inventory_sha256,
                shard_plan_sha256,
                units,
            })
            .map_err(|detail| go_progress_failure(spec, detail))?;
            Some(
                SemanticProgressStore::open(&progress_root.join("go"), scope)
                    .map_err(|detail| go_progress_failure(spec, detail))?,
            )
        }
        None => None,
    };

    let scip = GoScipExecution {
        spec,
        repository_root: root,
        execution_root,
        installed,
        expected_languages: &expected_languages,
        context: &context,
    };
    let mut document_indexes = Vec::with_capacity(shards.len());
    for (shard, unit) in shards.iter().zip(&document_units) {
        let expected_documents = shard.source_documents();
        document_indexes.push(
            run_or_resume_go_unit(progress.as_ref(), unit, root, spec, || {
                run_go_scip(&scip, shard.patterns(), &expected_documents, true)
            })
            .await?,
        );
    }
    let mut merged = merge_document_shards(document_indexes)
        .map_err(|detail| go_snapshot_assembly_failure(spec, detail))?;
    for ((left, right), unit) in pairs.into_iter().zip(&pair_units) {
        let expected_documents = shards[left]
            .source_documents()
            .into_iter()
            .chain(shards[right].source_documents())
            .collect();
        let pair = run_or_resume_go_unit(progress.as_ref(), unit, root, spec, || {
            run_go_scip(&scip, unit.patterns.clone(), &expected_documents, false)
        })
        .await?;
        merge_implementation_pair(&mut merged, pair)
            .map_err(|detail| go_snapshot_assembly_failure(spec, detail))?;
    }
    merged
        .provenance
        .invocations
        .splice(0..0, [context_invocation, inventory_invocation]);

    let source_digest_after =
        source_integrity_digest_at(root, execution_root, files).map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::IntegrityVerification,
                detail,
            )
        })?;
    if source_digest_before != source_digest_after {
        return Err(indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::IntegrityVerification,
            format!(
                "{} indexing changed an eligible source file; refusing to trust its SCIP output",
                spec.display_name
            ),
        ));
    }
    validate_expected_documents(root, required_documents, spec.kind, merged)
        .map_err(|detail| go_snapshot_assembly_failure(spec, detail))
}

async fn run_or_resume_go_unit<F, Future>(
    progress: Option<&SemanticProgressStore>,
    unit: &SemanticProgressUnit,
    repository_root: &Path,
    spec: PinnedIndexer,
    run: F,
) -> Result<SemanticIndex, SemanticIndexerRunFailure>
where
    F: FnOnce() -> Future,
    Future: std::future::Future<Output = Result<SemanticIndex, SemanticIndexerRunFailure>>,
{
    if let Some(progress) = progress
        && let Some(index) = progress
            .load(unit, repository_root)
            .map_err(|detail| go_progress_failure(spec, detail))?
    {
        return Ok(index);
    }
    let index = run().await?;
    if let Some(progress) = progress {
        progress
            .publish(unit, repository_root, &index)
            .map_err(|detail| go_progress_failure(spec, detail))?;
    }
    Ok(index)
}

fn go_progress_failure(
    spec: PinnedIndexer,
    detail: impl Into<String>,
) -> SemanticIndexerRunFailure {
    indexer_failure(
        spec,
        SemanticIndexerRunFailureKind::InfrastructureFailed,
        SemanticIndexerRunPhase::IntegrityVerification,
        detail,
    )
}

fn runtime_identity_sha256(
    spec: PinnedIndexer,
    execution_root: &Path,
    installed: &InstalledIndexer,
) -> Result<String, String> {
    let prepared =
        build_indexer_sandbox_command(spec, execution_root, installed, Vec::new(), None)?;
    let mut identities = runtime_file_identities(&prepared.runtime_files)?
        .into_iter()
        .map(|identity| (identity.length, identity.sha256))
        .collect::<Vec<_>>();
    identities.sort();
    canonical_sha256(&(spec.version, &installed.tree_sha256, identities))
}

fn file_scope_sha256(
    root: &Path,
    files: &[FileRecord],
    required_documents: &[FileRecord],
) -> Result<String, String> {
    fn records(
        root: &Path,
        files: &[FileRecord],
    ) -> Result<Vec<(RepositoryPath, String, String)>, String> {
        let mut records = files
            .iter()
            .map(|file| {
                Ok((
                    repository_relative_path(root, Path::new(&file.file_path))?,
                    file.language.clone(),
                    format!("{:x}", Sha256::digest(file.source.as_bytes())),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        records.sort();
        Ok(records)
    }
    canonical_sha256(&(records(root, files)?, records(root, required_documents)?))
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to serialize Go semantic progress identity: {error}"))
}

fn go_snapshot_assembly_failure(
    spec: PinnedIndexer,
    detail: impl Into<String>,
) -> SemanticIndexerRunFailure {
    indexer_failure(
        spec,
        SemanticIndexerRunFailureKind::IncompleteOutput,
        SemanticIndexerRunPhase::SnapshotAssembly,
        detail,
    )
}

#[cfg(test)]
#[path = "semantic_indexer_go_runner_tests.rs"]
mod tests;
