use super::go_shards::{
    GO_SHARD_LIMITS, GoShardLimits, parse_go_package_inventory, plan_go_package_shards_with_limits,
    shard_pairs,
};
use super::*;
use crate::semantic_index::{QualifiedSemanticIndex, SemanticIndexSet, SemanticIndexerVariantPlan};
use crate::semantic_index_merge::{
    begin_document_shard, merge_document_shard, merge_implementation_pair,
};
use crate::semantic_indexer_runner::progress::{
    SemanticProgressScope, SemanticProgressScopeInputs, SemanticProgressStore, SemanticProgressUnit,
};
use serde::Serialize;

use super::go_commands::{
    GoScipExecution, discover_go_build_context, go_output_validation_failure,
    package_inventory_invocation, resolve_go_variant_context, run_go_scip, run_go_tool,
    run_go_tool_with_environment,
};

const GO_LIST_FIELDS: &str =
    "ImportPath,Dir,GoFiles,CgoFiles,TestGoFiles,XTestGoFiles,IgnoredGoFiles";

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

pub(super) async fn run_required_go_indexer_variants(
    inputs: GoIndexerRunInputs<'_>,
    plans: &[SemanticIndexerVariantPlan],
) -> Result<SemanticIndexSet, SemanticIndexerRunFailure> {
    run_required_go_indexer_variants_with_limits(&inputs, plans, GO_SHARD_LIMITS).await
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
    let run_result = async {
        let prepared = prepare_go_recovery_scope(inputs, &execution_root).await?;
        let world = run_go_compiler_world(
            inputs,
            &execution_root,
            shard_limits,
            &prepared.expected_languages,
            None,
        )
        .await?;
        verify_go_recovery_scope(inputs, &execution_root, &prepared.source_digest_before)?;
        validate_expected_documents(
            inputs.root,
            inputs.required_documents,
            inputs.spec.kind,
            world.index,
        )
        .map_err(|detail| go_snapshot_assembly_failure(inputs.spec, detail))
    }
    .await;
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

async fn run_required_go_indexer_variants_with_limits(
    inputs: &GoIndexerRunInputs<'_>,
    plans: &[SemanticIndexerVariantPlan],
    shard_limits: GoShardLimits,
) -> Result<SemanticIndexSet, SemanticIndexerRunFailure> {
    if plans.is_empty() {
        return Err(indexer_failure(
            inputs.spec,
            SemanticIndexerRunFailureKind::InvalidInput,
            SemanticIndexerRunPhase::RepositoryValidation,
            "qualified Go semantic indexing requires at least one compiler variant".to_string(),
        ));
    }
    validate_variant_progress_directories(inputs.spec, inputs.progress_root, plans)?;
    let execution_root = inputs.recovery.prepare_indexer_run().map_err(|detail| {
        indexer_failure(
            inputs.spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            detail,
        )
    })?;
    let run_result = async {
        let prepared = prepare_go_recovery_scope(inputs, &execution_root).await?;
        let mut variants = BTreeMap::new();
        let mut selected_documents = BTreeSet::new();
        for plan in plans {
            plan.validate().map_err(|detail| {
                indexer_failure(
                    inputs.spec,
                    SemanticIndexerRunFailureKind::InvalidInput,
                    SemanticIndexerRunPhase::RepositoryValidation,
                    detail,
                )
            })?;
            let world = run_go_compiler_world(
                inputs,
                &execution_root,
                shard_limits,
                &prepared.expected_languages,
                Some(plan),
            )
            .await?;
            selected_documents.extend(world.index.documents.keys().cloned());
            let identity = plan.identity.clone();
            if variants
                .insert(
                    identity.clone(),
                    QualifiedSemanticIndex {
                        index: world.index,
                        ignored_documents: world.ignored_documents,
                    },
                )
                .is_some()
            {
                return Err(go_snapshot_assembly_failure(
                    inputs.spec,
                    format!("Go semantic variant {} was indexed twice", identity.0),
                ));
            }
        }
        require_variant_document_coverage(inputs, &selected_documents)?;
        verify_go_recovery_scope(inputs, &execution_root, &prepared.source_digest_before)?;
        let set = SemanticIndexSet::Qualified { variants };
        set.validate()
            .map_err(|detail| go_snapshot_assembly_failure(inputs.spec, detail))?;
        Ok(set)
    }
    .await;
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

struct PreparedGoRun {
    source_digest_before: String,
    expected_languages: BTreeMap<RepositoryPath, String>,
}

struct GoCompilerWorld {
    index: SemanticIndex,
    ignored_documents: BTreeSet<RepositoryPath>,
}

async fn prepare_go_recovery_scope(
    inputs: &GoIndexerRunInputs<'_>,
    execution_root: &Path,
) -> Result<PreparedGoRun, SemanticIndexerRunFailure> {
    repository_snapshot::stage_repository_snapshot(inputs.root, execution_root).map_err(
        |detail| {
            indexer_failure(
                inputs.spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Preparation,
                detail,
            )
        },
    )?;
    fs::create_dir(execution_root.join(INDEXER_TEMP_DIR)).map_err(|error| {
        indexer_failure(
            inputs.spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            format!(
                "failed to create isolated semantic runtime directory under {}: {error}",
                execution_root.display()
            ),
        )
    })?;
    let source_digest_before =
        source_integrity_digest_at(inputs.root, execution_root, inputs.files).map_err(
            |detail| {
                indexer_failure(
                    inputs.spec,
                    SemanticIndexerRunFailureKind::InvalidInput,
                    SemanticIndexerRunPhase::IntegrityVerification,
                    detail,
                )
            },
        )?;
    prepare_go_dependency_cache(inputs.spec, execution_root, inputs.installed).await?;
    let expected_languages = expected_document_languages(
        inputs.root,
        &files_for_indexer(inputs.files, inputs.spec.kind),
    )
    .map_err(|detail| {
        indexer_failure(
            inputs.spec,
            SemanticIndexerRunFailureKind::InvalidInput,
            SemanticIndexerRunPhase::SnapshotAssembly,
            detail,
        )
    })?;
    Ok(PreparedGoRun {
        source_digest_before,
        expected_languages,
    })
}

fn verify_go_recovery_scope(
    inputs: &GoIndexerRunInputs<'_>,
    execution_root: &Path,
    source_digest_before: &str,
) -> Result<(), SemanticIndexerRunFailure> {
    let source_digest_after = source_integrity_digest_at(inputs.root, execution_root, inputs.files)
        .map_err(|detail| {
            indexer_failure(
                inputs.spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::IntegrityVerification,
                detail,
            )
        })?;
    if source_digest_before != source_digest_after {
        return Err(indexer_failure(
            inputs.spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::IntegrityVerification,
            format!(
                "{} indexing changed an eligible source file; refusing to trust its SCIP output",
                inputs.spec.display_name
            ),
        ));
    }
    Ok(())
}

fn require_variant_document_coverage(
    inputs: &GoIndexerRunInputs<'_>,
    selected_documents: &BTreeSet<RepositoryPath>,
) -> Result<(), SemanticIndexerRunFailure> {
    let required = inputs
        .required_documents
        .iter()
        .filter(|file| files_for_indexer(std::slice::from_ref(file), inputs.spec.kind).len() == 1)
        .map(|file| repository_relative_path(inputs.root, Path::new(&file.file_path)))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|detail| go_snapshot_assembly_failure(inputs.spec, detail))?;
    let missing = required
        .difference(selected_documents)
        .map(|path| path.0.as_str())
        .take(8)
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }
    Err(go_snapshot_assembly_failure(
        inputs.spec,
        format!(
            "Go compiler variants selected no valid context for required documents {missing:?}; explicit unresolved variant coverage is required"
        ),
    ))
}

async fn run_go_compiler_world(
    inputs: &GoIndexerRunInputs<'_>,
    execution_root: &Path,
    shard_limits: GoShardLimits,
    expected_languages: &BTreeMap<RepositoryPath, String>,
    plan: Option<&SemanticIndexerVariantPlan>,
) -> Result<GoCompilerWorld, SemanticIndexerRunFailure> {
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
    let (context, context_invocation, variant) = match plan {
        Some(plan) => {
            let (context, invocation) =
                resolve_go_variant_context(spec, execution_root, installed, plan).await?;
            (context, invocation, plan.index_variant())
        }
        None => {
            let (context, invocation) =
                discover_go_build_context(spec, execution_root, installed).await?;
            (
                context,
                invocation,
                crate::semantic_index::SemanticIndexVariant::Unqualified,
            )
        }
    };
    let inventory_arguments = vec![
        "list".to_string(),
        format!("-json={GO_LIST_FIELDS}"),
        "-mod=readonly".to_string(),
        "-buildvcs=false".to_string(),
        "./...".to_string(),
    ];
    let inventory_output = if plan.is_some() {
        run_go_tool_with_environment(
            spec,
            execution_root,
            installed,
            inventory_arguments.clone(),
            "Go package inventory",
            &context,
        )
        .await?
    } else {
        run_go_tool(
            spec,
            execution_root,
            installed,
            inventory_arguments.clone(),
            "Go package inventory",
        )
        .await?
    };
    let inventory_invocation = package_inventory_invocation(
        inventory_arguments,
        context.clone(),
        inventory_output.stdout_sha256.clone(),
    );
    let inventory = parse_go_package_inventory(execution_root, &inventory_output.stdout)
        .map_err(|detail| go_output_validation_failure(spec, detail, &inventory_output))?;
    if let Some(plan) = plan {
        validate_go_variant_inventory(plan, &inventory)
            .map_err(|detail| go_output_validation_failure(spec, detail, &inventory_output))?;
    }
    let package_inventory_sha256 =
        canonical_sha256(&inventory).map_err(|detail| go_progress_failure(spec, detail))?;
    let ignored_documents = inventory.ignored_documents.clone();
    let shards = plan_go_package_shards_with_limits(inventory.packages, shard_limits)
        .map_err(|detail| go_snapshot_assembly_failure(spec, detail))?;

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
    let assembly_units = document_units
        .iter()
        .chain(&pair_units)
        .cloned()
        .collect::<Vec<_>>();
    let progress = match progress_root {
        Some(progress_root) => {
            let runtime_sha256 = runtime_identity_sha256(spec, execution_root, installed)
                .map_err(|detail| go_progress_failure(spec, detail))?;
            let file_scope_sha256 = file_scope_sha256(root, files, required_documents)
                .map_err(|detail| go_progress_failure(spec, detail))?;
            let shard_plan_sha256 = canonical_sha256(&(shard_limits, &shards))
                .map_err(|detail| go_progress_failure(spec, detail))?;
            let scope = SemanticProgressScope::new(SemanticProgressScopeInputs {
                indexer: spec.kind,
                indexer_version: spec.version.to_string(),
                installation_tree_sha256: installed.tree_sha256.clone(),
                runtime_sha256,
                repository_content_sha256: repository_content_sha256.to_string(),
                file_scope_sha256,
                variant: variant.clone(),
                build_context: context.clone(),
                build_context_output_sha256: context_invocation.output_sha256.clone(),
                package_inventory_sha256,
                shard_plan_sha256,
                units: assembly_units.clone(),
            })
            .map_err(|detail| go_progress_failure(spec, detail))?;
            Some(
                SemanticProgressStore::open(&go_progress_root(spec, progress_root, plan)?, scope)
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
        expected_languages,
        context: &context,
        variant: &variant,
    };
    let mut completed_unit_count = 0;
    let mut merged = None;
    if let Some(progress) = &progress
        && let Some(assembly) = progress
            .load_assembly(root)
            .map_err(|detail| go_progress_failure(spec, detail))?
    {
        completed_unit_count = assembly.completed_unit_count;
        merged = Some(assembly.payload);
    }
    for (unit_index, (shard, unit)) in shards.iter().zip(&document_units).enumerate() {
        if unit_index < completed_unit_count {
            continue;
        }
        let expected_documents = shard.source_documents();
        let index = run_or_resume_go_unit(progress.as_ref(), unit, root, spec, || {
            run_go_scip(&scip, shard.patterns(), &expected_documents, true)
        })
        .await?;
        match &mut merged {
            Some(merged) => merge_document_shard(merged, index),
            None => begin_document_shard(index).map(|index| merged = Some(index)),
        }
        .map_err(|detail| go_snapshot_assembly_failure(spec, detail))?;
        completed_unit_count += 1;
        if let (Some(progress), Some(merged)) = (&progress, &merged) {
            progress
                .publish_assembly(&assembly_units[..completed_unit_count], root, merged)
                .map_err(|detail| go_progress_failure(spec, detail))?;
        }
    }
    let document_unit_count = document_units.len();
    for (pair_index, ((left, right), unit)) in pairs.into_iter().zip(&pair_units).enumerate() {
        let unit_index = document_unit_count + pair_index;
        if unit_index < completed_unit_count {
            continue;
        }
        let expected_documents = shards[left]
            .source_documents()
            .into_iter()
            .chain(shards[right].source_documents())
            .collect();
        let pair = run_or_resume_go_unit(progress.as_ref(), unit, root, spec, || {
            run_go_scip(&scip, unit.patterns.clone(), &expected_documents, false)
        })
        .await?;
        merge_implementation_pair(
            merged.as_mut().ok_or_else(|| {
                go_snapshot_assembly_failure(
                    spec,
                    "implementation-pair assembly omitted every document shard",
                )
            })?,
            pair,
        )
        .map_err(|detail| go_snapshot_assembly_failure(spec, detail))?;
        completed_unit_count += 1;
        if let (Some(progress), Some(merged)) = (&progress, &merged) {
            progress
                .publish_assembly(&assembly_units[..completed_unit_count], root, merged)
                .map_err(|detail| go_progress_failure(spec, detail))?;
        }
    }
    let mut merged = merged.ok_or_else(|| {
        go_snapshot_assembly_failure(spec, "Go semantic assembly omitted every document shard")
    })?;
    merged
        .provenance
        .invocations
        .splice(0..0, [context_invocation, inventory_invocation]);
    Ok(GoCompilerWorld {
        index: merged,
        ignored_documents,
    })
}

fn validate_go_variant_inventory(
    plan: &SemanticIndexerVariantPlan,
    inventory: &super::go_shards::GoPackageInventory,
) -> Result<(), String> {
    let selected = inventory
        .packages
        .iter()
        .flat_map(|package| package.source_documents.iter().cloned())
        .collect::<BTreeSet<_>>();
    let missing_selected = plan
        .selected_documents
        .difference(&selected)
        .map(|path| path.0.as_str())
        .take(8)
        .collect::<Vec<_>>();
    let missing_ignored = plan
        .ignored_documents
        .difference(&inventory.ignored_documents)
        .map(|path| path.0.as_str())
        .take(8)
        .collect::<Vec<_>>();
    if missing_selected.is_empty() && missing_ignored.is_empty() {
        return Ok(());
    }
    Err(format!(
        "Go semantic inventory disagrees with committed variant {}; missing_selected={missing_selected:?}, missing_ignored={missing_ignored:?}",
        plan.identity.0
    ))
}

fn go_progress_root(
    spec: PinnedIndexer,
    progress_root: &Path,
    plan: Option<&SemanticIndexerVariantPlan>,
) -> Result<PathBuf, SemanticIndexerRunFailure> {
    let root = progress_root.join("go");
    let Some(plan) = plan else {
        return Ok(root);
    };
    let identity =
        canonical_sha256(&plan.identity).map_err(|detail| go_progress_failure(spec, detail))?;
    Ok(root.join(identity))
}

fn validate_variant_progress_directories(
    spec: PinnedIndexer,
    progress_root: Option<&Path>,
    plans: &[SemanticIndexerVariantPlan],
) -> Result<(), SemanticIndexerRunFailure> {
    let Some(progress_root) = progress_root else {
        return Ok(());
    };
    let root = progress_root.join("go");
    if !root.exists() {
        return Ok(());
    }
    let expected = plans
        .iter()
        .map(|plan| canonical_sha256(&plan.identity))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|detail| go_progress_failure(spec, detail))?;
    for entry in fs::read_dir(&root).map_err(|error| {
        go_progress_failure(
            spec,
            format!(
                "failed to enumerate Go semantic variant progress {}: {error}",
                root.display()
            ),
        )
    })? {
        let entry = entry.map_err(|error| {
            go_progress_failure(
                spec,
                format!(
                    "failed to inspect Go semantic variant progress {}: {error}",
                    root.display()
                ),
            )
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            go_progress_failure(spec, "Go semantic variant progress has a non-UTF-8 name")
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            go_progress_failure(
                spec,
                format!(
                    "failed to inspect Go semantic variant progress {}: {error}",
                    entry.path().display()
                ),
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || !expected.contains(&name) {
            return Err(go_progress_failure(
                spec,
                format!(
                    "Go semantic variant progress contains an entry outside the committed variant ledger: {}",
                    entry.path().display()
                ),
            ));
        }
    }
    Ok(())
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
