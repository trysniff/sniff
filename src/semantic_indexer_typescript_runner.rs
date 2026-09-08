use super::progress::{
    SemanticProgressScope, SemanticProgressScopeInputs, SemanticProgressStore, SemanticProgressUnit,
};
use super::*;
use serde::Serialize;

struct TypeScriptProgressIdentity {
    runtime_sha256: String,
    repository_content_sha256: String,
    file_scope_sha256: String,
}

pub(super) async fn run_typescript_variants(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    plans: &[SemanticIndexerVariantPlan],
) -> Result<SemanticIndexSet, SemanticIndexerRunFailure> {
    if plans.is_empty() {
        return Err(indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InvalidInput,
            SemanticIndexerRunPhase::RepositoryValidation,
            "TypeScript compiler variant ledger is empty",
        ));
    }
    validate_variant_progress_directories(spec, context.progress_root, plans)?;
    let progress_identity = context
        .progress_root
        .map(|_| prepare_progress_identity(context, spec, installed))
        .transpose()?;
    let mut variants = BTreeMap::new();
    let mut selected_union = BTreeSet::new();
    for plan in plans {
        plan.validate().map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InvalidInput,
                SemanticIndexerRunPhase::RepositoryValidation,
                detail,
            )
        })?;
        let selected_files =
            files_for_plan(context.root, context.files, plan).map_err(|detail| {
                indexer_failure(
                    spec,
                    SemanticIndexerRunFailureKind::InvalidInput,
                    SemanticIndexerRunPhase::RepositoryValidation,
                    detail,
                )
            })?;
        let unit = progress_unit(spec, plan)?;
        let progress = match (context.progress_root, progress_identity.as_ref()) {
            (Some(root), Some(identity)) => Some(open_variant_progress(
                root, spec, installed, plan, &unit, identity,
            )?),
            (None, None) => None,
            _ => {
                return Err(typescript_progress_failure(
                    spec,
                    "TypeScript semantic progress identity is inconsistent",
                ));
            }
        };
        let index = run_or_resume_variant(
            context,
            spec,
            installed,
            plan,
            &selected_files,
            progress.as_ref(),
            &unit,
        )
        .await?;
        selected_union.extend(plan.selected_documents.iter().cloned());
        if variants
            .insert(
                plan.identity.clone(),
                QualifiedSemanticIndex {
                    index,
                    ignored_documents: plan.ignored_documents.clone(),
                },
            )
            .is_some()
        {
            return Err(indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InvalidInput,
                SemanticIndexerRunPhase::OutputValidation,
                format!(
                    "TypeScript compiler variant {} was indexed twice",
                    plan.identity.0
                ),
            ));
        }
    }
    require_selected_union(context, spec, &selected_union)?;
    let set = SemanticIndexSet::Qualified { variants };
    set.validate().map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::IncompleteOutput,
            SemanticIndexerRunPhase::OutputValidation,
            detail,
        )
    })?;
    Ok(set)
}

async fn run_or_resume_variant(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    plan: &SemanticIndexerVariantPlan,
    selected_files: &[FileRecord],
    progress: Option<&SemanticProgressStore>,
    unit: &SemanticProgressUnit,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    let expected_languages = expected_languages(context, spec, selected_files)?;
    if let Some(progress) = progress
        && let Some(index) = progress
            .load(unit, context.root)
            .map_err(|detail| typescript_progress_failure(spec, detail))?
    {
        return validate_variant_index(context, spec, plan, selected_files, index, None);
    }
    let process = match run_one(
        spec,
        context.root,
        installed,
        context.files,
        context.recovery,
        Some(plan),
    )
    .await
    {
        Ok(process) => process,
        Err(run_failure) => {
            return Err(clean_after_failed_run(context.root, spec, run_failure));
        }
    };
    let index_path = context.root.join("index.scip");
    let result = crate::semantic_index_scip::ingest_scip_file_with_expected_languages(
        context.root,
        &index_path,
        Some(&expected_languages),
        missing_position_encoding(spec.kind),
    )
    .and_then(|mut index| {
        index.variant = plan.index_variant();
        Ok(index)
    })
    .map_err(|detail| variant_output_failure(spec, detail, Some(process.clone())))
    .and_then(|index| {
        validate_variant_index(context, spec, plan, selected_files, index, Some(process))
    });
    let cleanup = fs::remove_file(&index_path).map_err(|error| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Cleanup,
            format!(
                "failed to remove TypeScript variant SCIP output {}: {error}",
                index_path.display()
            ),
        )
    });
    let index = combine_typed_run_and_integrity(result, cleanup)?;
    if let Some(progress) = progress {
        progress
            .publish(unit, context.root, &index)
            .map_err(|detail| typescript_progress_failure(spec, detail))?;
    }
    Ok(index)
}

fn validate_variant_index(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    plan: &SemanticIndexerVariantPlan,
    selected_files: &[FileRecord],
    index: SemanticIndex,
    process: Option<SemanticIndexerProcessEvidence>,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    if index.variant != plan.index_variant() {
        return Err(variant_output_failure(
            spec,
            format!(
                "TypeScript semantic checkpoint changed compiler variant {}",
                plan.identity.0
            ),
            process,
        ));
    }
    validate_expected_documents(context.root, selected_files, spec.kind, index)
        .and_then(|index| reject_ignored_documents(index, plan))
        .map_err(|detail| variant_output_failure(spec, detail, process))
}

fn expected_languages(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    selected_files: &[FileRecord],
) -> Result<BTreeMap<RepositoryPath, String>, SemanticIndexerRunFailure> {
    expected_document_languages(context.root, selected_files).map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InvalidInput,
            SemanticIndexerRunPhase::OutputValidation,
            detail,
        )
    })
}

fn variant_output_failure(
    spec: PinnedIndexer,
    detail: impl Into<String>,
    process: Option<SemanticIndexerProcessEvidence>,
) -> SemanticIndexerRunFailure {
    SemanticIndexerRunFailure {
        kind: SemanticIndexerRunFailureKind::IncompleteOutput,
        phase: SemanticIndexerRunPhase::OutputValidation,
        indexer: Some(spec.kind),
        detail: detail.into(),
        process: process.map(Box::new),
    }
}

fn progress_unit(
    spec: PinnedIndexer,
    plan: &SemanticIndexerVariantPlan,
) -> Result<SemanticProgressUnit, SemanticIndexerRunFailure> {
    SemanticProgressUnit::new(
        "compiler-project".to_string(),
        "compiler-project",
        variant_arguments(spec, plan).map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InvalidInput,
                SemanticIndexerRunPhase::RepositoryValidation,
                detail,
            )
        })?,
        &plan.selected_documents,
        true,
    )
    .map_err(|detail| typescript_progress_failure(spec, detail))
}

fn prepare_progress_identity(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
) -> Result<TypeScriptProgressIdentity, SemanticIndexerRunFailure> {
    let node = resolve_runtime("node").map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::Preparation,
            detail,
        )
    })?;
    let runtime_files = runtime_file_identities(&[node])
        .map_err(|detail| typescript_progress_failure(spec, detail))?;
    let runtime_files = runtime_files
        .into_iter()
        .map(|identity| (identity.length, identity.sha256))
        .collect::<Vec<_>>();
    let runtime_sha256 = canonical_sha256(&(spec.version, &installed.tree_sha256, runtime_files))
        .map_err(|detail| typescript_progress_failure(spec, detail))?;
    let file_scope_sha256 =
        file_scope_sha256(context.root, context.files, context.required_documents)
            .map_err(|detail| typescript_progress_failure(spec, detail))?;
    Ok(TypeScriptProgressIdentity {
        runtime_sha256,
        repository_content_sha256: context.repository_content_sha256.to_string(),
        file_scope_sha256,
    })
}

fn open_variant_progress(
    progress_root: &Path,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    plan: &SemanticIndexerVariantPlan,
    unit: &SemanticProgressUnit,
    identity: &TypeScriptProgressIdentity,
) -> Result<SemanticProgressStore, SemanticIndexerRunFailure> {
    let mut compiler_context = plan
        .dimensions
        .iter()
        .map(|(name, value)| (format!("dimension:{name}"), value.clone()))
        .collect::<BTreeMap<_, _>>();
    compiler_context.extend(
        plan.environment
            .iter()
            .map(|(name, value)| (format!("environment:{name}"), value.clone())),
    );
    if let Some(project) = &plan.compiler_project {
        compiler_context.insert("compiler_project".to_string(), project.0.clone());
    }
    let scope = SemanticProgressScope::new(SemanticProgressScopeInputs {
        indexer: spec.kind,
        indexer_version: spec.version.to_string(),
        installation_tree_sha256: installed.tree_sha256.clone(),
        runtime_sha256: identity.runtime_sha256.clone(),
        repository_content_sha256: identity.repository_content_sha256.clone(),
        file_scope_sha256: identity.file_scope_sha256.clone(),
        variant: plan.index_variant(),
        compiler_context,
        compiler_context_sha256: canonical_sha256(plan)
            .map_err(|detail| typescript_progress_failure(spec, detail))?,
        document_partition_sha256: canonical_sha256(&(
            &plan.selected_documents,
            &plan.ignored_documents,
        ))
        .map_err(|detail| typescript_progress_failure(spec, detail))?,
        unit_plan_sha256: canonical_sha256(unit)
            .map_err(|detail| typescript_progress_failure(spec, detail))?,
        units: vec![unit.clone()],
    })
    .map_err(|detail| typescript_progress_failure(spec, detail))?;
    SemanticProgressStore::open(&typescript_progress_root(progress_root, spec, plan)?, scope)
        .map_err(|detail| typescript_progress_failure(spec, detail))
}

fn typescript_progress_root(
    progress_root: &Path,
    spec: PinnedIndexer,
    plan: &SemanticIndexerVariantPlan,
) -> Result<PathBuf, SemanticIndexerRunFailure> {
    let identity = canonical_sha256(&plan.identity)
        .map_err(|detail| typescript_progress_failure(spec, detail))?;
    let root = ensure_semantic_progress_family(progress_root, "typescript")
        .map_err(|detail| typescript_progress_failure(spec, detail))?;
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
    let root = progress_root.join("typescript");
    if !root.exists() {
        return Ok(());
    }
    let expected = plans
        .iter()
        .map(|plan| canonical_sha256(&plan.identity))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|detail| typescript_progress_failure(spec, detail))?;
    for entry in fs::read_dir(&root).map_err(|error| {
        typescript_progress_failure(
            spec,
            format!(
                "failed to enumerate TypeScript semantic variant progress {}: {error}",
                root.display()
            ),
        )
    })? {
        let entry = entry.map_err(|error| {
            typescript_progress_failure(
                spec,
                format!(
                    "failed to inspect TypeScript semantic variant progress {}: {error}",
                    root.display()
                ),
            )
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            typescript_progress_failure(
                spec,
                "TypeScript semantic variant progress has a non-UTF-8 name",
            )
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            typescript_progress_failure(
                spec,
                format!(
                    "failed to inspect TypeScript semantic variant progress {}: {error}",
                    entry.path().display()
                ),
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || !expected.contains(&name) {
            return Err(typescript_progress_failure(
                spec,
                format!(
                    "TypeScript semantic variant progress contains an entry outside the committed variant ledger: {}",
                    entry.path().display()
                ),
            ));
        }
    }
    Ok(())
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
        .map_err(|error| format!("failed to serialize TypeScript semantic progress: {error}"))
}

fn typescript_progress_failure(
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

fn clean_after_failed_run(
    root: &Path,
    spec: PinnedIndexer,
    run_failure: SemanticIndexerRunFailure,
) -> SemanticIndexerRunFailure {
    let index_path = root.join("index.scip");
    if !index_path.exists() {
        return run_failure;
    }
    match fs::remove_file(&index_path) {
        Ok(()) => run_failure,
        Err(error) => SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::InfrastructureFailed,
            phase: SemanticIndexerRunPhase::Cleanup,
            indexer: Some(spec.kind),
            detail: format!(
                "{}; additionally failed to remove generated TypeScript variant output {}: {error}",
                run_failure.detail,
                index_path.display()
            ),
            process: run_failure.process,
        },
    }
}

fn reject_ignored_documents(
    index: SemanticIndex,
    plan: &SemanticIndexerVariantPlan,
) -> Result<SemanticIndex, String> {
    let conflicts = index
        .documents
        .keys()
        .filter(|document| plan.ignored_documents.contains(*document))
        .take(8)
        .map(|document| document.0.as_str())
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        Ok(index)
    } else {
        Err(format!(
            "TypeScript compiler variant {} indexed explicitly ignored documents {conflicts:?}",
            plan.identity.0
        ))
    }
}

fn require_selected_union(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    selected_union: &BTreeSet<RepositoryPath>,
) -> Result<(), SemanticIndexerRunFailure> {
    let required = files_for_indexer(context.required_documents, spec.kind)
        .iter()
        .map(|file| repository_relative_path(context.root, Path::new(&file.file_path)))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InvalidInput,
                SemanticIndexerRunPhase::OutputValidation,
                detail,
            )
        })?;
    let missing = required
        .difference(selected_union)
        .take(8)
        .map(|path| path.0.as_str())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::IncompleteOutput,
            SemanticIndexerRunPhase::OutputValidation,
            format!(
                "TypeScript compiler variants selected no valid context for required documents {missing:?}"
            ),
        ))
    }
}

fn files_for_plan(
    root: &Path,
    files: &[FileRecord],
    plan: &SemanticIndexerVariantPlan,
) -> Result<Vec<FileRecord>, String> {
    let available = files_for_indexer(files, SemanticIndexerKind::TypeScriptJavaScript)
        .into_iter()
        .map(|file| {
            let path = repository_relative_path(root, Path::new(&file.file_path))?;
            Ok((path, file))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let known = plan
        .selected_documents
        .iter()
        .chain(&plan.ignored_documents)
        .collect::<BTreeSet<_>>();
    let unknown = known
        .iter()
        .filter(|path| !available.contains_key(*path))
        .take(8)
        .map(|path| path.0.as_str())
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(format!(
            "TypeScript compiler variant {} references unknown documents {unknown:?}",
            plan.identity.0
        ));
    }
    plan.selected_documents
        .iter()
        .map(|path| {
            available.get(path).cloned().ok_or_else(|| {
                format!(
                    "TypeScript compiler variant {} omitted selected document {}",
                    plan.identity.0, path.0
                )
            })
        })
        .collect()
}

pub(super) fn variant_arguments(
    spec: PinnedIndexer,
    plan: &SemanticIndexerVariantPlan,
) -> Result<Vec<String>, String> {
    if spec.kind != SemanticIndexerKind::TypeScriptJavaScript {
        return Err("compiler-project arguments require scip-typescript".to_string());
    }
    let mut arguments = vec!["index".to_string()];
    match &plan.compiler_project {
        Some(project) => arguments.push(project.0.clone()),
        None => {
            arguments.push(".".to_string());
            arguments.push("--infer-tsconfig".to_string());
        }
    }
    Ok(arguments)
}

#[cfg(test)]
#[path = "semantic_indexer_typescript_runner_tests.rs"]
mod tests;
