use super::go_shards::{
    GO_SHARD_LIMITS, GoShardLimits, parse_go_package_inventory, plan_go_package_shards_with_limits,
    shard_pairs,
};
use super::*;
use crate::semantic_index_merge::{merge_document_shards, merge_implementation_pair};

use super::go_commands::{
    GoScipExecution, discover_go_build_context, package_inventory_invocation, run_go_scip,
    run_go_tool,
};

const GO_LIST_FIELDS: &str = "ImportPath,Dir,GoFiles,CgoFiles,TestGoFiles,XTestGoFiles";

pub(super) async fn run_required_go_indexer(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
    files: &[FileRecord],
    required_documents: &[FileRecord],
    recovery: &SemanticIndexerRecoveryGuard,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    run_required_go_indexer_with_limits(
        spec,
        root,
        installed,
        files,
        required_documents,
        recovery,
        GO_SHARD_LIMITS,
    )
    .await
}

async fn run_required_go_indexer_with_limits(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
    files: &[FileRecord],
    required_documents: &[FileRecord],
    recovery: &SemanticIndexerRecoveryGuard,
    shard_limits: GoShardLimits,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    let execution_root = recovery.prepare_indexer_run().map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            detail,
        )
    })?;
    let run_result = run_go_in_recovery_scope(
        spec,
        root,
        &execution_root,
        installed,
        files,
        required_documents,
        shard_limits,
    )
    .await;
    let cleanup_result = recovery.finish_indexer_run().map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Cleanup,
            detail,
        )
    });
    combine_typed_run_and_integrity(run_result, cleanup_result)
}

async fn run_go_in_recovery_scope(
    spec: PinnedIndexer,
    root: &Path,
    execution_root: &Path,
    installed: &InstalledIndexer,
    files: &[FileRecord],
    required_documents: &[FileRecord],
    shard_limits: GoShardLimits,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
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
    let packages =
        parse_go_package_inventory(execution_root, &inventory_output.stdout).map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::IncompleteOutput,
                SemanticIndexerRunPhase::OutputValidation,
                detail,
            )
        })?;
    let shards = plan_go_package_shards_with_limits(packages, shard_limits).map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::IncompleteOutput,
            SemanticIndexerRunPhase::OutputValidation,
            detail,
        )
    })?;
    let expected_languages =
        expected_document_languages(root, &files_for_indexer(files, spec.kind)).map_err(
            |detail| {
                indexer_failure(
                    spec,
                    SemanticIndexerRunFailureKind::InvalidInput,
                    SemanticIndexerRunPhase::OutputValidation,
                    detail,
                )
            },
        )?;

    let scip = GoScipExecution {
        spec,
        repository_root: root,
        execution_root,
        installed,
        expected_languages: &expected_languages,
        context: &context,
    };
    let mut document_indexes = Vec::with_capacity(shards.len());
    for shard in &shards {
        document_indexes
            .push(run_go_scip(&scip, shard.patterns(), &shard.source_documents(), true).await?);
    }
    let mut merged = merge_document_shards(document_indexes).map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::IncompleteOutput,
            SemanticIndexerRunPhase::OutputValidation,
            detail,
        )
    })?;
    for (left, right) in shard_pairs(shards.len()) {
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
        let pair = run_go_scip(&scip, patterns, &expected_documents, false).await?;
        merge_implementation_pair(&mut merged, pair).map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::IncompleteOutput,
                SemanticIndexerRunPhase::OutputValidation,
                detail,
            )
        })?;
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
    validate_expected_documents(root, required_documents, spec.kind, merged).map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::IncompleteOutput,
            SemanticIndexerRunPhase::OutputValidation,
            detail,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_index::{
        RepositoryPath, SemanticIndexerContribution, SemanticRelationshipKind, SemanticResolution,
        SemanticSymbolId,
    };
    use crate::semantic_indexer_installation::SemanticIndexerStore;

    fn write_go_file(root: &Path, relative: &str, source: &str) -> FileRecord {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, source).unwrap();
        FileRecord {
            file_path: path.to_string_lossy().into_owned(),
            source: source.to_string(),
            language: "go".to_string(),
            methods: Vec::new(),
        }
    }

    fn symbol_id(index: &SemanticIndex, display_name: &str) -> SemanticSymbolId {
        let matches = index
            .symbols
            .values()
            .filter(|symbol| symbol.display_name.as_deref() == Some(display_name))
            .map(|symbol| symbol.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one compiler symbol named {display_name}: {matches:?}"
        );
        matches.into_iter().next().unwrap()
    }

    #[tokio::test]
    #[ignore = "requires the installed pinned Go semantic indexer"]
    async fn live_multi_shard_go_index_preserves_calls_and_structural_implementations() {
        let repository = tempfile::tempdir().unwrap();
        fs::write(
            repository.path().join("go.mod"),
            "module example.test/sharded\n\ngo 1.22\n",
        )
        .unwrap();
        let files = vec![
            write_go_file(
                repository.path(),
                "contract/contract.go",
                "package contract\n\ntype Speaker interface { Speak() string }\n\nfunc Invoke(s Speaker) string { return s.Speak() }\n",
            ),
            write_go_file(
                repository.path(),
                "impl/impl.go",
                "package impl\n\ntype Dog struct{}\n\nfunc (Dog) Speak() string { return \"woof\" }\n",
            ),
            write_go_file(
                repository.path(),
                "app/app.go",
                "package app\n\nimport (\n    \"example.test/sharded/contract\"\n    \"example.test/sharded/impl\"\n)\n\nfunc Run() string { return contract.Invoke(impl.Dog{}) }\n",
            ),
        ];
        let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
        let store = SemanticIndexerStore::for_user().unwrap();
        let installed = store.verify(spec).unwrap();
        let recovery = SemanticIndexerRecoveryGuard::begin(repository.path()).unwrap();

        let result = run_required_go_indexer_with_limits(
            spec,
            repository.path(),
            &installed,
            &files,
            &files,
            &recovery,
            GoShardLimits {
                target_source_bytes: u64::MAX,
                max_packages: 1,
            },
        )
        .await;
        recovery.finish().unwrap();
        let index = result.unwrap();

        assert_eq!(
            index.documents.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                RepositoryPath("app/app.go".to_string()),
                RepositoryPath("contract/contract.go".to_string()),
                RepositoryPath("impl/impl.go".to_string()),
            ])
        );
        let contribution_count = |contribution| {
            index
                .provenance
                .invocations
                .iter()
                .filter(|invocation| invocation.contribution == contribution)
                .count()
        };
        assert_eq!(
            contribution_count(SemanticIndexerContribution::BuildContextDiscovery),
            1
        );
        assert_eq!(
            contribution_count(SemanticIndexerContribution::PackageInventory),
            1
        );
        assert_eq!(
            contribution_count(SemanticIndexerContribution::DocumentShard),
            3
        );
        assert_eq!(
            contribution_count(SemanticIndexerContribution::ImplementationPair),
            3
        );

        let run = symbol_id(&index, "Run");
        let invoke = symbol_id(&index, "Invoke");
        assert!(index.calls.iter().any(|call| {
            call.caller == run
                && call.callee
                    == SemanticResolution::Resolved {
                        value: invoke.clone(),
                    }
        }));

        let dog = symbol_id(&index, "Dog");
        let speaker = symbol_id(&index, "Speaker");
        assert!(index.relationships.iter().any(|relationship| {
            relationship.kind == SemanticRelationshipKind::Implementation
                && relationship.source == dog
                && relationship.target == speaker
        }));
    }
}
