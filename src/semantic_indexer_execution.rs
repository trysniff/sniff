use super::*;
use crate::sandbox::SandboxOutput;

pub(super) async fn run_worker(
    prepared: PreparedIndexerCommand,
    spec: PinnedIndexer,
    verify_before: impl FnOnce(&[RuntimeFileIdentity]) -> Result<(), String>,
) -> Result<SandboxOutput, SemanticIndexerRunFailure> {
    let before = runtime_file_identities(&prepared.runtime_files)
        .and_then(|before| verify_before(&before).map(|()| before))
        .map_err(|detail| {
            execution_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
        })?;
    let result = run_sandbox_command(prepared.command, spec.display_name).await;
    let integrity = runtime_file_identities(&prepared.runtime_files)
        .and_then(|after| verify_runtime_identities_unchanged(spec.display_name, &before, &after));
    finish_worker(spec, result, integrity)
}

pub(super) fn finish_worker(
    spec: PinnedIndexer,
    result: Result<SandboxOutput, String>,
    integrity: Result<(), String>,
) -> Result<SandboxOutput, SemanticIndexerRunFailure> {
    let result = result
        .map(|output| {
            let process = process_evidence(output.clone());
            (output, process)
        })
        .map_err(|detail| execution_failure(spec, SemanticIndexerRunPhase::Execution, detail));
    combine_witnessed_run_and_integrity(
        result,
        integrity.map_err(|detail| {
            execution_failure(spec, SemanticIndexerRunPhase::IntegrityVerification, detail)
        }),
    )
    .map(|(output, _)| output)
}

pub(super) struct Completion<'a> {
    pub(super) spec: PinnedIndexer,
    pub(super) root: &'a Path,
    pub(super) execution_root: &'a Path,
    pub(super) files: &'a [FileRecord],
    pub(super) recovery: &'a SemanticIndexerRecoveryGuard,
    pub(super) typescript_plan: Option<&'a SemanticIndexerVariantPlan>,
    pub(super) source_digest_before: &'a str,
}

impl Completion<'_> {
    pub(super) fn finish(
        &self,
        output: Result<SandboxOutput, SemanticIndexerRunFailure>,
        temporary_project: Option<PathBuf>,
        workspace: Option<TemporaryIndexerWorkspace>,
        cache_root: Option<PathBuf>,
    ) -> Result<SemanticIndexerProcessEvidence, SemanticIndexerRunFailure> {
        let result = output.map(|output| {
            let process = process_evidence(output.clone());
            (output, process)
        });
        let guards = self.guards(temporary_project, workspace, cache_root);
        let (output, process) = combine_witnessed_run_and_integrity(result, guards)?;
        self.validate_output(output).map_err(|mut failure| {
            if failure.process.is_none() {
                failure.process = Some(Box::new(process));
            }
            failure
        })
    }

    fn guards(
        &self,
        temporary_project: Option<PathBuf>,
        workspace: Option<TemporaryIndexerWorkspace>,
        cache_root: Option<PathBuf>,
    ) -> Result<(), SemanticIndexerRunFailure> {
        let project = cleanup_temporary_project(temporary_project, self.spec.display_name).map_err(
            |detail| execution_failure(self.spec, SemanticIndexerRunPhase::Cleanup, detail),
        );
        let workspace = workspace
            .map(|workspace| workspace.cleanup(self.spec.display_name))
            .transpose()
            .map(|_| ())
            .map_err(|detail| {
                execution_failure(self.spec, SemanticIndexerRunPhase::Cleanup, detail)
            });
        let cache = if let Some(cache_root) = cache_root
            && cache_root.exists()
        {
            fs::remove_dir_all(&cache_root).map_err(|error| {
                execution_failure(
                    self.spec,
                    SemanticIndexerRunPhase::Cleanup,
                    format!(
                        "{} indexing completed but private cache cleanup failed for {}: {error}",
                        self.spec.display_name,
                        cache_root.display()
                    ),
                )
            })
        } else {
            Ok(())
        };
        let census = self.verify_census();
        let source = source_integrity_digest_at(self.root, self.execution_root, self.files)
            .and_then(|after| {
                if after == self.source_digest_before { Ok(()) } else {
                    Err(format!("{} indexing changed an eligible source file; refusing to trust its SCIP output", self.spec.display_name))
                }
            })
            .map_err(|detail| execution_failure(self.spec, SemanticIndexerRunPhase::IntegrityVerification, detail));
        [project, workspace, cache, census, source]
            .into_iter()
            .fold(Ok(()), combine_typed_run_and_integrity)
    }

    fn verify_census(&self) -> Result<(), SemanticIndexerRunFailure> {
        let Some(expected) = self
            .typescript_plan
            .and_then(|plan| plan.dimensions.get("source_snapshot_sha256"))
        else {
            return Ok(());
        };
        repository_snapshot::repository_content_digest_with_generated_index(self.execution_root)
            .and_then(|after| {
                if after == *expected { Ok(()) } else {
                    Err("TypeScript indexing changed its compiler census snapshot; refusing its SCIP output".into())
                }
            })
            .map_err(|detail| execution_failure(self.spec, SemanticIndexerRunPhase::IntegrityVerification, detail))
    }

    fn validate_output(
        &self,
        output: SandboxOutput,
    ) -> Result<SemanticIndexerProcessEvidence, SemanticIndexerRunFailure> {
        let spec = self.spec;
        for (exceeded, detail) in [
            (
                output.memory_limit_exceeded,
                format!(
                    "{} exceeded Sniff's {} byte aggregate process-tree memory limit; no weaker semantic provider was used",
                    spec.display_name, INDEXER_MEMORY_LIMIT
                ),
            ),
            (
                output.process_limit_exceeded,
                format!(
                    "{} exceeded Sniff's {} process limit; no weaker semantic provider was used",
                    spec.display_name, INDEXER_PROCESS_LIMIT
                ),
            ),
        ] {
            if exceeded {
                return Err(indexer_process_failure(
                    spec,
                    SemanticIndexerRunFailureKind::RepositoryRejected,
                    SemanticIndexerRunPhase::Execution,
                    detail,
                    output,
                ));
            }
        }
        if output.timed_out {
            return Err(indexer_process_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureUnavailable,
                SemanticIndexerRunPhase::Execution,
                format!(
                    "{} indexing timed out after {}",
                    spec.display_name,
                    format_timeout(index_timeout())
                ),
                output,
            ));
        }
        if output.status_code == Some(0) {
            publish_isolated_index(self.execution_root, self.root, self.recovery).map_err(
                |detail| execution_failure(spec, SemanticIndexerRunPhase::OutputValidation, detail),
            )?;
            let index_path = self.root.join("index.scip");
            if !index_path.is_file() {
                return Err(indexer_process_failure(
                    spec,
                    SemanticIndexerRunFailureKind::IncompleteOutput,
                    SemanticIndexerRunPhase::OutputValidation,
                    format!(
                        "{} exited successfully but did not emit SCIP index {}; output: {}",
                        spec.display_name,
                        index_path.display(),
                        compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
                    ),
                    output,
                ));
            }
            return Ok(process_evidence(output));
        }
        let (kind, detail) = match output.status_code {
            None => (
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                format!(
                    "{} indexing terminated without an exit status; output: {}",
                    spec.display_name,
                    compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
                ),
            ),
            Some(status) => (
                SemanticIndexerRunFailureKind::RepositoryRejected,
                format!(
                    "{} indexing failed with {}; output: {}",
                    spec.display_name,
                    status,
                    compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
                ),
            ),
        };
        Err(indexer_process_failure(
            spec,
            kind,
            SemanticIndexerRunPhase::Execution,
            detail,
            output,
        ))
    }
}

fn execution_failure(
    spec: PinnedIndexer,
    phase: SemanticIndexerRunPhase,
    detail: impl Into<String>,
) -> SemanticIndexerRunFailure {
    indexer_failure(
        spec,
        SemanticIndexerRunFailureKind::InfrastructureFailed,
        phase,
        detail,
    )
}

#[cfg(test)]
#[path = "tests/semantic_indexer_execution.rs"]
mod tests;
