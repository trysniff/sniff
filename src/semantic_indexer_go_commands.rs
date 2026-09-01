use super::*;
use crate::semantic_index::{SemanticIndexerContribution, SemanticIndexerInvocation};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct GoBuildContext {
    GOOS: String,
    GOARCH: String,
    CGO_ENABLED: String,
    GOFLAGS: String,
}

pub(super) struct GoScipExecution<'a> {
    pub(super) spec: PinnedIndexer,
    pub(super) repository_root: &'a Path,
    pub(super) execution_root: &'a Path,
    pub(super) installed: &'a InstalledIndexer,
    pub(super) expected_languages: &'a BTreeMap<RepositoryPath, String>,
    pub(super) context: &'a BTreeMap<String, String>,
}

pub(super) async fn discover_go_build_context(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
) -> Result<(BTreeMap<String, String>, SemanticIndexerInvocation), SemanticIndexerRunFailure> {
    let arguments = vec![
        "env".to_string(),
        "-json".to_string(),
        "GOOS".to_string(),
        "GOARCH".to_string(),
        "CGO_ENABLED".to_string(),
        "GOFLAGS".to_string(),
    ];
    let output = run_go_tool(
        spec,
        root,
        installed,
        arguments.clone(),
        "Go build-context discovery",
    )
    .await?;
    let context: GoBuildContext = serde_json::from_str(&output.stdout).map_err(|error| {
        go_output_validation_failure(
            spec,
            format!("Go build-context discovery returned invalid JSON: {error}"),
            &output,
        )
    })?;
    if context.GOOS.trim().is_empty()
        || context.GOARCH.trim().is_empty()
        || context.CGO_ENABLED.trim().is_empty()
    {
        return Err(go_output_validation_failure(
            spec,
            "Go build-context discovery omitted required values".to_string(),
            &output,
        ));
    }
    let context = BTreeMap::from([
        ("CGO_ENABLED".to_string(), context.CGO_ENABLED),
        ("GOARCH".to_string(), context.GOARCH),
        ("GOFLAGS".to_string(), context.GOFLAGS),
        ("GOOS".to_string(), context.GOOS),
    ]);
    let invocation = command_invocation(
        arguments,
        context.clone(),
        output.stdout_sha256,
        SemanticIndexerContribution::BuildContextDiscovery,
    );
    Ok((context, invocation))
}

fn command_invocation(
    arguments: Vec<String>,
    context: BTreeMap<String, String>,
    output_sha256: String,
    contribution: SemanticIndexerContribution,
) -> SemanticIndexerInvocation {
    SemanticIndexerInvocation {
        arguments,
        context,
        contribution,
        output_sha256,
    }
}

pub(super) fn package_inventory_invocation(
    arguments: Vec<String>,
    context: BTreeMap<String, String>,
    output_sha256: String,
) -> SemanticIndexerInvocation {
    command_invocation(
        arguments,
        context,
        output_sha256,
        SemanticIndexerContribution::PackageInventory,
    )
}

pub(super) async fn run_go_scip(
    execution: &GoScipExecution<'_>,
    patterns: Vec<String>,
    expected_documents: &BTreeSet<RepositoryPath>,
    collect_calls: bool,
) -> Result<SemanticIndex, SemanticIndexerRunFailure> {
    let spec = execution.spec;
    if patterns.is_empty() {
        return Err(indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InvalidInput,
            SemanticIndexerRunPhase::Preparation,
            "Go compiler invocation received no package patterns".to_string(),
        ));
    }
    let index_path = execution.execution_root.join("index.scip");
    if index_path.exists() {
        return Err(indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            format!(
                "previous Go compiler invocation left an unconsumed output {}",
                index_path.display()
            ),
        ));
    }
    let mut arguments = vec!["--module-root".to_string(), ".".to_string()];
    arguments.extend(patterns);
    let invocation_arguments = arguments.clone();
    let prepared = build_indexer_sandbox_command(
        spec,
        execution.execution_root,
        execution.installed,
        arguments,
        None,
    )
    .map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Preparation,
            detail,
        )
    })?;
    let output = run_with_runtime_identity(prepared, spec.display_name)
        .await
        .map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Execution,
                detail,
            )
        })?;
    let output = require_go_command_success(spec, output, spec.display_name)?;
    if !index_path.is_file() {
        return Err(go_output_validation_failure(
            spec,
            format!(
                "{} exited successfully but did not emit {}",
                spec.display_name,
                index_path.display()
            ),
            &output,
        ));
    }
    let result = crate::semantic_index_scip::ingest_scip_file_with_expected_languages(
        execution.repository_root,
        &index_path,
        Some(execution.expected_languages),
        missing_position_encoding(spec.kind),
    )
    .and_then(|mut index| {
        validate_go_documents(&index, expected_documents)?;
        if collect_calls {
            super::go_calls::enrich_go_calls(&mut index, execution.execution_root)?;
        }
        let [invocation]: &mut [SemanticIndexerInvocation; 1] = index
            .provenance
            .invocations
            .as_mut_slice()
            .try_into()
            .map_err(|_| {
                "one scip-go process must produce exactly one provenance invocation".to_string()
            })?;
        invocation.arguments = invocation_arguments;
        invocation.context = execution.context.clone();
        Ok(index)
    })
    .map_err(|detail| go_output_validation_failure(spec, detail, &output));
    let cleanup = fs::remove_file(&index_path).map_err(|error| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Cleanup,
            format!(
                "failed to remove consumed Go compiler output {}: {error}",
                index_path.display()
            ),
        )
    });
    combine_typed_run_and_integrity(result, cleanup)
}

pub(super) fn go_output_validation_failure(
    spec: PinnedIndexer,
    detail: impl Into<String>,
    output: &crate::sandbox::SandboxOutput,
) -> SemanticIndexerRunFailure {
    indexer_process_failure(
        spec,
        SemanticIndexerRunFailureKind::IncompleteOutput,
        SemanticIndexerRunPhase::OutputValidation,
        detail,
        output.clone(),
    )
}

fn validate_go_documents(
    index: &SemanticIndex,
    expected: &BTreeSet<RepositoryPath>,
) -> Result<(), String> {
    let actual = index.documents.keys().cloned().collect::<BTreeSet<_>>();
    if actual == *expected {
        return Ok(());
    }
    let missing = expected
        .difference(&actual)
        .map(|path| path.0.as_str())
        .take(8)
        .collect::<Vec<_>>();
    let unexpected = actual
        .difference(expected)
        .map(|path| path.0.as_str())
        .take(8)
        .collect::<Vec<_>>();
    Err(format!(
        "scip-go package-pattern output disagrees with compiler inventory; missing={missing:?}, unexpected={unexpected:?}"
    ))
}

pub(super) async fn run_go_tool(
    spec: PinnedIndexer,
    root: &Path,
    installed: &InstalledIndexer,
    arguments: Vec<String>,
    operation: &str,
) -> Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure> {
    let mut prepared = build_indexer_sandbox_command(spec, root, installed, Vec::new(), None)
        .map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Preparation,
                detail,
            )
        })?;
    prepared.command.program = go_dependency_program(installed)
        .map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureUnavailable,
                SemanticIndexerRunPhase::Preparation,
                detail,
            )
        })?
        .to_string_lossy()
        .into_owned();
    prepared.command.args = arguments;
    prepared.command.allow_network = false;
    let output = run_with_runtime_identity(prepared, operation)
        .await
        .map_err(|detail| {
            indexer_failure(
                spec,
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                SemanticIndexerRunPhase::Execution,
                detail,
            )
        })?;
    require_go_command_success(spec, output, operation)
}

fn require_go_command_success(
    spec: PinnedIndexer,
    output: crate::sandbox::SandboxOutput,
    operation: &str,
) -> Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure> {
    if output.memory_limit_exceeded {
        return Err(indexer_process_failure(
            spec,
            SemanticIndexerRunFailureKind::RepositoryRejected,
            SemanticIndexerRunPhase::Execution,
            format!(
                "{operation} exceeded Sniff's {INDEXER_MEMORY_LIMIT} byte aggregate process-tree memory limit; no weaker semantic provider was used"
            ),
            output,
        ));
    }
    if output.process_limit_exceeded {
        return Err(indexer_process_failure(
            spec,
            SemanticIndexerRunFailureKind::RepositoryRejected,
            SemanticIndexerRunPhase::Execution,
            format!(
                "{operation} exceeded Sniff's {INDEXER_PROCESS_LIMIT} process limit; no weaker semantic provider was used"
            ),
            output,
        ));
    }
    if output.timed_out {
        return Err(indexer_process_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            SemanticIndexerRunPhase::Execution,
            format!(
                "{operation} timed out after {}",
                format_timeout(index_timeout())
            ),
            output,
        ));
    }
    if output.status_code == Some(0) {
        return Ok(output);
    }
    let kind = if output.status_code.is_none() {
        SemanticIndexerRunFailureKind::InfrastructureFailed
    } else {
        SemanticIndexerRunFailureKind::RepositoryRejected
    };
    Err(indexer_process_failure(
        spec,
        kind,
        SemanticIndexerRunPhase::Execution,
        format!(
            "{operation} failed with {}; output: {}",
            output
                .status_code
                .map_or_else(|| "signal".to_string(), |status| status.to_string()),
            compact_process_output(output.stdout.as_bytes(), output.stderr.as_bytes())
        ),
        output,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_index::{
        SemanticDocument, SemanticIndexProvenance, SemanticPositionEncoding, SemanticTextEncoding,
    };

    fn index(paths: &[&str]) -> SemanticIndex {
        SemanticIndex {
            format_version: crate::semantic_index::SEMANTIC_INDEX_FORMAT_VERSION,
            repository_root: "C:/repo".to_string(),
            provenance: SemanticIndexProvenance {
                format: "scip".to_string(),
                tool_name: "scip-go".to_string(),
                tool_version: Some("0.2.7".to_string()),
                arguments: Vec::new(),
                source_text_encoding: Some(SemanticTextEncoding::Utf8),
                invocations: vec![SemanticIndexerInvocation {
                    arguments: Vec::new(),
                    context: BTreeMap::new(),
                    contribution: SemanticIndexerContribution::CompleteIndex,
                    output_sha256: "0".repeat(64),
                }],
                diagnostics: Vec::new(),
            },
            documents: paths
                .iter()
                .map(|path| {
                    let path = RepositoryPath((*path).to_string());
                    (
                        path.clone(),
                        SemanticDocument {
                            path,
                            language: "go".to_string(),
                            position_encoding: SemanticPositionEncoding::Utf8,
                            embedded_text: None,
                            occurrences: Vec::new(),
                        },
                    )
                })
                .collect(),
            symbols: BTreeMap::new(),
            relationships: BTreeSet::new(),
            imports: BTreeSet::new(),
            calls: BTreeSet::new(),
            test_relationships: BTreeSet::new(),
            unresolved_edges: BTreeSet::new(),
        }
    }

    #[test]
    fn output_validation_failure_retains_successful_process_evidence() {
        let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
        let failure = go_output_validation_failure(
            spec,
            "compiler output omitted a required document",
            &crate::sandbox::SandboxOutput {
                status_code: Some(0),
                stdout: "compiler stdout".to_string(),
                stderr: "compiler stderr".to_string(),
                stdout_sha256: "stdout-sha256".to_string(),
                stderr_sha256: "stderr-sha256".to_string(),
                timed_out: false,
                memory_limit_exceeded: false,
                process_limit_exceeded: false,
            },
        );

        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::IncompleteOutput
        );
        assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
        let process = failure.process.unwrap();
        assert_eq!(process.status_code, Some(0));
        assert_eq!(process.stdout, "compiler stdout");
        assert_eq!(process.stderr, "compiler stderr");
    }

    #[test]
    fn package_output_requires_exact_compiler_document_coverage() {
        let expected = BTreeSet::from([
            RepositoryPath("a.go".to_string()),
            RepositoryPath("a_test.go".to_string()),
        ]);

        validate_go_documents(&index(&["a.go", "a_test.go"]), &expected).unwrap();
        let error = validate_go_documents(&index(&["a.go", "extra.go"]), &expected).unwrap_err();

        assert!(error.contains("missing=[\"a_test.go\"]"));
        assert!(error.contains("unexpected=[\"extra.go\"]"));
    }

    #[test]
    fn package_inventory_provenance_keeps_the_exact_worker_digest() {
        let digest = "ab".repeat(32);

        let invocation =
            package_inventory_invocation(vec!["list".to_string()], BTreeMap::new(), digest.clone());

        assert_eq!(invocation.output_sha256, digest);
        assert_eq!(
            invocation.contribution,
            SemanticIndexerContribution::PackageInventory
        );
    }
}
