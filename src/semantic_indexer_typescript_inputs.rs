use super::*;

pub(super) struct CompilerInputBindings<'a> {
    pub(super) project_model: &'a str,
    pub(super) runtime: &'a str,
    pub(super) installation: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ObservedInputs {
    pub(super) runtime: String,
    pub(super) installation: String,
}

pub(super) fn runtime_sha256(
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    runtime_files: &[PathBuf],
) -> Result<String, String> {
    if spec.kind != SemanticIndexerKind::TypeScriptJavaScript || runtime_files.len() != 1 {
        return Err(
            "TypeScript execution runtime has an unexpected provider or image scope".into(),
        );
    }
    runtime_commitment(spec, installed, &runtime_file_identities(runtime_files)?)
}

fn runtime_commitment(
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    identities: &[RuntimeFileIdentity],
) -> Result<String, String> {
    if spec.kind != SemanticIndexerKind::TypeScriptJavaScript || identities.len() != 1 {
        return Err(
            "TypeScript execution runtime has an unexpected provider or image scope".into(),
        );
    }
    let identities = identities
        .iter()
        .map(|identity| (identity.length, &identity.sha256))
        .collect::<Vec<_>>();
    serde_json::to_vec(&(spec.version, &installed.tree_sha256, identities))
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit TypeScript execution inputs: {error}"))
}

pub(super) fn command_runtime_sha256(
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    program: &Path,
    identities: &[RuntimeFileIdentity],
) -> Result<String, String> {
    let program = fs::canonicalize(program)
        .map_err(|error| format!("failed to identify TypeScript worker program: {error}"))?;
    let mut matches = identities
        .iter()
        .filter(|identity| identity.path == program);
    let identity = matches.next().ok_or_else(|| {
        "TypeScript worker program differs from its observed runtime image".to_string()
    })?;
    if matches.next().is_some() {
        return Err("TypeScript worker program has duplicate runtime observations".into());
    }
    runtime_commitment(spec, installed, std::slice::from_ref(identity))
}

pub(super) fn observe(
    context: &RequiredIndexerRunContext<'_>,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
) -> Result<ObservedInputs, SemanticIndexerRunFailure> {
    let observe = (|| {
        if repository_snapshot::repository_content_digest(context.root)?
            != context.repository_content_sha256
        {
            return Err(
                "TypeScript repository changed since its compiler source snapshot".to_string(),
            );
        }
        let verified = context.store.verify(spec)?;
        if verified != *installed {
            return Err(
                "TypeScript installation changed since compiler world discovery".to_string(),
            );
        }
        let node = resolve_runtime("node")?;
        Ok(ObservedInputs {
            runtime: runtime_sha256(spec, installed, &[node])?,
            installation: installed.tree_sha256.clone(),
        })
    })();
    observe.map_err(|detail| input_failure(spec, detail))
}

pub(super) async fn run_worker(
    prepared: PreparedIndexerCommand,
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    plan: &SemanticIndexerVariantPlan,
) -> Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure> {
    let before = runtime_file_identities(&prepared.runtime_files)
        .map_err(|detail| input_failure(spec, detail))?;
    verify_worker(
        spec,
        installed,
        plan,
        Path::new(&prepared.command.program),
        &before,
    )
    .map_err(|detail| input_failure(spec, detail))?;
    // Bind the same observed image used by the execution integrity guard.
    let result = run_sandbox_command(prepared.command, spec.display_name).await;
    let integrity = runtime_file_identities(&prepared.runtime_files)
        .and_then(|after| verify_runtime_identities_unchanged(spec.display_name, &before, &after));
    finish_worker(spec, result, integrity)
}

fn verify_worker(
    spec: PinnedIndexer,
    installed: &InstalledIndexer,
    plan: &SemanticIndexerVariantPlan,
    program: &Path,
    before: &[RuntimeFileIdentity],
) -> Result<(), String> {
    if before.len() != 1 {
        return Err("TypeScript worker has an unexpected runtime image scope".into());
    }
    let runtime = command_runtime_sha256(spec, installed, program, before)?;
    verify(
        required(std::slice::from_ref(plan))?.as_ref(),
        &ObservedInputs {
            runtime,
            installation: installed.tree_sha256.clone(),
        },
    )
}

fn finish_worker(
    spec: PinnedIndexer,
    result: Result<crate::sandbox::SandboxOutput, String>,
    integrity: Result<(), String>,
) -> Result<crate::sandbox::SandboxOutput, SemanticIndexerRunFailure> {
    let process = result.as_ref().ok().cloned().map(process_evidence);
    let result = result.map_err(|detail| {
        indexer_failure(
            spec,
            SemanticIndexerRunFailureKind::InfrastructureFailed,
            SemanticIndexerRunPhase::Execution,
            detail,
        )
    });
    let integrity = integrity.map_err(|detail| {
        let mut failure = input_failure(spec, detail);
        failure.process = process.map(Box::new);
        failure
    });
    combine_typed_run_and_integrity(result, integrity)
}

pub(super) fn required(
    plans: &[SemanticIndexerVariantPlan],
) -> Result<Option<ObservedInputs>, String> {
    let keys = [
        "project_model_runtime_sha256",
        "discovery_scope",
        "compiler_runtime_sha256",
        "compiler_installation_sha256",
    ];
    if !plans
        .iter()
        .any(|plan| keys.iter().any(|key| plan.dimensions.contains_key(*key)))
    {
        return Ok(None);
    }
    let mut bound = None;
    for plan in plans {
        if plan.dimensions.get("discovery_scope").map(String::as_str)
            != Some("conventional-config-roots-and-compiler-reference-closure")
        {
            return Err(
                "TypeScript normal census cannot mix explicit or unrecognized worlds".into(),
            );
        }
        for key in [
            "project_model_runtime_sha256",
            "source_snapshot_sha256",
            "compiler_runtime_sha256",
            "compiler_installation_sha256",
        ] {
            if !plan
                .dimensions
                .get(key)
                .is_some_and(|value| super::is_lower_sha256(value))
            {
                return Err(format!(
                    "TypeScript normal census is missing or has invalid {key}; rediscover compiler worlds"
                ));
            }
        }
        let actual = ObservedInputs {
            runtime: plan.dimensions["compiler_runtime_sha256"].clone(),
            installation: plan.dimensions["compiler_installation_sha256"].clone(),
        };
        if bound.as_ref().is_some_and(|previous| previous != &actual) {
            return Err("TypeScript compiler worlds disagree on execution inputs".into());
        }
        bound = Some(actual);
    }
    Ok(bound)
}

pub(super) fn verify(
    expected: Option<&ObservedInputs>,
    actual: &ObservedInputs,
) -> Result<(), String> {
    if expected.is_some_and(|expected| expected != actual) {
        return Err("TypeScript execution inputs differ from its compiler project census".into());
    }
    Ok(())
}

pub(super) fn input_failure(
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

#[cfg(test)]
#[path = "tests/semantic_indexer_typescript_inputs.rs"]
mod tests;
