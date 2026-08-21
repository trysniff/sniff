use super::{
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_BINDING_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundaryProjectModelBinding,
    IntentionalBoundaryProjectModelBindingCensus,
    IntentionalBoundaryProjectModelBindingOutcome as Outcome,
    IntentionalBoundaryProjectModelBindingUnresolvedReason as UnresolvedReason,
    IntentionalBoundaryProjectModelBoundSubject, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryProjectModelNonMethodReason as NonMethodReason,
    IntentionalBoundaryProjectModelTarget, IntentionalBoundaryProjectModelTargetStatus,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySourceCensus, validate_intentional_boundary_project_model_census_commitment,
    validate_intentional_boundary_semantic_census,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const BINDING_CONTRACT: &str = "sniffbench-intentional-boundary-project-model-bindings-v2";

pub fn bind_intentional_boundary_project_models(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
) -> Result<IntentionalBoundaryProjectModelBindingCensus, String> {
    validate_intentional_boundary_project_model_census_commitment(inventory, project_model_census)?;
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    if source_census.inventory_sha256 != inventory.inventory_sha256
        || source_census.repository != project_model_census.repository
        || source_census.revision != project_model_census.revision
    {
        return Err("intentional-boundary project-model binding identity changed".to_string());
    }
    let semantic_methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let bindings = project_model_census
        .targets
        .iter()
        .map(|target| {
            Ok(IntentionalBoundaryProjectModelBinding {
                target_id: target.target_id.clone(),
                outcome: bind_target(source_census, &semantic_methods, target)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    finish_binding_census(
        source_census,
        semantic_census,
        project_model_census,
        bindings,
    )
}

pub fn validate_intentional_boundary_project_model_bindings(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    binding_census: &IntentionalBoundaryProjectModelBindingCensus,
) -> Result<(), String> {
    let expected = bind_intentional_boundary_project_models(
        inventory,
        source_census,
        semantic_census,
        project_model_census,
    )?;
    if binding_census != &expected {
        return Err("intentional-boundary project-model bindings changed".to_string());
    }
    Ok(())
}

fn bind_target(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_methods: &BTreeMap<&str, &IntentionalBoundarySemanticMethod>,
    target: &IntentionalBoundaryProjectModelTarget,
) -> Result<Outcome, String> {
    let (declaration_kind, selector) = match &target.target_status {
        IntentionalBoundaryProjectModelTargetStatus::Boundary {
            declaration_kind,
            target,
        } => (*declaration_kind, target),
        IntentionalBoundaryProjectModelTargetStatus::NonBoundary { reason } => {
            return Ok(Outcome::NonBoundary { reason: *reason });
        }
        IntentionalBoundaryProjectModelTargetStatus::Unresolved { reason, detail } => {
            return Ok(Outcome::UpstreamUnresolved {
                reason: *reason,
                detail: detail.clone(),
            });
        }
    };
    if declaration_kind == IntentionalBoundaryManifestDeclarationKind::BuildScript {
        return Ok(Outcome::AwaitingGeneratorReplay);
    }
    let repository_paths = match selector {
        IntentionalBoundaryManifestTarget::RepositoryPath { repository_path } => {
            vec![repository_path.as_str()]
        }
        IntentionalBoundaryManifestTarget::RepositoryPaths { repository_paths } => {
            repository_paths.iter().map(String::as_str).collect()
        }
        IntentionalBoundaryManifestTarget::PythonObject { .. } => {
            return Ok(binding_unresolved(
                UnresolvedReason::UnsupportedSelector,
                "project-model target selector is not supported by this provider".to_string(),
            ));
        }
        IntentionalBoundaryManifestTarget::PackageScript { .. } => {
            return Ok(binding_unresolved(
                UnresolvedReason::UnsupportedSelector,
                "package-script selectors do not belong to command-backed project models"
                    .to_string(),
            ));
        }
        IntentionalBoundaryManifestTarget::GoGeneratePackage { .. } => {
            return Ok(binding_unresolved(
                UnresolvedReason::UnsupportedSelector,
                "Go generator selectors do not belong to project-model boundaries".to_string(),
            ));
        }
    };
    let mut files = Vec::with_capacity(repository_paths.len());
    for repository_path in repository_paths {
        let Some(file) = source_census
            .source_files
            .iter()
            .find(|file| file.repository_path == repository_path)
        else {
            return Ok(binding_unresolved(
                UnresolvedReason::TargetNotInSourceCensus,
                format!("project-model target is not a supported source file: {repository_path}"),
            ));
        };
        files.push(file);
    }
    match declaration_kind {
        IntentionalBoundaryManifestDeclarationKind::PublishedModule => {
            let methods = files
                .iter()
                .flat_map(|file| file.methods.iter())
                .filter(|method| method.is_exported)
                .collect::<Vec<_>>();
            if methods.is_empty() {
                return Ok(Outcome::NonMethodBoundary {
                    reason: NonMethodReason::ModuleHasNoExportedMethods,
                });
            }
            bind_methods(semantic_methods, &methods)
        }
        IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint => {
            let methods = files
                .iter()
                .flat_map(|file| file.methods.iter())
                .filter(|method| method.symbol_name == "main")
                .collect::<Vec<_>>();
            match methods.as_slice() {
                [] => Ok(Outcome::NonMethodBoundary {
                    reason: NonMethodReason::WholeScriptEntrypoint,
                }),
                [_] => bind_methods(semantic_methods, &methods),
                _ => Ok(binding_unresolved(
                    UnresolvedReason::AmbiguousSourceTarget,
                    "project-model runtime target has repeated main methods".to_string(),
                )),
            }
        }
        IntentionalBoundaryManifestDeclarationKind::BuildScript => {
            Ok(Outcome::AwaitingGeneratorReplay)
        }
        IntentionalBoundaryManifestDeclarationKind::PackageScript => {
            Ok(Outcome::AwaitingGeneratorReplay)
        }
        IntentionalBoundaryManifestDeclarationKind::GeneratorCommand => {
            Ok(Outcome::AwaitingGeneratorReplay)
        }
    }
}

fn bind_methods(
    semantic_methods: &BTreeMap<&str, &IntentionalBoundarySemanticMethod>,
    methods: &[&IntentionalBoundaryMethodCensusEntry],
) -> Result<Outcome, String> {
    let mut subjects = Vec::with_capacity(methods.len());
    for method in methods {
        let semantic_method = semantic_methods
            .get(method.parser_unit_id.as_str())
            .ok_or_else(|| {
                format!(
                    "project-model binding omitted semantic method {}",
                    method.parser_unit_id
                )
            })?;
        let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } =
            &semantic_method.status
        else {
            return Ok(binding_unresolved(
                UnresolvedReason::CompilerMethodUnavailable,
                format!(
                    "project-model target method has no compiler identity: {}",
                    method.parser_unit_id
                ),
            ));
        };
        subjects.push(IntentionalBoundaryProjectModelBoundSubject {
            parser_unit_id: method.parser_unit_id.clone(),
            subject_symbol_id: symbol.symbol_id.clone(),
        });
    }
    subjects.sort();
    Ok(Outcome::Bound { subjects })
}

fn binding_unresolved(reason: UnresolvedReason, detail: String) -> Outcome {
    Outcome::BindingUnresolved { reason, detail }
}

fn finish_binding_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    bindings: Vec<IntentionalBoundaryProjectModelBinding>,
) -> Result<IntentionalBoundaryProjectModelBindingCensus, String> {
    let count = |predicate: fn(&Outcome) -> bool| {
        bindings
            .iter()
            .filter(|binding| predicate(&binding.outcome))
            .count()
    };
    let mut census = IntentionalBoundaryProjectModelBindingCensus {
        schema_version: INTENTIONAL_BOUNDARY_PROJECT_MODEL_BINDING_CENSUS_SCHEMA_VERSION,
        binding_contract: BINDING_CONTRACT.to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        project_model_census_sha256: project_model_census.project_model_census_sha256.clone(),
        bound_target_count: count(|outcome| matches!(outcome, Outcome::Bound { .. })),
        non_method_target_count: count(|outcome| {
            matches!(outcome, Outcome::NonMethodBoundary { .. })
        }),
        awaiting_generator_replay_count: count(|outcome| {
            matches!(outcome, Outcome::AwaitingGeneratorReplay)
        }),
        non_boundary_target_count: count(|outcome| matches!(outcome, Outcome::NonBoundary { .. })),
        upstream_unresolved_target_count: count(|outcome| {
            matches!(outcome, Outcome::UpstreamUnresolved { .. })
        }),
        binding_unresolved_target_count: count(|outcome| {
            matches!(outcome, Outcome::BindingUnresolved { .. })
        }),
        bindings,
        binding_census_sha256: String::new(),
    };
    census.binding_census_sha256 = compute_binding_census_sha256(&census)?;
    Ok(census)
}

fn compute_binding_census_sha256(
    census: &IntentionalBoundaryProjectModelBindingCensus,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.binding_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.project_model_census_sha256,
        &census.bindings,
        census.bound_target_count,
        census.non_method_target_count,
        census.awaiting_generator_replay_count,
        census.non_boundary_target_count,
        census.upstream_unresolved_target_count,
        census.binding_unresolved_target_count,
    ))
    .map_err(|error| format!("failed to commit project-model bindings: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
