use super::intentional_boundary_manifest::validate_manifest_census_commitment;
use super::{
    INTENTIONAL_BOUNDARY_MANIFEST_BINDING_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryManifestBinding, IntentionalBoundaryManifestBindingCensus,
    IntentionalBoundaryManifestBindingOutcome as Outcome,
    IntentionalBoundaryManifestBindingUnresolvedReason as UnresolvedReason,
    IntentionalBoundaryManifestBoundSubject, IntentionalBoundaryManifestCensus,
    IntentionalBoundaryManifestDeclaration, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestNonMethodReason as NonMethodReason,
    IntentionalBoundaryManifestProvider, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySourceCensus, validate_intentional_boundary_semantic_census,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const BINDING_CONTRACT: &str = "sniffbench-intentional-boundary-manifest-bindings-v2";

pub fn bind_intentional_boundary_manifests(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
) -> Result<IntentionalBoundaryManifestBindingCensus, String> {
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    validate_manifest_census_commitment(&source_census.inventory_sha256, manifest_census)?;
    if manifest_census.repository != source_census.repository
        || manifest_census.revision != source_census.revision
    {
        return Err("intentional-boundary manifest binding identity changed".to_string());
    }
    let semantic_methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut bindings = Vec::with_capacity(manifest_census.declarations.len());
    for declaration in &manifest_census.declarations {
        let outcome = bind_declaration(source_census, &semantic_methods, declaration)?;
        bindings.push(IntentionalBoundaryManifestBinding {
            declaration_id: declaration.declaration_id.clone(),
            outcome,
        });
    }
    finish_binding_census(source_census, semantic_census, manifest_census, bindings)
}

pub fn validate_intentional_boundary_manifest_bindings(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
) -> Result<(), String> {
    let expected =
        bind_intentional_boundary_manifests(source_census, semantic_census, manifest_census)?;
    if binding_census != &expected {
        return Err("intentional-boundary manifest bindings changed".to_string());
    }
    Ok(())
}

fn bind_declaration(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_methods: &BTreeMap<&str, &IntentionalBoundarySemanticMethod>,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Result<Outcome, String> {
    if declaration.declaration_kind == IntentionalBoundaryManifestDeclarationKind::BuildScript {
        return Ok(Outcome::AwaitingGeneratorReplay);
    }
    match &declaration.target {
        IntentionalBoundaryManifestTarget::RepositoryPath { repository_path } => {
            bind_repository_path(
                source_census,
                semantic_methods,
                declaration,
                repository_path,
            )
        }
        IntentionalBoundaryManifestTarget::RepositoryPaths { repository_paths } => {
            bind_repository_paths(
                source_census,
                semantic_methods,
                declaration,
                repository_paths,
            )
        }
        IntentionalBoundaryManifestTarget::PythonObject { module, qualname } => bind_python_object(
            source_census,
            semantic_methods,
            declaration,
            module,
            qualname,
        ),
    }
}

fn bind_repository_path(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_methods: &BTreeMap<&str, &IntentionalBoundarySemanticMethod>,
    declaration: &IntentionalBoundaryManifestDeclaration,
    repository_path: &str,
) -> Result<Outcome, String> {
    bind_repository_paths(
        source_census,
        semantic_methods,
        declaration,
        &[repository_path.to_string()],
    )
}

fn bind_repository_paths(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_methods: &BTreeMap<&str, &IntentionalBoundarySemanticMethod>,
    declaration: &IntentionalBoundaryManifestDeclaration,
    repository_paths: &[String],
) -> Result<Outcome, String> {
    let mut files = Vec::with_capacity(repository_paths.len());
    for repository_path in repository_paths {
        let Some(file) = source_census
            .source_files
            .iter()
            .find(|file| file.repository_path == *repository_path)
        else {
            return Ok(unresolved(
                UnresolvedReason::TargetNotInSourceCensus,
                format!("manifest target is not a supported source file: {repository_path}"),
            ));
        };
        files.push(file);
    }
    match declaration.declaration_kind {
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
        IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint
            if declaration.provider == IntentionalBoundaryManifestProvider::CargoManifest
                && files.iter().all(|file| file.language == "rust") =>
        {
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
                _ => Ok(unresolved(
                    UnresolvedReason::AmbiguousSourceTarget,
                    "Cargo binary target has repeated main methods".to_string(),
                )),
            }
        }
        IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint => {
            Ok(Outcome::NonMethodBoundary {
                reason: NonMethodReason::WholeScriptEntrypoint,
            })
        }
        IntentionalBoundaryManifestDeclarationKind::BuildScript => {
            Ok(Outcome::AwaitingGeneratorReplay)
        }
    }
}

fn bind_python_object(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_methods: &BTreeMap<&str, &IntentionalBoundarySemanticMethod>,
    declaration: &IntentionalBoundaryManifestDeclaration,
    module: &[String],
    qualname: &[String],
) -> Result<Outcome, String> {
    if declaration.provider != IntentionalBoundaryManifestProvider::PythonProjectManifest
        || declaration.declaration_kind
            != IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint
    {
        return Err("intentional-boundary manifest binding has incompatible selector".to_string());
    }
    let directory = declaration
        .manifest_repository_path
        .rsplit_once('/')
        .map(|(directory, _)| directory);
    let module_path = module.join("/");
    let relative_candidates = [
        format!("{module_path}.py"),
        format!("{module_path}/__init__.py"),
    ];
    let candidate_paths = relative_candidates.map(|path| match directory {
        Some(directory) => format!("{directory}/{path}"),
        None => path,
    });
    let files = source_census
        .source_files
        .iter()
        .filter(|file| candidate_paths.contains(&file.repository_path))
        .collect::<Vec<_>>();
    let [file] = files.as_slice() else {
        return Ok(if files.is_empty() {
            unresolved(
                UnresolvedReason::TargetNotInSourceCensus,
                format!("Python module target is not in the source census: {module_path}"),
            )
        } else {
            unresolved(
                UnresolvedReason::AmbiguousSourceTarget,
                format!("Python module resolves to multiple source files: {module_path}"),
            )
        });
    };
    if qualname.is_empty() {
        return Ok(Outcome::NonMethodBoundary {
            reason: NonMethodReason::ModuleLevelPythonEntrypoint,
        });
    }
    let [name] = qualname else {
        return Ok(unresolved(
            UnresolvedReason::UnsupportedPythonQualname,
            format!(
                "nested Python entry-point selector requires compiler owner identities: {}",
                qualname.join(".")
            ),
        ));
    };
    let methods = file
        .methods
        .iter()
        .filter(|method| method.symbol_name == *name)
        .collect::<Vec<_>>();
    match methods.as_slice() {
        [] => Ok(unresolved(
            UnresolvedReason::CompilerMethodUnavailable,
            format!("Python entry-point method is absent: {name}"),
        )),
        [_] => bind_methods(semantic_methods, &methods),
        _ => Ok(unresolved(
            UnresolvedReason::AmbiguousSourceTarget,
            format!("Python entry-point method is repeated: {name}"),
        )),
    }
}

fn bind_methods(
    semantic_methods: &BTreeMap<&str, &IntentionalBoundarySemanticMethod>,
    methods: &[&IntentionalBoundaryMethodCensusEntry],
) -> Result<Outcome, String> {
    let mut subjects = Vec::with_capacity(methods.len());
    for method in methods {
        let Some(semantic_method) = semantic_methods.get(method.parser_unit_id.as_str()) else {
            return Err(format!(
                "intentional-boundary manifest binding omitted semantic method {}",
                method.parser_unit_id
            ));
        };
        let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } =
            &semantic_method.status
        else {
            return Ok(unresolved(
                UnresolvedReason::CompilerMethodUnavailable,
                format!(
                    "manifest target method has no compiler identity: {}",
                    method.parser_unit_id
                ),
            ));
        };
        subjects.push(IntentionalBoundaryManifestBoundSubject {
            parser_unit_id: method.parser_unit_id.clone(),
            subject_symbol_id: symbol.symbol_id.clone(),
        });
    }
    subjects.sort_by(|left, right| left.parser_unit_id.cmp(&right.parser_unit_id));
    Ok(Outcome::Bound { subjects })
}

fn unresolved(reason: UnresolvedReason, detail: String) -> Outcome {
    Outcome::Unresolved { reason, detail }
}

fn finish_binding_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    bindings: Vec<IntentionalBoundaryManifestBinding>,
) -> Result<IntentionalBoundaryManifestBindingCensus, String> {
    let bound_declaration_count = bindings
        .iter()
        .filter(|binding| matches!(binding.outcome, Outcome::Bound { .. }))
        .count();
    let non_method_declaration_count = bindings
        .iter()
        .filter(|binding| matches!(binding.outcome, Outcome::NonMethodBoundary { .. }))
        .count();
    let awaiting_generator_replay_count = bindings
        .iter()
        .filter(|binding| matches!(binding.outcome, Outcome::AwaitingGeneratorReplay))
        .count();
    let unresolved_declaration_count = bindings
        .iter()
        .filter(|binding| matches!(binding.outcome, Outcome::Unresolved { .. }))
        .count();
    let mut census = IntentionalBoundaryManifestBindingCensus {
        schema_version: INTENTIONAL_BOUNDARY_MANIFEST_BINDING_CENSUS_SCHEMA_VERSION,
        binding_contract: BINDING_CONTRACT.to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        manifest_census_sha256: manifest_census.manifest_census_sha256.clone(),
        bindings,
        bound_declaration_count,
        non_method_declaration_count,
        awaiting_generator_replay_count,
        unresolved_declaration_count,
        binding_census_sha256: String::new(),
    };
    census.binding_census_sha256 = compute_binding_census_sha256(&census)?;
    Ok(census)
}

fn compute_binding_census_sha256(
    census: &IntentionalBoundaryManifestBindingCensus,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.binding_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.manifest_census_sha256,
        &census.bindings,
        census.bound_declaration_count,
        census.non_method_declaration_count,
        census.awaiting_generator_replay_count,
        census.unresolved_declaration_count,
    ))
    .map_err(|error| format!("failed to commit manifest binding census: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_manifest_binding_tests.rs"]
mod tests;
