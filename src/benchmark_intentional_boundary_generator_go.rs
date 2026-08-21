use super::GeneratorCommand;
use crate::benchmark::release::{
    IntentionalBoundaryGeneratorUnresolvedReason, IntentionalBoundaryGoGenerateDirective,
    IntentionalBoundaryManifestDeclaration, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestProvider, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelProvider as Provider, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryProjectModelTargetStatus,
};
use std::collections::{BTreeMap, BTreeSet};

#[path = "benchmark_intentional_boundary_generator_go_directive.rs"]
mod directive;
use directive::directives_use_only_go;

pub(super) enum GoGeneratorCommandPlan {
    NotApplicable,
    Planned(GeneratorCommand),
    Unresolved {
        reason: IntentionalBoundaryGeneratorUnresolvedReason,
        detail: String,
    },
}

enum OwnerError {
    Missing,
    Ambiguous,
}

pub(super) fn go_generator_command(
    project_models: &IntentionalBoundaryProjectModelCensus,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    match go_generator_command_plan(project_models, declaration) {
        GoGeneratorCommandPlan::Planned(command) => Some(command),
        GoGeneratorCommandPlan::NotApplicable | GoGeneratorCommandPlan::Unresolved { .. } => None,
    }
}

pub(super) fn go_generator_command_plan(
    project_models: &IntentionalBoundaryProjectModelCensus,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> GoGeneratorCommandPlan {
    if declaration.provider != IntentionalBoundaryManifestProvider::GoGenerateSource
        || declaration.declaration_kind
            != IntentionalBoundaryManifestDeclarationKind::GeneratorCommand
    {
        return GoGeneratorCommandPlan::NotApplicable;
    }
    let IntentionalBoundaryManifestTarget::GoGeneratePackage {
        module_manifest_repository_path,
        package_repository_path,
        directives,
    } = &declaration.target
    else {
        return unsupported("Go generator declaration has an invalid target shape");
    };
    let Some(module_manifest) = module_manifest_repository_path else {
        return unresolved(
            IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration,
            "Go generator package has no enclosing tracked go.mod",
        );
    };
    let Some(module_directory) = module_directory(module_manifest) else {
        return unsupported("Go generator module path is not safely repository-relative");
    };
    if !safe_directory(package_repository_path)
        || !is_same_or_descendant(package_repository_path, module_directory)
        || directives.is_empty()
        || directives.windows(2).any(|pair| pair[0] >= pair[1])
        || declaration.declaration_location != directives[0].location
    {
        return unsupported("Go generator declaration is malformed or outside its module");
    }
    let Some(directive_paths) = directive_source_paths(package_repository_path, directives) else {
        return unsupported("Go generator directives are not exact package source locations");
    };
    if !directives_use_only_go(directives) {
        return unsupported(
            "Go generator directives require an unsupported executable or malformed alias",
        );
    }
    let (target, execution) = match exact_project_model_owner(
        project_models,
        module_manifest,
        package_repository_path,
        &directive_paths,
    ) {
        Ok(owner) => owner,
        Err(OwnerError::Missing) => {
            return unresolved(
                IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration,
                "Go generator package has no exact compiler-owned go list target",
            );
        }
        Err(OwnerError::Ambiguous) => {
            return unresolved(
                IntentionalBoundaryGeneratorUnresolvedReason::AmbiguousConfiguration,
                "Go generator package has multiple compiler-owned go list targets",
            );
        }
    };
    if target.execution_id != execution.execution_id {
        return unresolved(
            IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration,
            "Go generator package lost its compiler execution identity",
        );
    }

    let module_argument = path_argument(module_directory);
    let package_argument = path_argument(package_repository_path);
    let mut execution_command = vec![
        "go".to_string(),
        "-C".to_string(),
        package_argument,
        "generate".to_string(),
        "-mod=readonly".to_string(),
        "-buildvcs=false".to_string(),
    ];
    let Some(source_names) = directive_paths
        .iter()
        .map(|path| source_basename(package_repository_path, path))
        .collect::<Option<Vec<_>>>()
    else {
        return unsupported("Go generator source path is not package-relative");
    };
    execution_command.extend(source_names);
    GoGeneratorCommandPlan::Planned(GeneratorCommand {
        preparation: Some(vec![
            "go".to_string(),
            "-C".to_string(),
            module_argument,
            "mod".to_string(),
            "download".to_string(),
            "all".to_string(),
        ]),
        preparation_environment: go_environment(false),
        execution: execution_command,
        execution_environment: go_environment(true),
        cleanup_paths: Vec::new(),
    })
}

fn exact_project_model_owner<'a>(
    census: &'a IntentionalBoundaryProjectModelCensus,
    module_manifest: &str,
    package_repository_path: &str,
    directive_paths: &BTreeSet<String>,
) -> Result<
    (
        &'a IntentionalBoundaryProjectModelTarget,
        &'a IntentionalBoundaryProjectModelExecution,
    ),
    OwnerError,
> {
    let mut matches = census.targets.iter().filter(|target| {
        target.provider == Provider::GoList
            && target.manifest_repository_path == module_manifest
            && matches!(
                target.target_status,
                IntentionalBoundaryProjectModelTargetStatus::Boundary { .. }
            )
            && target
                .source_repository_paths
                .iter()
                .all(|path| parent_path(path) == package_repository_path)
            && target
                .source_repository_paths
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == target.source_repository_paths.len()
            && directive_paths
                .iter()
                .all(|path| target.source_repository_paths.contains(path))
    });
    let target = matches.next().ok_or(OwnerError::Missing)?;
    if matches.next().is_some() {
        return Err(OwnerError::Ambiguous);
    }
    let mut executions = census.executions.iter().filter(|execution| {
        execution.execution_id == target.execution_id
            && execution.provider == Provider::GoList
            && execution.invocation_anchor_repository_path == module_manifest
            && execution.covered_manifest_repository_paths == [module_manifest]
    });
    let execution = executions.next().ok_or(OwnerError::Missing)?;
    if executions.next().is_some() {
        return Err(OwnerError::Ambiguous);
    }
    Ok((target, execution))
}

fn unsupported(detail: impl Into<String>) -> GoGeneratorCommandPlan {
    unresolved(
        IntentionalBoundaryGeneratorUnresolvedReason::UnsupportedConfiguration,
        detail,
    )
}

fn unresolved(
    reason: IntentionalBoundaryGeneratorUnresolvedReason,
    detail: impl Into<String>,
) -> GoGeneratorCommandPlan {
    GoGeneratorCommandPlan::Unresolved {
        reason,
        detail: detail.into(),
    }
}

fn directive_source_paths(
    package_repository_path: &str,
    directives: &[IntentionalBoundaryGoGenerateDirective],
) -> Option<BTreeSet<String>> {
    directives
        .iter()
        .try_fold(BTreeSet::new(), |mut paths, directive| {
            let path = &directive.location.repository_path;
            if parent_path(path) != package_repository_path
                || !path.ends_with(".go")
                || directive.location.start_character_zero_based != 0
                || directive.location.start_line_zero_based
                    != directive.location.end_line_zero_based
                || directive.location.end_character_zero_based != directive.source_text.len() as u32
                || directive.source_text.contains(['\r', '\n'])
            {
                return None;
            }
            paths.insert(path.clone());
            Some(paths)
        })
}

fn module_directory(manifest: &str) -> Option<&str> {
    (manifest == "go.mod").then_some("").or_else(|| {
        manifest
            .strip_suffix("/go.mod")
            .filter(|path| safe_directory(path))
    })
}

fn safe_directory(path: &str) -> bool {
    path.is_empty()
        || (!path.contains('\\')
            && !path.starts_with('/')
            && !path.ends_with('/')
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."))
}

fn is_same_or_descendant(path: &str, directory: &str) -> bool {
    directory.is_empty()
        || path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn path_argument(path: &str) -> String {
    if path.is_empty() {
        ".".to_string()
    } else {
        path.to_string()
    }
}

fn source_basename(package_repository_path: &str, path: &str) -> Option<String> {
    let name = if package_repository_path.is_empty() {
        path
    } else {
        path.strip_prefix(&format!("{package_repository_path}/"))?
    };
    (!name.is_empty() && !name.contains('/') && name.ends_with(".go")).then(|| name.to_string())
}

fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn go_environment(offline: bool) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        ("GO111MODULE".to_string(), "on".to_string()),
        ("GOENV".to_string(), "off".to_string()),
        ("GOTOOLCHAIN".to_string(), "local".to_string()),
        ("GOWORK".to_string(), "off".to_string()),
    ]);
    if offline {
        environment.extend([
            (
                "GOFLAGS".to_string(),
                "-mod=readonly -buildvcs=false".to_string(),
            ),
            ("GOPROXY".to_string(), "off".to_string()),
            ("GOSUMDB".to_string(), "off".to_string()),
        ]);
    }
    environment
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_generator_go_tests.rs"]
mod tests;
