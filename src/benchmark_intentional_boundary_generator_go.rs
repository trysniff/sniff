use super::GeneratorCommand;
use crate::benchmark::release::{
    IntentionalBoundaryGoGenerateDirective, IntentionalBoundaryManifestDeclaration,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryManifestTarget, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryProjectModelExecution, IntentionalBoundaryProjectModelProvider as Provider,
    IntentionalBoundaryProjectModelTarget, IntentionalBoundaryProjectModelTargetStatus,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn go_generator_command(
    project_models: &IntentionalBoundaryProjectModelCensus,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    if declaration.provider != IntentionalBoundaryManifestProvider::GoGenerateSource
        || declaration.declaration_kind
            != IntentionalBoundaryManifestDeclarationKind::GeneratorCommand
    {
        return None;
    }
    let IntentionalBoundaryManifestTarget::GoGeneratePackage {
        module_manifest_repository_path: Some(module_manifest),
        package_repository_path,
        directives,
    } = &declaration.target
    else {
        return None;
    };
    let module_directory = module_directory(module_manifest)?;
    if !safe_directory(package_repository_path)
        || !is_same_or_descendant(package_repository_path, module_directory)
        || directives.is_empty()
        || directives.windows(2).any(|pair| pair[0] >= pair[1])
        || declaration.declaration_location != directives[0].location
    {
        return None;
    }
    let directive_paths = directive_source_paths(package_repository_path, directives)?;
    if !directives_use_only_go(directives) {
        return None;
    }
    let (target, execution) = exact_project_model_owner(
        project_models,
        module_manifest,
        package_repository_path,
        &directive_paths,
    )?;
    if target.execution_id != execution.execution_id {
        return None;
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
    execution_command.extend(
        directive_paths
            .iter()
            .map(|path| source_basename(package_repository_path, path))
            .collect::<Option<Vec<_>>>()?,
    );
    Some(GeneratorCommand {
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
) -> Option<(
    &'a IntentionalBoundaryProjectModelTarget,
    &'a IntentionalBoundaryProjectModelExecution,
)> {
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
    let target = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    let mut executions = census.executions.iter().filter(|execution| {
        execution.execution_id == target.execution_id
            && execution.provider == Provider::GoList
            && execution.invocation_anchor_repository_path == module_manifest
            && execution.covered_manifest_repository_paths == [module_manifest]
    });
    let execution = executions.next()?;
    (executions.next().is_none()).then_some((target, execution))
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

fn directives_use_only_go(directives: &[IntentionalBoundaryGoGenerateDirective]) -> bool {
    let mut aliases = BTreeMap::<String, String>::new();
    let mut current_file = None::<&str>;
    let mut executable_directive = false;
    for directive in directives {
        let file = directive.location.repository_path.as_str();
        if current_file != Some(file) {
            aliases.clear();
            current_file = Some(file);
        }
        let Some(body) = directive
            .source_text
            .strip_prefix("//go:generate ")
            .or_else(|| directive.source_text.strip_prefix("//go:generate\t"))
        else {
            return false;
        };
        let words = body.split_ascii_whitespace().take(3).collect::<Vec<_>>();
        let Some(first) = words.first().copied() else {
            return false;
        };
        if first == "-command" {
            let [_, alias, executable] = words.as_slice() else {
                return false;
            };
            if !plain_command_word(alias) || !plain_command_word(executable) {
                return false;
            }
            aliases.insert((*alias).to_string(), (*executable).to_string());
            continue;
        }
        if !plain_command_word(first) {
            return false;
        }
        let effective = aliases.get(first).map_or(first, String::as_str);
        if effective != "go" {
            return false;
        }
        executable_directive = true;
    }
    executable_directive
}

fn plain_command_word(word: &str) -> bool {
    !word.is_empty() && !word.contains(['"', '\'', '`', '$', '\\', '\0']) && !word.contains('/')
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
