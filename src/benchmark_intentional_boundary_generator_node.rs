use super::manifest_directory;
use crate::benchmark::release::{
    BoundaryGitEntryKind, IntentionalBoundaryManifestDeclaration,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryManifestTarget, IntentionalBoundaryRepositoryInventory,
};
use std::collections::BTreeMap;

#[derive(Clone)]
pub(crate) struct GeneratorCommand {
    pub(crate) preparation: Option<Vec<String>>,
    pub(crate) preparation_environment: BTreeMap<String, String>,
    pub(crate) execution: Vec<String>,
    pub(crate) execution_environment: BTreeMap<String, String>,
    pub(crate) cleanup_paths: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeManager {
    Npm,
    Pnpm,
    YarnClassic,
    YarnModern,
    Bun,
}

pub(super) fn node_generator_command(
    inventory: &IntentionalBoundaryRepositoryInventory,
    declarations: &[IntentionalBoundaryManifestDeclaration],
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    if declaration.provider != IntentionalBoundaryManifestProvider::NodePackageManifest
        || declaration.declaration_kind != IntentionalBoundaryManifestDeclarationKind::PackageScript
    {
        return None;
    }
    let IntentionalBoundaryManifestTarget::PackageScript {
        script_name,
        package_manager,
        ..
    } = &declaration.target
    else {
        return None;
    };
    let directory = manifest_directory(declaration);
    let manager = locked_node_manager(inventory, directory, package_manager.as_deref())?;
    if manager_runs_implicit_hooks(manager)
        && has_sibling_hook(declarations, declaration, script_name)
    {
        return None;
    }
    let path = |name: &str| scoped_path(directory, name);
    let prefix = if directory.is_empty() { "." } else { directory };
    let cleanup_paths = node_cleanup_paths(inventory, directory, manager);
    let (preparation, execution) = match manager {
        NodeManager::Npm => (
            vec![
                "npm",
                "--prefix",
                prefix,
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
            vec![
                "npm",
                "--prefix",
                prefix,
                "run-script",
                "--ignore-scripts",
                script_name,
            ],
        ),
        NodeManager::Pnpm => (
            vec![
                "pnpm",
                "--dir",
                prefix,
                "install",
                "--frozen-lockfile",
                "--ignore-scripts",
                "--reporter=silent",
            ],
            vec!["pnpm", "--dir", prefix, "run", script_name],
        ),
        NodeManager::YarnClassic => (
            vec![
                "yarn",
                "--cwd",
                prefix,
                "install",
                "--frozen-lockfile",
                "--ignore-scripts",
                "--non-interactive",
            ],
            vec!["yarn", "--cwd", prefix, "run", script_name],
        ),
        NodeManager::YarnModern => (
            vec![
                "yarn",
                "--cwd",
                prefix,
                "install",
                "--immutable",
                "--mode=skip-build",
            ],
            vec!["yarn", "--cwd", prefix, "run", script_name],
        ),
        NodeManager::Bun => (
            vec![
                "bun",
                "install",
                "--cwd",
                prefix,
                "--frozen-lockfile",
                "--ignore-scripts",
            ],
            vec!["bun", "--cwd", prefix, "run", script_name],
        ),
    };
    Some(GeneratorCommand {
        preparation: Some(preparation.into_iter().map(str::to_string).collect()),
        preparation_environment: BTreeMap::new(),
        execution: execution.into_iter().map(str::to_string).collect(),
        execution_environment: BTreeMap::new(),
        cleanup_paths: cleanup_paths.into_iter().map(path).collect(),
    })
}

fn locked_node_manager(
    inventory: &IntentionalBoundaryRepositoryInventory,
    directory: &str,
    package_manager: Option<&str>,
) -> Option<NodeManager> {
    let regular = |name: &str| {
        let path = scoped_path(directory, name);
        inventory.tracked_entries.iter().any(|entry| {
            entry.repository_path == path && entry.kind == BoundaryGitEntryKind::RegularBlob
        })
    };
    let npm = regular("npm-shrinkwrap.json") || regular("package-lock.json");
    let pnpm = regular("pnpm-lock.yaml");
    let yarn = regular("yarn.lock");
    let bun_lock_count = ["bun.lock", "bun.lockb"]
        .iter()
        .filter(|name| regular(name))
        .count();
    if [npm, pnpm, yarn, bun_lock_count == 1]
        .into_iter()
        .filter(|present| *present)
        .count()
        != 1
        || bun_lock_count > 1
    {
        return None;
    }
    let locked = if npm {
        NodeManager::Npm
    } else if pnpm {
        NodeManager::Pnpm
    } else if yarn {
        yarn_manager(package_manager?)?
    } else {
        NodeManager::Bun
    };
    match package_manager {
        Some(spec) if package_manager_matches(spec, locked) => Some(locked),
        Some(_) => None,
        None => Some(locked),
    }
}

fn yarn_manager(spec: &str) -> Option<NodeManager> {
    let (name, version) = split_package_manager(spec)?;
    if name != "yarn" {
        return None;
    }
    let major = version.split('.').next()?.parse::<u64>().ok()?;
    Some(if major == 1 {
        NodeManager::YarnClassic
    } else if major > 1 {
        NodeManager::YarnModern
    } else {
        return None;
    })
}

fn package_manager_matches(spec: &str, manager: NodeManager) -> bool {
    let Some((name, version)) = split_package_manager(spec) else {
        return false;
    };
    if !is_exact_manager_version(version) {
        return false;
    }
    match manager {
        NodeManager::Npm => name == "npm",
        NodeManager::Pnpm => name == "pnpm",
        NodeManager::YarnClassic | NodeManager::YarnModern => yarn_manager(spec) == Some(manager),
        NodeManager::Bun => name == "bun",
    }
}

fn split_package_manager(spec: &str) -> Option<(&str, &str)> {
    let (name, version) = spec.split_once('@')?;
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

fn is_exact_manager_version(version: &str) -> bool {
    if version.contains(char::is_whitespace) {
        return false;
    }
    let (without_integrity, integrity_valid) = version
        .split_once('+')
        .map_or((version, true), |(value, integrity)| {
            (value, !integrity.is_empty())
        });
    let (core, prerelease_valid) = without_integrity
        .split_once('-')
        .map_or((without_integrity, true), |(value, prerelease)| {
            (value, !prerelease.is_empty())
        });
    let parts = core.split('.').collect::<Vec<_>>();
    integrity_valid
        && prerelease_valid
        && parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn manager_runs_implicit_hooks(manager: NodeManager) -> bool {
    manager != NodeManager::Npm
}

fn has_sibling_hook(
    declarations: &[IntentionalBoundaryManifestDeclaration],
    selected: &IntentionalBoundaryManifestDeclaration,
    script_name: &str,
) -> bool {
    let pre = format!("pre{script_name}");
    let post = format!("post{script_name}");
    declarations.iter().any(|declaration| {
        declaration.manifest_repository_path == selected.manifest_repository_path
            && matches!(
                &declaration.target,
                IntentionalBoundaryManifestTarget::PackageScript { script_name, .. }
                    if script_name == &pre || script_name == &post
            )
    })
}

fn node_cleanup_paths(
    inventory: &IntentionalBoundaryRepositoryInventory,
    directory: &str,
    manager: NodeManager,
) -> Vec<&'static str> {
    let candidates = if manager == NodeManager::YarnModern {
        &[
            "node_modules",
            ".pnp.cjs",
            ".pnp.loader.mjs",
            ".yarn/install-state.gz",
            ".yarn/unplugged",
        ][..]
    } else {
        &["node_modules"][..]
    };
    candidates
        .iter()
        .copied()
        .filter(|name| {
            let path = scoped_path(directory, name);
            !inventory
                .tracked_entries
                .iter()
                .any(|entry| entry.repository_path == path)
        })
        .collect()
}

fn scoped_path(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_string()
    } else {
        format!("{directory}/{name}")
    }
}

pub(super) fn generator_candidate_key(
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> (u8, &str) {
    let priority = match &declaration.target {
        IntentionalBoundaryManifestTarget::PackageScript {
            script_name,
            command,
            ..
        } if generator_like(script_name) || generator_like(command) => 0,
        IntentionalBoundaryManifestTarget::PythonObject { qualname, .. }
            if qualname.iter().any(|part| generator_like(part)) =>
        {
            0
        }
        IntentionalBoundaryManifestTarget::RepositoryPath { .. } => 1,
        IntentionalBoundaryManifestTarget::GoGeneratePackage { .. } => 0,
        IntentionalBoundaryManifestTarget::PackageScript { .. } => 2,
        _ => 3,
    };
    (priority, declaration.declaration_id.as_str())
}

fn generator_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["generate", "generated", "codegen", "protoc", "openapi"]
        .iter()
        .any(|token| lower.contains(token))
}
