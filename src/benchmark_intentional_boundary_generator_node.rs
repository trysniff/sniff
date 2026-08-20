use super::{cargo_generator_command, manifest_directory};
use crate::benchmark::release::{
    BoundaryGitEntryKind, IntentionalBoundaryManifestDeclaration,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryManifestTarget, IntentionalBoundaryRepositoryInventory,
};

#[derive(Clone)]
pub(crate) struct GeneratorCommand {
    pub(crate) preparation: Option<Vec<String>>,
    pub(crate) execution: Vec<String>,
    pub(crate) cleanup_paths: Vec<String>,
}

pub(crate) fn generator_command(
    inventory: &IntentionalBoundaryRepositoryInventory,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    if let Some(execution) = cargo_generator_command(declaration) {
        return Some(GeneratorCommand {
            preparation: None,
            execution,
            cleanup_paths: Vec::new(),
        });
    }
    npm_generator_command(inventory, declaration)
}

fn npm_generator_command(
    inventory: &IntentionalBoundaryRepositoryInventory,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    if declaration.provider != IntentionalBoundaryManifestProvider::NodePackageManifest
        || declaration.declaration_kind != IntentionalBoundaryManifestDeclarationKind::PackageScript
    {
        return None;
    }
    let IntentionalBoundaryManifestTarget::PackageScript { script_name, .. } = &declaration.target
    else {
        return None;
    };
    let directory = manifest_directory(declaration);
    let path = |name: &str| {
        if directory.is_empty() {
            name.to_string()
        } else {
            format!("{directory}/{name}")
        }
    };
    let has_npm_lock = ["npm-shrinkwrap.json", "package-lock.json"]
        .iter()
        .any(|name| {
            inventory.tracked_entries.iter().any(|entry| {
                entry.repository_path == path(name)
                    && entry.kind == BoundaryGitEntryKind::RegularBlob
            })
        });
    if !has_npm_lock {
        return None;
    }
    let prefix = if directory.is_empty() { "." } else { directory };
    Some(GeneratorCommand {
        preparation: Some(vec![
            "npm".to_string(),
            "--prefix".to_string(),
            prefix.to_string(),
            "ci".to_string(),
            "--ignore-scripts".to_string(),
            "--no-audit".to_string(),
            "--no-fund".to_string(),
        ]),
        execution: vec![
            "npm".to_string(),
            "--prefix".to_string(),
            prefix.to_string(),
            "run-script".to_string(),
            "--ignore-scripts".to_string(),
            script_name.clone(),
        ],
        cleanup_paths: vec![path("node_modules")],
    })
}

pub(super) fn generator_candidate_key(
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> (u8, &str) {
    let priority = match &declaration.target {
        IntentionalBoundaryManifestTarget::PackageScript {
            script_name,
            command,
        } if generator_like(script_name) || generator_like(command) => 0,
        IntentionalBoundaryManifestTarget::RepositoryPath { .. } => 1,
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
