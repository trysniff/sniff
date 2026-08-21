use super::go;
use super::node::{self, GeneratorCommand};
use super::python;
use crate::benchmark::release::{
    IntentionalBoundaryManifestBindingCensus, IntentionalBoundaryManifestDeclaration,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryManifestTarget, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
};
use std::collections::BTreeMap;

pub(in crate::benchmark::release) fn cargo_generator_command(
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<Vec<String>> {
    if declaration.provider != IntentionalBoundaryManifestProvider::CargoManifest {
        return None;
    }
    let IntentionalBoundaryManifestTarget::RepositoryPath { .. } = &declaration.target else {
        return None;
    };
    Some(vec![
        "cargo".to_string(),
        "check".to_string(),
        "--offline".to_string(),
        "--locked".to_string(),
        "--manifest-path".to_string(),
        declaration.manifest_repository_path.clone(),
    ])
}

pub(in crate::benchmark::release) fn is_generator_declaration(
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> bool {
    matches!(
        declaration.declaration_kind,
        IntentionalBoundaryManifestDeclarationKind::BuildScript
            | IntentionalBoundaryManifestDeclarationKind::PackageScript
            | IntentionalBoundaryManifestDeclarationKind::GeneratorCommand
    ) || (declaration.provider == IntentionalBoundaryManifestProvider::PythonProjectManifest
        && declaration.declaration_kind
            == IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint)
}

pub(super) fn generator_command(
    inventory: &IntentionalBoundaryRepositoryInventory,
    declarations: &[IntentionalBoundaryManifestDeclaration],
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    if let Some(execution) = cargo_generator_command(declaration) {
        return Some(GeneratorCommand {
            preparation: None,
            preparation_environment: BTreeMap::new(),
            execution,
            execution_environment: BTreeMap::new(),
            cleanup_paths: Vec::new(),
        });
    }
    node::node_generator_command(inventory, declarations, declaration)
}

pub(in crate::benchmark::release) fn generator_command_with_context(
    inventory: &IntentionalBoundaryRepositoryInventory,
    declarations: &[IntentionalBoundaryManifestDeclaration],
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    generator_command(inventory, declarations, declaration)
        .or_else(|| {
            python::python_generator_command(
                inventory,
                semantic_census,
                binding_census,
                declaration,
            )
        })
        .or_else(|| go::go_generator_command(project_model_census, declaration))
}
