use super::go;
use super::node::{self, GeneratorCommand};
use super::python;
use crate::benchmark::release::{
    IntentionalBoundaryGeneratorUnresolvedReason, IntentionalBoundaryManifestBindingCensus,
    IntentionalBoundaryManifestDeclaration, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestProvider, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus,
};
use std::collections::BTreeMap;

pub(super) enum GeneratorCommandPlan {
    Planned(GeneratorCommand),
    Unresolved {
        reason: IntentionalBoundaryGeneratorUnresolvedReason,
        detail: String,
    },
}

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

#[cfg(test)]
pub(in crate::benchmark::release) fn generator_command_with_context(
    inventory: &IntentionalBoundaryRepositoryInventory,
    declarations: &[IntentionalBoundaryManifestDeclaration],
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    match generator_command_plan_with_context(
        inventory,
        declarations,
        semantic_census,
        project_model_census,
        binding_census,
        declaration,
    ) {
        GeneratorCommandPlan::Planned(command) => Some(command),
        GeneratorCommandPlan::Unresolved { .. } => None,
    }
}

pub(super) fn generator_command_plan_with_context(
    inventory: &IntentionalBoundaryRepositoryInventory,
    declarations: &[IntentionalBoundaryManifestDeclaration],
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> GeneratorCommandPlan {
    if let Some(command) = generator_command(inventory, declarations, declaration).or_else(|| {
        python::python_generator_command(inventory, semantic_census, binding_census, declaration)
    }) {
        return GeneratorCommandPlan::Planned(command);
    }
    match go::go_generator_command_plan(project_model_census, declaration) {
        go::GoGeneratorCommandPlan::Planned(command) => GeneratorCommandPlan::Planned(command),
        go::GoGeneratorCommandPlan::Unresolved { reason, detail } => {
            GeneratorCommandPlan::Unresolved { reason, detail }
        }
        go::GoGeneratorCommandPlan::NotApplicable => GeneratorCommandPlan::Unresolved {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::UnsupportedConfiguration,
            detail: "generator declaration has no supported locked command".to_string(),
        },
    }
}
