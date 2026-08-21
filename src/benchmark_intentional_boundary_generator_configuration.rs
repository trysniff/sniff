use super::command::{GeneratorCommandPlan, generator_command_plan_with_context};
use super::gradle::{self, GradleGeneratorCommandPlan};
use super::node::generator_candidate_key;
use super::{GeneratorCommand, ReplayContext, nearest_declarations};
use crate::benchmark::release::{
    IntentionalBoundaryManifestDeclaration, IntentionalBoundaryManifestProofKind,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelProducerTask,
    IntentionalBoundaryProjectModelProofKind, IntentionalBoundaryProjectModelProvider,
    IntentionalBoundaryProjectModelTarget, IntentionalBoundarySemanticRange,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
enum GeneratorConfigurationKind<'a> {
    Manifest(&'a IntentionalBoundaryManifestDeclaration),
    Gradle {
        target: &'a IntentionalBoundaryProjectModelTarget,
        task: &'a IntentionalBoundaryProjectModelProducerTask,
    },
}

#[derive(Clone)]
pub(in crate::benchmark::release) struct GeneratorConfiguration<'a> {
    id: String,
    kind: GeneratorConfigurationKind<'a>,
}

#[derive(Clone, Copy)]
pub(in crate::benchmark::release) enum GeneratorConfigurationEvidenceProof {
    Manifest(IntentionalBoundaryManifestProofKind),
    ProjectModel(IntentionalBoundaryProjectModelProofKind),
}

impl<'a> GeneratorConfiguration<'a> {
    pub(in crate::benchmark::release) fn id(&self) -> &str {
        &self.id
    }

    pub(in crate::benchmark::release) fn evidence_locations(
        &self,
    ) -> Vec<IntentionalBoundarySemanticRange> {
        match self.kind {
            GeneratorConfigurationKind::Manifest(declaration) => {
                vec![declaration.declaration_location.clone()]
            }
            GeneratorConfigurationKind::Gradle { .. } => Vec::new(),
        }
    }

    pub(in crate::benchmark::release) fn evidence_proof(
        &self,
    ) -> GeneratorConfigurationEvidenceProof {
        match self.kind {
            GeneratorConfigurationKind::Manifest(_) => {
                GeneratorConfigurationEvidenceProof::Manifest(
                    IntentionalBoundaryManifestProofKind::GeneratorConfiguration,
                )
            }
            GeneratorConfigurationKind::Gradle { .. } => {
                GeneratorConfigurationEvidenceProof::ProjectModel(
                    IntentionalBoundaryProjectModelProofKind::GeneratorConfiguration,
                )
            }
        }
    }

    pub(super) fn command_plan(&self, context: &ReplayContext<'_>) -> GeneratorCommandPlan {
        match self.kind {
            GeneratorConfigurationKind::Manifest(declaration) => {
                generator_command_plan_with_context(
                    context.inventory,
                    context.declarations,
                    context.semantic_census,
                    context.project_model_census,
                    context.binding_census,
                    declaration,
                )
            }
            GeneratorConfigurationKind::Gradle { target, task } => {
                match gradle::gradle_generator_command_plan(
                    context.inventory,
                    context.project_model_census,
                    target,
                    task,
                ) {
                    GradleGeneratorCommandPlan::Planned(command) => {
                        GeneratorCommandPlan::Planned(command)
                    }
                    GradleGeneratorCommandPlan::Unresolved { reason, detail } => {
                        GeneratorCommandPlan::Unresolved { reason, detail }
                    }
                }
            }
        }
    }

    pub(in crate::benchmark::release) fn command(
        &self,
        context: &ReplayContext<'_>,
    ) -> Option<GeneratorCommand> {
        match self.command_plan(context) {
            GeneratorCommandPlan::Planned(command) => Some(command),
            GeneratorCommandPlan::Unresolved { .. } => None,
        }
    }

    fn candidate_key(&self) -> (u8, u8, &str) {
        match self.kind {
            GeneratorConfigurationKind::Gradle { .. } => (0, 0, self.id()),
            GeneratorConfigurationKind::Manifest(declaration) => {
                let (priority, id) = generator_candidate_key(declaration);
                (1, priority, id)
            }
        }
    }

    pub(super) fn is_gradle(&self) -> bool {
        matches!(self.kind, GeneratorConfigurationKind::Gradle { .. })
    }
}

pub(super) fn has_ambiguous_exact_gradle(configurations: &[&GeneratorConfiguration<'_>]) -> bool {
    configurations.len() > 1
        && configurations
            .iter()
            .all(|configuration| configuration.is_gradle())
}

pub(in crate::benchmark::release) fn configurations<'a>(
    declarations: &'a [IntentionalBoundaryManifestDeclaration],
    project_models: &'a IntentionalBoundaryProjectModelCensus,
) -> Result<Vec<GeneratorConfiguration<'a>>, String> {
    let mut configurations = declarations
        .iter()
        .filter(|declaration| super::is_generator_declaration(declaration))
        .map(|declaration| GeneratorConfiguration {
            id: declaration.declaration_id.clone(),
            kind: GeneratorConfigurationKind::Manifest(declaration),
        })
        .collect::<Vec<_>>();
    for target in &project_models.targets {
        if target.provider != IntentionalBoundaryProjectModelProvider::GradleToolingApi {
            continue;
        }
        for task in &target.producer_tasks {
            configurations.push(GeneratorConfiguration {
                id: gradle::configuration_id(target, task)?,
                kind: GeneratorConfigurationKind::Gradle { target, task },
            });
        }
    }
    configurations.sort_by(|left, right| left.id.cmp(&right.id));
    if configurations
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id)
    {
        return Err("generator configurations have duplicate identities".to_string());
    }
    Ok(configurations)
}

pub(super) fn candidate_configuration_ids(
    repository_path: &str,
    configurations: &[GeneratorConfiguration<'_>],
) -> Vec<String> {
    let mut exact_gradle = configurations
        .iter()
        .filter(|configuration| match configuration.kind {
            GeneratorConfigurationKind::Gradle { task, .. } => task
                .source_repository_paths
                .binary_search_by(|path| path.as_str().cmp(repository_path))
                .is_ok(),
            GeneratorConfigurationKind::Manifest(_) => false,
        })
        .map(|configuration| configuration.id.clone())
        .collect::<Vec<_>>();
    exact_gradle.sort();
    if !exact_gradle.is_empty() {
        return exact_gradle;
    }
    let declarations = configurations
        .iter()
        .filter_map(|configuration| match configuration.kind {
            GeneratorConfigurationKind::Manifest(declaration) => Some(declaration),
            GeneratorConfigurationKind::Gradle { .. } => None,
        })
        .collect::<Vec<_>>();
    nearest_declarations(repository_path, &declarations)
}

pub(in crate::benchmark::release) fn configurations_by_id<'a, 'b>(
    configurations: &'b [GeneratorConfiguration<'a>],
) -> BTreeMap<&'b str, &'b GeneratorConfiguration<'a>> {
    configurations
        .iter()
        .map(|configuration| (configuration.id(), configuration))
        .collect()
}

pub(super) fn sorted_candidates<'a, 'b>(
    ids: &[String],
    by_id: &'b BTreeMap<&str, &'b GeneratorConfiguration<'a>>,
) -> Result<Vec<&'b GeneratorConfiguration<'a>>, String> {
    let mut candidates = ids
        .iter()
        .map(|id| {
            by_id
                .get(id.as_str())
                .copied()
                .ok_or_else(|| "generator grouping invented a configuration".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort_by_key(|configuration| configuration.candidate_key());
    Ok(candidates)
}

pub(in crate::benchmark::release) fn validate_candidate_partition(
    subjects: &[crate::benchmark::release::IntentionalBoundaryGeneratorSubject],
    configurations: &[GeneratorConfiguration<'_>],
    actual_ids: &[String],
) -> bool {
    subjects
        .iter()
        .map(|subject| candidate_configuration_ids(&subject.repository_path, configurations))
        .collect::<BTreeSet<_>>()
        == BTreeSet::from([actual_ids.to_vec()])
}
