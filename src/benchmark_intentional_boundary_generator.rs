use super::intentional_boundary_compiler_evidence::validate_evidence_census_commitment;
use super::intentional_boundary_manifest::validate_manifest_census_commitment;
use super::{
    BoundaryEvidenceKind, BoundaryGitEntryKind,
    INTENTIONAL_BOUNDARY_GENERATOR_CENSUS_SCHEMA_VERSION, IntentionalBoundaryEvidenceCensus,
    IntentionalBoundaryEvidenceProof, IntentionalBoundaryGeneratorCensus,
    IntentionalBoundaryGeneratorExecution, IntentionalBoundaryGeneratorOutput,
    IntentionalBoundaryGeneratorReplay, IntentionalBoundaryGeneratorReplayOutcome,
    IntentionalBoundaryGeneratorSubject, IntentionalBoundaryGeneratorUnresolvedReason,
    IntentionalBoundaryManifestBindingCensus, IntentionalBoundaryManifestCensus,
    IntentionalBoundaryManifestDeclaration, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySourceCensus,
    validate_intentional_boundary_manifest_bindings,
    validate_intentional_boundary_project_model_census_commitment,
    validate_intentional_boundary_repository_inventory,
    validate_intentional_boundary_semantic_census, validate_intentional_boundary_source_census,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) const GENERATOR_CONTRACT: &str = "sniffbench-intentional-boundary-generator-replay-v7";

#[path = "benchmark_intentional_boundary_generator_command.rs"]
mod command;
#[path = "benchmark_intentional_boundary_generator_commitment.rs"]
mod commitment;
#[path = "benchmark_intentional_boundary_generator_configuration.rs"]
pub(super) mod configuration;
use commitment::*;
pub(super) use commitment::{generator_census_sha256, is_sha256, replay_id};
#[path = "benchmark_intentional_boundary_generator_go.rs"]
mod go;
#[path = "benchmark_intentional_boundary_generator_gradle.rs"]
mod gradle;
#[path = "benchmark_intentional_boundary_generator_node.rs"]
mod node;
#[path = "benchmark_intentional_boundary_generator_python.rs"]
mod python;
#[path = "benchmark_intentional_boundary_generator_runtime.rs"]
mod runtime;
use command::GeneratorCommandPlan;
pub(super) use command::is_generator_declaration;
#[cfg(test)]
use command::{cargo_generator_command, generator_command, generator_command_with_context};
use configuration::{
    GeneratorConfiguration, candidate_configuration_ids, configurations, configurations_by_id,
    has_ambiguous_exact_gradle, sorted_candidates,
};
pub(super) use node::GeneratorCommand;

#[derive(Clone)]
struct ExpectedOutput {
    repository_path: String,
    object_id: String,
    byte_length: u64,
    committed_sha256: String,
}

struct ReplaySuccess {
    outputs: Vec<IntentionalBoundaryGeneratorOutput>,
    preparations: Vec<IntentionalBoundaryGeneratorExecution>,
    executions: Vec<IntentionalBoundaryGeneratorExecution>,
}

struct ReplayFailure {
    reason: IntentionalBoundaryGeneratorUnresolvedReason,
    detail: String,
}

pub(super) struct ReplayContext<'a> {
    pub(super) inventory: &'a IntentionalBoundaryRepositoryInventory,
    pub(super) source_census: &'a IntentionalBoundarySourceCensus,
    pub(super) semantic_census: &'a IntentionalBoundarySemanticCensus,
    pub(super) project_model_census: &'a IntentionalBoundaryProjectModelCensus,
    pub(super) binding_census: &'a IntentionalBoundaryManifestBindingCensus,
    pub(super) declarations: &'a [IntentionalBoundaryManifestDeclaration],
}

#[allow(clippy::too_many_arguments)]
pub fn census_intentional_boundary_generators(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryGeneratorCensus, String> {
    census_generators_with_executor(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        project_model_census,
        manifest_census,
        binding_census,
        base_evidence,
        |command, outputs| runtime::execute_generator_replay(root, revision, command, outputs),
    )
}

#[allow(clippy::too_many_arguments)]
fn census_generators_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    mut executor: F,
) -> Result<IntentionalBoundaryGeneratorCensus, String>
where
    F: FnMut(&GeneratorCommand, &[ExpectedOutput]) -> Result<ReplaySuccess, ReplayFailure>,
{
    validate_inputs(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        project_model_census,
        manifest_census,
        binding_census,
        base_evidence,
    )?;
    let subjects = generator_subjects(source_census, semantic_census, base_evidence)?;
    let configurations = configurations(&manifest_census.declarations, project_model_census)?;
    let mut grouped = BTreeMap::<Vec<String>, Vec<IntentionalBoundaryGeneratorSubject>>::new();
    let configuration_by_id = configurations_by_id(&configurations);
    let replay_context = ReplayContext {
        inventory,
        source_census,
        semantic_census,
        project_model_census,
        binding_census,
        declarations: &manifest_census.declarations,
    };
    for subject in subjects {
        grouped
            .entry(candidate_configuration_ids(
                &subject.repository_path,
                &configurations,
            ))
            .or_default()
            .push(subject);
    }
    let mut replays = Vec::new();
    for (candidate_ids, mut subjects) in grouped {
        subjects.sort();
        let outcome = if candidate_ids.is_empty() {
            unresolved(
                IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration,
                "generated subjects have no enclosing declared generator command",
            )
        } else {
            let candidates = sorted_candidates(&candidate_ids, &configuration_by_id)?;
            replay_outcome(&replay_context, &candidates, &subjects, &mut executor)?
        };
        let configuration_id = match &outcome {
            IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
                configuration_id, ..
            } => Some(configuration_id.clone()),
            IntentionalBoundaryGeneratorReplayOutcome::Unresolved { .. } => None,
        };
        let replay_id = replay_id(repository, revision, &candidate_ids, &subjects)?;
        replays.push(IntentionalBoundaryGeneratorReplay {
            replay_id,
            configuration_id,
            candidate_configuration_ids: candidate_ids,
            subjects,
            outcome,
        });
    }
    finish_census(
        inventory,
        source_census,
        semantic_census,
        project_model_census,
        manifest_census,
        binding_census,
        base_evidence,
        replays,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_inputs(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    validate_intentional_boundary_source_census(
        repository,
        revision,
        root,
        inventory,
        source_census,
    )?;
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    validate_intentional_boundary_project_model_census_commitment(inventory, project_model_census)?;
    validate_manifest_census_commitment(&inventory.inventory_sha256, manifest_census)?;
    validate_intentional_boundary_manifest_bindings(
        source_census,
        semantic_census,
        manifest_census,
        binding_census,
    )?;
    validate_evidence_census_commitment(source_census, semantic_census, base_evidence)?;
    if manifest_census.repository != repository
        || manifest_census.revision != revision
        || base_evidence.repository != repository
        || base_evidence.revision != revision
    {
        return Err("intentional-boundary generator input identity changed".to_string());
    }
    Ok(())
}

pub(super) fn generator_subjects(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<Vec<IntentionalBoundaryGeneratorSubject>, String> {
    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let source_paths = source_census
        .source_files
        .iter()
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut subjects = Vec::new();
    for atom in &evidence.atoms {
        if atom.evidence_kind != BoundaryEvidenceKind::GeneratorIdentity {
            continue;
        }
        if !matches!(
            atom.proof,
            IntentionalBoundaryEvidenceProof::SourceAst(
                super::IntentionalBoundaryAstProofKind::GeneratorMarker
            )
        ) {
            return Err("generator identity lacks an exact AST marker proof".to_string());
        }
        let method = methods
            .get(atom.subject_parser_unit_id.as_str())
            .copied()
            .ok_or_else(|| "generator identity invented a method".to_string())?;
        if !matches!(
            &method.status,
            IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. }
                if symbol.symbol_id == atom.subject_symbol_id
        ) || !source_paths.contains(method.repository_path.as_str())
        {
            return Err("generator identity changed the compiler subject".to_string());
        }
        let [marker] = atom.locations.as_slice() else {
            return Err("generator identity requires one exact marker location".to_string());
        };
        if marker.repository_path != method.repository_path {
            return Err("generator marker changed the subject file".to_string());
        }
        subjects.push(IntentionalBoundaryGeneratorSubject {
            parser_unit_id: method.parser_unit_id.clone(),
            subject_symbol_id: atom.subject_symbol_id.clone(),
            repository_path: method.repository_path.clone(),
            marker_location: marker.clone(),
        });
    }
    subjects.sort();
    if subjects.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("generator subjects are duplicated".to_string());
    }
    Ok(subjects)
}

pub(super) fn nearest_declarations(
    repository_path: &str,
    declarations: &[&IntentionalBoundaryManifestDeclaration],
) -> Vec<String> {
    let nearest_depth = declarations
        .iter()
        .filter(|declaration| path_is_under(repository_path, manifest_directory(declaration)))
        .map(|declaration| manifest_directory(declaration).len())
        .max();
    let mut ids = declarations
        .iter()
        .filter(|declaration| {
            nearest_depth.is_some_and(|depth| {
                path_is_under(repository_path, manifest_directory(declaration))
                    && manifest_directory(declaration).len() == depth
            })
        })
        .map(|declaration| declaration.declaration_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn manifest_directory(declaration: &IntentionalBoundaryManifestDeclaration) -> &str {
    declaration
        .manifest_repository_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory)
}

fn path_is_under(path: &str, directory: &str) -> bool {
    directory.is_empty()
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn replay_outcome<F>(
    context: &ReplayContext<'_>,
    configurations: &[&GeneratorConfiguration<'_>],
    subjects: &[IntentionalBoundaryGeneratorSubject],
    executor: &mut F,
) -> Result<IntentionalBoundaryGeneratorReplayOutcome, String>
where
    F: FnMut(&GeneratorCommand, &[ExpectedOutput]) -> Result<ReplaySuccess, ReplayFailure>,
{
    let paths = subjects
        .iter()
        .map(|subject| subject.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let outputs = paths
        .into_iter()
        .map(|path| expected_output(context.inventory, context.source_census, path))
        .collect::<Result<Vec<_>, _>>()?;
    if has_ambiguous_exact_gradle(configurations) {
        return Ok(unresolved(
            IntentionalBoundaryGeneratorUnresolvedReason::AmbiguousConfiguration,
            "generated subjects have multiple exact Gradle producer tasks",
        ));
    }
    let mut failures = Vec::new();
    let mut planning_failures = Vec::new();
    let mut supported = 0usize;
    for configuration in configurations {
        let command = match configuration.command_plan(context) {
            GeneratorCommandPlan::Planned(command) => command,
            GeneratorCommandPlan::Unresolved { reason, detail } => {
                planning_failures.push((configuration.id(), reason, detail));
                continue;
            }
        };
        supported += 1;
        match executor(&command, &outputs) {
            Ok(success) => {
                validate_replay_success(&success, &command, &outputs)?;
                return Ok(IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
                    configuration_id: configuration.id().to_string(),
                    configuration_evidence_locations: configuration.evidence_locations(),
                    preparations: success.preparations,
                    command: command.execution,
                    outputs: success.outputs,
                    executions: success.executions,
                });
            }
            Err(failure) => failures.push((configuration.id(), failure)),
        }
    }
    if supported == 0 {
        let (reason, detail) = planning_failures.first().map_or_else(
            || {
                (
                    IntentionalBoundaryGeneratorUnresolvedReason::UnsupportedConfiguration,
                    "generator replay found no supported locked generator command".to_string(),
                )
            },
            |(id, reason, detail)| {
                (
                    *reason,
                    format!("generator configuration {id} is unresolved: {detail}"),
                )
            },
        );
        return Ok(unresolved(reason, detail));
    }
    let reason = failures.first().map_or(
        IntentionalBoundaryGeneratorUnresolvedReason::ExecutionFailed,
        |(_, failure)| failure.reason,
    );
    let detail = failures.first().map_or_else(
        || "supported generator commands produced no replay result".to_string(),
        |(id, failure)| {
            format!(
                "all {supported} supported generator commands failed; first configuration {id}: {}",
                failure.detail
            )
        },
    );
    Ok(unresolved(reason, detail))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_generator_tests.rs"]
mod tests;
