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
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) const GENERATOR_CONTRACT: &str = "sniffbench-intentional-boundary-generator-replay-v6";

#[path = "benchmark_intentional_boundary_generator_command.rs"]
mod command;
#[path = "benchmark_intentional_boundary_generator_go.rs"]
mod go;
#[path = "benchmark_intentional_boundary_generator_node.rs"]
mod node;
#[path = "benchmark_intentional_boundary_generator_python.rs"]
mod python;
#[path = "benchmark_intentional_boundary_generator_runtime.rs"]
mod runtime;
use command::{GeneratorCommandPlan, generator_command_plan_with_context};
#[cfg(test)]
use command::{cargo_generator_command, generator_command};
pub(super) use command::{generator_command_with_context, is_generator_declaration};
pub(super) use node::GeneratorCommand;
use node::generator_candidate_key;

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

struct ReplayContext<'a> {
    inventory: &'a IntentionalBoundaryRepositoryInventory,
    source_census: &'a IntentionalBoundarySourceCensus,
    semantic_census: &'a IntentionalBoundarySemanticCensus,
    project_model_census: &'a IntentionalBoundaryProjectModelCensus,
    binding_census: &'a IntentionalBoundaryManifestBindingCensus,
    declarations: &'a [IntentionalBoundaryManifestDeclaration],
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
        |declaration, command, outputs| {
            runtime::execute_generator_replay(root, revision, declaration, command, outputs)
        },
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
    F: FnMut(
        &IntentionalBoundaryManifestDeclaration,
        &GeneratorCommand,
        &[ExpectedOutput],
    ) -> Result<ReplaySuccess, ReplayFailure>,
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
    let declarations = manifest_census
        .declarations
        .iter()
        .filter(|declaration| is_generator_declaration(declaration))
        .collect::<Vec<_>>();
    let mut grouped = BTreeMap::<Vec<String>, Vec<IntentionalBoundaryGeneratorSubject>>::new();
    let declaration_by_id = declarations
        .iter()
        .map(|declaration| (declaration.declaration_id.as_str(), *declaration))
        .collect::<BTreeMap<_, _>>();
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
            .entry(nearest_declarations(
                &subject.repository_path,
                &declarations,
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
            let candidates = candidate_ids
                .iter()
                .map(|id| {
                    declaration_by_id
                        .get(id.as_str())
                        .copied()
                        .ok_or_else(|| "generator grouping invented a declaration".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            replay_outcome(&replay_context, &candidates, &subjects, &mut executor)?
        };
        let configuration_declaration_id = match &outcome {
            IntentionalBoundaryGeneratorReplayOutcome::Reproduced { declaration_id, .. } => {
                Some(declaration_id.clone())
            }
            IntentionalBoundaryGeneratorReplayOutcome::Unresolved { .. } => None,
        };
        let replay_id = replay_id(repository, revision, &candidate_ids, &subjects)?;
        replays.push(IntentionalBoundaryGeneratorReplay {
            replay_id,
            configuration_declaration_id,
            candidate_declaration_ids: candidate_ids,
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
    declarations: &[&IntentionalBoundaryManifestDeclaration],
    subjects: &[IntentionalBoundaryGeneratorSubject],
    executor: &mut F,
) -> Result<IntentionalBoundaryGeneratorReplayOutcome, String>
where
    F: FnMut(
        &IntentionalBoundaryManifestDeclaration,
        &GeneratorCommand,
        &[ExpectedOutput],
    ) -> Result<ReplaySuccess, ReplayFailure>,
{
    let paths = subjects
        .iter()
        .map(|subject| subject.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let outputs = paths
        .into_iter()
        .map(|path| expected_output(context.inventory, context.source_census, path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut candidates = declarations.to_vec();
    candidates.sort_by_key(|declaration| generator_candidate_key(declaration));
    let mut failures = Vec::new();
    let mut planning_failures = Vec::new();
    let mut supported = 0usize;
    for declaration in candidates {
        let command = match generator_command_plan_with_context(
            context.inventory,
            context.declarations,
            context.semantic_census,
            context.project_model_census,
            context.binding_census,
            declaration,
        ) {
            GeneratorCommandPlan::Planned(command) => command,
            GeneratorCommandPlan::Unresolved { reason, detail } => {
                planning_failures.push((declaration.declaration_id.as_str(), reason, detail));
                continue;
            }
        };
        supported += 1;
        match executor(declaration, &command, &outputs) {
            Ok(success) => {
                validate_replay_success(&success, &command, &outputs)?;
                return Ok(IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
                    declaration_id: declaration.declaration_id.clone(),
                    declaration_location: declaration.declaration_location.clone(),
                    preparations: success.preparations,
                    command: command.execution,
                    outputs: success.outputs,
                    executions: success.executions,
                });
            }
            Err(failure) => failures.push((declaration.declaration_id.as_str(), failure)),
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
                    format!("generator declaration {id} is unresolved: {detail}"),
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
                "all {supported} supported generator commands failed; first declaration {id}: {}",
                failure.detail
            )
        },
    );
    Ok(unresolved(reason, detail))
}

fn validate_replay_success(
    success: &ReplaySuccess,
    command: &GeneratorCommand,
    expected: &[ExpectedOutput],
) -> Result<(), String> {
    let preparation_valid = match &command.preparation {
        None => success.preparations.is_empty(),
        Some(preparation) => {
            success.preparations.len() == 2
                && success
                    .preparations
                    .iter()
                    .enumerate()
                    .all(|(index, execution)| {
                        execution.run_number == (index + 1) as u8
                            && execution.command == *preparation
                            && execution.environment == command.preparation_environment
                            && execution.status_code == 0
                            && !execution.timed_out
                            && execution.network_enabled
                            && is_sha256(&execution.runtime_identity_sha256)
                            && is_sha256(&execution.stdout_sha256)
                            && is_sha256(&execution.stderr_sha256)
                    })
        }
    };
    if !preparation_valid
        || success.executions.len() != 2
        || success
            .executions
            .iter()
            .enumerate()
            .any(|(index, execution)| {
                execution.run_number != (index + 1) as u8
                    || execution.command != command.execution
                    || execution.environment != command.execution_environment
                    || execution.status_code != 0
                    || execution.timed_out
                    || execution.network_enabled
                    || !is_sha256(&execution.runtime_identity_sha256)
                    || !is_sha256(&execution.stdout_sha256)
                    || !is_sha256(&execution.stderr_sha256)
            })
        || success.outputs.len() != expected.len()
    {
        return Err("generator replay executor violated its receipt contract".to_string());
    }
    for (actual, expected) in success.outputs.iter().zip(expected) {
        if actual.repository_path != expected.repository_path
            || actual.object_id != expected.object_id
            || actual.byte_length != expected.byte_length
            || actual.committed_sha256 != expected.committed_sha256
            || actual.first_run_sha256 != expected.committed_sha256
            || actual.second_run_sha256 != expected.committed_sha256
        {
            return Err("generator replay executor changed reproduced output identity".to_string());
        }
    }
    Ok(())
}

fn expected_output(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    path: &str,
) -> Result<ExpectedOutput, String> {
    let entry = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == path)
        .ok_or_else(|| format!("generated output is not tracked: {path}"))?;
    let source = source_census
        .source_files
        .iter()
        .find(|file| file.repository_path == path)
        .ok_or_else(|| format!("generated output is not in the source census: {path}"))?;
    if entry.kind != BoundaryGitEntryKind::RegularBlob
        || entry.byte_length != Some(source.byte_length)
        || entry.object_id != source.object_id
    {
        return Err(format!("generated output identity changed: {path}"));
    }
    Ok(ExpectedOutput {
        repository_path: path.to_string(),
        object_id: entry.object_id.clone(),
        byte_length: source.byte_length,
        committed_sha256: source.source_sha256.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_census(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source: &IntentionalBoundarySourceCensus,
    semantic: &IntentionalBoundarySemanticCensus,
    project_models: &IntentionalBoundaryProjectModelCensus,
    manifests: &IntentionalBoundaryManifestCensus,
    bindings: &IntentionalBoundaryManifestBindingCensus,
    evidence: &IntentionalBoundaryEvidenceCensus,
    mut replays: Vec<IntentionalBoundaryGeneratorReplay>,
) -> Result<IntentionalBoundaryGeneratorCensus, String> {
    replays.sort();
    let replay_count_by_status = replays.iter().fold(BTreeMap::new(), |mut counts, replay| {
        let status = match replay.outcome {
            IntentionalBoundaryGeneratorReplayOutcome::Reproduced { .. } => "reproduced",
            IntentionalBoundaryGeneratorReplayOutcome::Unresolved { .. } => "unresolved",
        };
        *counts.entry(status.to_string()).or_default() += 1;
        counts
    });
    let mut census = IntentionalBoundaryGeneratorCensus {
        schema_version: INTENTIONAL_BOUNDARY_GENERATOR_CENSUS_SCHEMA_VERSION,
        generator_contract: GENERATOR_CONTRACT.to_string(),
        repository: source.repository.clone(),
        revision: source.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_sha256: source.census_sha256.clone(),
        semantic_census_sha256: semantic.semantic_census_sha256.clone(),
        project_model_census_sha256: project_models.project_model_census_sha256.clone(),
        manifest_census_sha256: manifests.manifest_census_sha256.clone(),
        manifest_binding_census_sha256: bindings.binding_census_sha256.clone(),
        base_evidence_census_sha256: evidence.evidence_census_sha256.clone(),
        replays,
        replay_count_by_status,
        generator_census_sha256: String::new(),
    };
    census.generator_census_sha256 = generator_census_sha256(&census)?;
    Ok(census)
}

pub(super) fn replay_id(
    repository: &str,
    revision: &str,
    candidate_declaration_ids: &[String],
    subjects: &[IntentionalBoundaryGeneratorSubject],
) -> Result<String, String> {
    Ok(format!(
        "ibgr-v1:{}",
        hash_json(&(
            GENERATOR_CONTRACT,
            repository,
            revision,
            candidate_declaration_ids,
            subjects
        ))?
    ))
}

pub(super) fn generator_census_sha256(
    census: &IntentionalBoundaryGeneratorCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.generator_contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.project_model_census_sha256,
        &census.manifest_census_sha256,
        &census.manifest_binding_census_sha256,
        &census.base_evidence_census_sha256,
        &census.replays,
        &census.replay_count_by_status,
    ))
}

fn unresolved(
    reason: IntentionalBoundaryGeneratorUnresolvedReason,
    detail: impl Into<String>,
) -> IntentionalBoundaryGeneratorReplayOutcome {
    IntentionalBoundaryGeneratorReplayOutcome::Unresolved {
        reason,
        detail: detail.into(),
    }
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit generator replay: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_generator_tests.rs"]
mod tests;
